package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/weppos/publicsuffix-go/publicsuffix"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// Crawling, in this process.
//
// Replaces gospider, which was a binary the agent had to find on the
// host and which therefore failed the same two ways gobuster did: not
// installed, or installed and a different version from the one the
// output parser expected. katana is a library here, so neither is
// possible.
//
// The `gospider` task kind is gone. It was routed here so that
// tasks queued under the old name would not be stranded mid-swap,
// and across the whole fleet not one was ever queued -- so what the
// alias actually did was keep a binary nobody could run installed
// on every agent.
//
// # Authenticated crawling
//
// A crawl of a site you cannot log into sees the login page and
// nothing behind it, which on an engagement is most of the
// application. Headers and cookies are passed straight through, so a
// session captured in Burp or handed over by the client reaches the
// crawler as itself.
//
// Credentials arrive per task from the project's own store. They are
// never logged: the summary counts URLs and names the site, and the
// headers do not appear in the result.
//
// # Scope
//
// `FieldScope: "rdn"` keeps the crawl inside the registrable domain
// of whatever it started from, and `--subs` style expansion is off
// unless asked for. Following a link off the target is how a crawl
// ends up touching something nobody authorised, and a crawler does
// that in milliseconds without anybody watching.

// runKatana crawls one or more sites.
func runKatana(ctx context.Context, args map[string]any, _ string) Result {
	us := subjects(args, "url", "urls", "site", "sites")
	if len(us) == 0 {
		return failed("katana needs `targets` (or `url`)")
	}

	depth := intOr(args, "depth", 2)
	conc := intOr(args, "concurrency", 5)
	limit := intOr(args, "max_urls", 5000)

	// How much of one response to carry, and how much in total.
	//
	// NOT a storage limit and not a transport one. The database is
	// where this belongs, the proxy in front of Oddjob sets
	// `client_max_body_size 0`, and the Web list never selects the
	// body columns -- it has a separate packet endpoint -- so a large
	// capture costs the table nothing.
	//
	// The constraint is the AGENT. It accumulates the whole result in
	// memory and encodes it to JSON before posting, which transiently
	// doubles it, and the fleet includes a 1GB box that has already
	// been OOM-killed once for taking on more than it could hold. 32MB
	// of bodies is a ~64MB spike there, which it survives; 500MB is
	// the agent dying with the entire crawl unreported.
	//
	// Both are per-task arguments, so a crawl that matters can be told
	// to carry more, and whatever does not fit is COUNTED and flagged
	// rather than quietly absent.
	maxBody := intOr(args, "max_body", 1024*1024)
	budget := intOr(args, "body_budget", 32*1024*1024)

	var (
		mu        sync.Mutex
		seen      = map[string]bool{}
		urls      []string
		pages     []page
		byType    = map[string]int{}
		assets    []asset
		assetSeen = map[string]bool{}
		spent     int
		trunc     int
		skipped   int
		captured  int
	)

	opts := &types.Options{
		MaxDepth:          depth,
		FieldScope:        "rdn",
		Timeout:           intOr(args, "timeout_s", 10),
		Concurrency:       conc,
		Parallelism:       conc,
		RateLimit:         intOr(args, "rate", 150),
		Strategy:          "depth-first",
		ScrapeJSResponses: true,
		// Wappalyzer fingerprinting, which is what fills
		// `Response.Technologies` and therefore the Tech column.
		//
		// It was off, and everything downstream of it was already
		// built: the agent reads `Technologies`, `crawl.py` parses
		// `tech`, `scans.py` writes the column, and the Web view has
		// a Tech column that renders the list. All of it ran against
		// an array katana never filled, so the column was empty on
		// 122,542 rows -- the same empty-column symptom as `server`,
		// but with a cause that is one boolean rather than a gap in
		// the data.
		//
		// Costs no requests. It fingerprints the headers and body
		// katana has already fetched, so the only price is CPU on
		// the agent, and nothing extra reaches the client.
		TechDetect: true,
		// Without this katana reads NO response body, so it finds no
		// links and returns only the url it was handed -- a crawl that
		// reports "done, 1 url" against a site with hundreds, and says
		// nothing about why.
		//
		// katana's CLI defaults it to 4 MB and its own library example
		// sets it explicitly; building Options directly leaves it at
		// zero. That is the trap, and it is invisible: nothing errors.
		// Caught by a test that asserts the crawl FOLLOWED LINKS rather
		// than that it ran.
		BodyReadSize: 4 * 1024 * 1024,
		// Said on every request, so the target's own logs can attribute
		// this without anybody having to ask us who was crawling them.
		CustomHeaders: headerList(args),
		Silent:        true,
		OnResult: func(r output.Result) {
			if r.Request == nil {
				return
			}
			u := strings.TrimSpace(r.Request.URL)
			if u == "" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			byType[strings.ToLower(r.Request.Method)]++
			if seen[u] || len(urls) >= limit {
				return
			}
			seen[u] = true
			urls = append(urls, u)

			// The response, not just the address.
			//
			// This reported a list of URL strings and threw the rest
			// away, which left the Web view with a Verb column, a
			// Status column and a Title column that were empty on
			// every one of 24,937 imported rows. katana had all of
			// it -- it is a crawler, it made the request -- and the
			// server had no way to know that because the agent did
			// not send it.
			p := page{URL: u, Method: r.Request.Method}
			p.Request = redactAuth(r.Request.Raw)
			if r.Response != nil {
				p.Status = r.Response.StatusCode
				p.Length = r.Response.ContentLength
				p.Tech = r.Response.Technologies
				p.Server = r.Response.Headers["server"]
				p.ContentType = r.Response.Headers["content_type"]
				if r.Response.Reader != nil {
					p.Title = strings.TrimSpace(
						r.Response.Reader.Find("title").First().Text())
					if len(p.Title) > 400 {
						p.Title = p.Title[:400]
					}
				}
				// The exchange, within the budget.
				raw := r.Response.Raw
				if raw == "" {
					raw = r.Response.Body
				}
				switch {
				case raw == "":
					// Nothing to carry. Not a skip and not a
					// truncation; the response genuinely had no body.
				case spent >= budget:
					p.BodySkipped = true
					skipped++
				default:
					if len(raw) > maxBody {
						raw = raw[:maxBody]
						p.Truncated = true
						trunc++
					}
					p.Response = raw
					spent += len(raw)
					captured++
				}
				if p.Length == 0 {
					p.Length = int64(len(r.Response.Body))
				}
				// What this page pulls in. Read from the document
				// katana already parsed -- no request is made.
				for _, a := range assetsFrom(r.Response.Reader, u) {
					if assetSeen[a.URL] {
						continue
					}
					assetSeen[a.URL] = true
					a.Page = u
					assets = append(assets, a)
				}
			}
			pages = append(pages, p)
		},
	}
	// Known hosts only, unless the task says otherwise. See the note
	// on scope above.
	if b, ok := args["subdomains"].(bool); ok && b {
		opts.FieldScope = "dn"
	}

	co, err := types.NewCrawlerOptions(opts)
	if err != nil {
		return failed("katana setup: %v", err)
	}
	defer func() { _ = co.Close() }()

	fetchAssetsWanted, _ := args["fetch_assets"].(bool)
	// Reported in the result, not logged: "we recorded 412 assets and
	// deliberately did not fetch them" is something the operator who
	// asked for the crawl needs to read, and a log line on the agent
	// host is not where they are looking.
	assetsSkipped := 0

	crawler, err := standard.New(co)
	if err != nil {
		return failed("katana setup: %v", err)
	}
	defer func() { _ = crawler.Close() }()

	// Bounded, like every other task that touches a client. A crawler
	// with no deadline on a site that generates URLs -- a calendar, a
	// faceted search -- does not finish on its own.
	deadline := timeout(args, 45*time.Minute)
	cctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	var failures []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, u := range us {
			if cctx.Err() != nil {
				return
			}
			if err := crawler.Crawl(u); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", u, err))
			}
		}
	}()
	select {
	case <-done:
	case <-cctx.Done():
		// Whatever was found before the deadline is kept. A crawl that
		// ran for 45 minutes and found 4,000 urls has not failed just
		// because it had not finished.
		failures = append(failures,
			fmt.Sprintf("stopped after %s", deadline))
	}

	mu.Lock()
	out := append([]string(nil), urls...)
	types_ := map[string]int{}
	for k, v := range byType {
		types_[k] = v
	}
	mu.Unlock()
	sort.Strings(out)

	// Pulled back only when asked. See fetchAssets.
	if fetchAssetsWanted && len(assets) > 0 {
		// And only the client's own, unless the operator widened it
		// by name. The references are kept either way -- "this page
		// loads jQuery from a CDN" is a fact about the page and
		// costs no traffic to record. FETCHING is the part that
		// sends a request to a host the engagement does not have,
		// and on a real project that is several hundred of them.
		//
		// A checkbox is one click. Defaulting it to everything
		// would put "scan the client" and "touch four hundred
		// third parties" behind the same click.
		notOurs := 0
		if assetScope(args) != "all" {
			keep := make([]asset, 0, len(assets))
			for _, a := range assets {
				if samePartyAsset(a) {
					keep = append(keep, a)
					continue
				}
				notOurs++
			}
			assets = keep
		}
		if len(assets) > 0 {
			assets = fetchAssets(ctx, assets, args,
				intOr(args, "max_asset_body", 5*1024*1024),
				intOr(args, "asset_budget", 64*1024*1024))
		}
		assetsSkipped = notOurs
	}

	if len(out) == 0 && len(failures) > 0 {
		return failed("katana did not complete: %s", failures[0])
	}
	capped := ""
	if len(out) >= limit {
		capped = fmt.Sprintf(", capped at %d", limit)
	}
	return Result{
		Status: "done",
		// The same shape gospider produced, so the importer and
		// anything reading stored results keep working unchanged.
		Output: recon.JSON(map[string]any{
			// `urls` stays alongside `pages`, and is not redundant.
			// Tasks delivered before this change carry only `urls`
			// and are still imported by the same importer; dropping
			// it would strand them.
			"sites": us, "depth": depth, "urls": out,
			"pages": pages, "assets": assets, "by_type": types_,
			// Said out loud. A body that was too large or arrived
			// after the budget ran out is a gap in the evidence, and
			// a gap nobody is told about is one nobody accounts for.
			"bodies": map[string]any{
				"captured": captured, "truncated": trunc,
				"skipped_over_budget": skipped,
				"bytes":               spent, "max_body": maxBody, "budget": budget,
			},
			// Recorded but deliberately not fetched, because they
			// are on somebody else's host. A gap in the bundles,
			// said out loud for the same reason the body gaps are.
			"assets_not_fetched": assetsSkipped,
			"assets_scope":       assetScope(args)}),
		Stderr: tail(strings.Join(failures, "\n"), 4000),
		Summary: fmt.Sprintf(
			"katana: %d url(s) across %d site(s)%s; %d exchange(s) kept"+
				"%s%s",
			len(out), len(us), capped, captured,
			map[bool]string{true: fmt.Sprintf(", %d truncated", trunc)}[trunc > 0],
			map[bool]string{true: fmt.Sprintf(
				", %d past the body budget", skipped)}[skipped > 0]),
	}
}

// headerList builds katana's custom headers.
//
// The user agent is always set. `headers` carries whatever else the
// task was given -- a session cookie, a bearer token, an
// anti-CSRF header -- as "Name: value" strings, which is the form
// both katana and an operator pasting from Burp already use.
func headerList(args map[string]any) []string {
	ua := userAgent(args)
	out := []string{"User-Agent: " + ua}
	for _, h := range stringsArg(args, "headers") {
		if h = strings.TrimSpace(h); h != "" && strings.Contains(h, ":") {
			out = append(out, h)
		}
	}
	if c := str(args, "cookies"); c != "" {
		out = append(out, "Cookie: "+c)
	}
	return out
}

// page is one address the crawler actually requested, and what came
// back from it.
//
// A crawler knows more than "this URL exists": it asked for the page
// and read the answer. Reporting only the address threw away the
// verb, the status, the title and the server on every result, which
// is why those columns were blank for every crawled row in the Web
// view. Omitempty throughout, so a result with no response is a bare
// URL rather than a row of confident zeroes -- a status of 0 would
// read as a status.
type page struct {
	URL         string   `json:"url"`
	Method      string   `json:"method,omitempty"`
	Status      int      `json:"status,omitempty"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Length      int64    `json:"length,omitempty"`
	Tech        []string `json:"tech,omitempty"`

	// The exchange itself. What was sent and what came back, so a
	// finding can be shown rather than described.
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	// Set when the response was longer than `max_body` and the rest
	// was not carried. The TRUE length is in `length`, so a truncated
	// capture never reads as a short page.
	Truncated bool `json:"truncated,omitempty"`
	// Set when the task had spent its whole body budget before
	// reaching this page. The page is still reported; only the
	// exchange is missing, and it says so rather than looking like a
	// page that returned nothing.
	BodySkipped bool `json:"body_skipped,omitempty"`
}

// redactAuth strips the credentials out of a captured request.
//
// The raw request carries every header that was sent, which for an
// authenticated crawl is the operator's own session: the `Cookie`
// they pasted in, or a bearer token. Storing the exchange is the
// point -- being able to show what was sent rather than describe it
// -- but the engagement's credentials are not evidence about the
// client, and a datastore that quietly accumulates them is one more
// place they have to be rotated out of.
//
// The header is kept with its value replaced, not dropped. "This
// request was authenticated" is itself a fact about the result: the
// same URL fetched with and without a session is two different
// findings, and a request that silently lost its Cookie line reads
// as the unauthenticated one.
func redactAuth(raw string) string {
	if raw == "" {
		return ""
	}
	lines := strings.Split(raw, "\n")
	for i, ln := range lines {
		name, _, found := strings.Cut(ln, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "cookie", "authorization", "proxy-authorization",
			"x-api-key", "x-auth-token", "set-cookie":
			lines[i] = strings.TrimSpace(name) + ": [redacted]"
		}
	}
	return strings.Join(lines, "\n")
}

// ------------------------------------------------------------ assets
// What a page pulls in: scripts, stylesheets, fonts.
//
// Taken from the document katana ALREADY parsed, which is the whole
// reason this is cheap. The crawler is scoped to the registrable
// domain, so a `<script src="https://cdn.example/jquery-3.6.0.min.js">`
// never appears in its results -- that host is out of scope and
// rightly never crawled. But the fact that the client's page depends
// on it is a fact about the client's page, and it was being thrown
// away with the rest of the DOM.
//
// No request is made here. Nothing is fetched, nothing is touched;
// this reads markup already in memory.

type asset struct {
	URL     string `json:"url"`
	Page    string `json:"page,omitempty"`
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`

	// Filled in only when `fetch_assets` was asked for.
	Status      int    `json:"status,omitempty"`
	Bytes       int    `json:"bytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	FetchError  string `json:"fetch_error,omitempty"`
}

// : `jquery-3.6.0.min.js`, `bootstrap.bundle.min-5.3.2.js`,
// : `d3@7.8.5.js`, `lib.js?v=1.2.3`. Deliberately conservative: a
// : wrong version is worse than no version, because "no version" is
// : read as unknown and a wrong one is read as fact.
var verRe = regexp.MustCompile(
	`(?i)[@\-_/]v?(\d+\.\d+(?:\.\d+)?(?:-[0-9a-z.]+)?)(?:\.min)?(?:\.[a-z]+)?$`)
var qverRe = regexp.MustCompile(`(?i)[?&](?:v|ver|version)=v?(\d+\.\d+(?:\.\d+)?)`)

// assetsFrom reads every external reference out of one parsed page.
func assetsFrom(doc *goquery.Document, pageURL string) []asset {
	if doc == nil {
		return nil
	}
	base, err := neturl.Parse(pageURL)
	if err != nil {
		return nil
	}
	out := []asset{}
	seen := map[string]bool{}
	add := func(raw, kind string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") {
			return
		}
		ref, err := neturl.Parse(raw)
		if err != nil {
			return
		}
		abs := base.ResolveReference(ref)
		if abs.Scheme != "http" && abs.Scheme != "https" {
			return
		}
		u := abs.String()
		if seen[u] {
			return
		}
		seen[u] = true
		a := asset{URL: u, Kind: kind}
		a.Name, a.Version = nameVersion(abs.Path, abs.RawQuery)
		out = append(out, a)
	}
	doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
		if v, ok := s.Attr("src"); ok {
			add(v, "script")
		}
	})
	doc.Find("link[href]").Each(func(_ int, s *goquery.Selection) {
		rel, _ := s.Attr("rel")
		v, ok := s.Attr("href")
		if !ok {
			return
		}
		switch {
		case strings.Contains(strings.ToLower(rel), "stylesheet"):
			add(v, "stylesheet")
		case strings.Contains(strings.ToLower(rel), "preload"):
			as, _ := s.Attr("as")
			add(v, strings.ToLower(as))
		}
	})
	doc.Find("iframe[src]").Each(func(_ int, s *goquery.Selection) {
		if v, ok := s.Attr("src"); ok {
			add(v, "iframe")
		}
	})
	return out
}

// nameVersion guesses the library and version from a URL.
//
// Only what the URL states. A fingerprinted bundle -- `app.a1b2c3.js`
// -- yields a name and NO version, and that is the honest answer:
// absent means unknown, and the hashed bundles are exactly the case
// where the filename helps least and the version matters most.
func nameVersion(path, query string) (string, string) {
	file := path
	if i := strings.LastIndex(file, "/"); i >= 0 {
		file = file[i+1:]
	}
	if file == "" {
		return "", ""
	}
	ver := ""
	stem := strings.TrimSuffix(file, filepath.Ext(file))
	stem = strings.TrimSuffix(stem, ".min")
	if m := verRe.FindStringSubmatch(stem); m != nil {
		ver = m[1]
		stem = strings.TrimSuffix(stem, m[0])
	} else if m := qverRe.FindStringSubmatch("?" + query); m != nil {
		ver = m[1]
	}
	// A version can also live in the path: /ajax/libs/jquery/3.6.0/x.js
	if ver == "" {
		for _, seg := range strings.Split(path, "/") {
			if m := verRe.FindStringSubmatch("/" + seg); m != nil && seg != "" {
				ver = m[1]
				break
			}
		}
	}
	stem = strings.Trim(stem, "-_.@")
	if len(stem) > 64 {
		stem = stem[:64]
	}
	return stem, ver
}

// fetchAssets pulls back the files the pages referenced.
//
// **Off unless asked for, and that is a scope decision rather than
// caution.** These URLs are mostly on third-party hosts -- a CDN, a
// font service, an analytics vendor -- which are not the client's
// infrastructure and are not in the engagement's scope. Reading a
// public static file is not testing it, and a browser loading the
// client's page does exactly the same thing, but it is still
// outbound traffic from the engagement's egress to somebody who did
// not agree to be part of it. That is the operator's call to make
// deliberately, so it is a flag.
//
// One request per distinct URL, serially. The point is to identify
// a library, which needs the bytes once; hammering a CDN in parallel
// to do it faster would be the rudest possible way to read a file
// anybody can read.
func fetchAssets(ctx context.Context, in []asset, args map[string]any,
	maxBody, budget int) []asset {
	cl := &http.Client{
		Timeout: time.Duration(intOr(args, "asset_timeout_s", 20)) * time.Second,
		// Redirects followed: a CDN pointing at its own versioned
		// path is the normal case, and refusing to follow would
		// report the library as unreachable.
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	ua := userAgent(args)
	spent := 0
	out := make([]asset, 0, len(in))
	for _, a := range in {
		if ctx.Err() != nil {
			out = append(out, in[len(out):]...)
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
		if err != nil {
			a.FetchError = err.Error()
			out = append(out, a)
			continue
		}
		req.Header.Set("User-Agent", ua)
		resp, err := cl.Do(req)
		if err != nil {
			a.FetchError = tail(err.Error(), 200)
			out = append(out, a)
			continue
		}
		a.Status = resp.StatusCode
		a.ContentType = resp.Header.Get("Content-Type")
		// Read under the cap. The hash is of what was READ, and is
		// therefore only meaningful for a file that arrived whole --
		// see the truncation guard below.
		lim := maxBody
		if rem := budget - spent; rem < lim {
			lim = rem
		}
		if lim < 0 {
			lim = 0
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, int64(lim)+1))
		_ = resp.Body.Close()
		if rerr != nil {
			a.FetchError = tail(rerr.Error(), 200)
			out = append(out, a)
			continue
		}
		if len(body) > lim {
			// Deliberately no hash and no body. A hash of a prefix
			// is not the file's hash, and anything matching against
			// it would be matching a different file with confidence.
			a.FetchError = fmt.Sprintf(
				"larger than the %d byte limit; not carried", maxBody)
			a.Bytes = len(body) - 1
			out = append(out, a)
			continue
		}
		sum := sha256.Sum256(body)
		a.SHA256 = hex.EncodeToString(sum[:])
		a.Bytes = len(body)
		a.Body = string(body)
		spent += len(body)
		out = append(out, a)
	}
	return out
}

// assetScope reports which assets `fetch_assets` may pull back.
//
// `first-party` (the default) means the client's own registrable
// domain only. `all` is the operator saying, deliberately, that
// fetching from CDNs and font services is acceptable on this
// engagement.
//
// Default-is-safe: a missing or misspelled value gives the narrow
// behaviour. Getting it wrong should cost a file nobody fetched,
// never a request nobody authorised.
func assetScope(args map[string]any) string {
	if s, ok := args["assets_scope"].(string); ok &&
		strings.EqualFold(strings.TrimSpace(s), "all") {
		return "all"
	}
	return "first-party"
}

// samePartyAsset reports whether an asset sits on the same
// registrable domain as the page that loaded it.
//
// Registrable domain, not hostname: `static.acme.example` serving
// `www.acme.example` is the same party, and refusing it would
// withhold exactly the bundles worth reading. This mirrors the
// comparison the server makes when it sets `third_party`, and the
// two agreeing is what stops a row being recorded as first-party
// and then never fetched.
//
// An asset whose page is unknown is treated as third-party. We
// cannot show it belongs to the client, and "could not determine"
// must not collapse into "yes".
func samePartyAsset(a asset) bool {
	if a.Page == "" {
		return false
	}
	au, err := neturl.Parse(a.URL)
	if err != nil {
		return false
	}
	pu, err := neturl.Parse(a.Page)
	if err != nil {
		return false
	}
	ah, ph := registrableHost(au.Hostname()), registrableHost(pu.Hostname())
	return ah != "" && ah == ph
}

// registrableHost reduces a hostname to the domain somebody can
// register, so `a.b.acme.co.uk` and `acme.co.uk` compare equal.
//
// Falls back to the hostname itself when the public suffix list
// cannot place it -- an IP literal, an internal name like
// `intranet`, a host with no dot. Comparing those verbatim is the
// strict answer, which is the right way to be wrong here.
func registrableHost(host string) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return ""
	}
	if net.ParseIP(h) != nil {
		return h
	}
	if d, err := publicsuffix.Domain(h); err == nil && d != "" {
		return d
	}
	return h
}
