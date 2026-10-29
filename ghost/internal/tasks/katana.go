package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	"github.com/xsecurity-ai/oddjob/ghost/internal/browserfetch"
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
	// Off by default: a re-crawl pulls back only the bundles the
	// project does not already hold. On, every one is fetched again,
	// which is what a deploy since the last run calls for -- a
	// fingerprinted bundle changes its URL, but `app.js` does not.
	refetchAssets, _ := args["refetch_assets"].(bool)
	// Reported in the result, not logged: "we recorded 412 assets and
	// deliberately did not fetch them" is something the operator who
	// asked for the crawl needs to read, and a log line on the agent
	// host is not where they are looking.
	assetsSkipped := 0
	assetsHeld := 0

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
		// Assets held back from the fetch, re-joined to the result
		// afterwards. Two reasons an asset lands here and only one
		// of them is "already held", which is why the counters are
		// separate in the output.
		var pulled []asset
		if assetScope(args) != "all" {
			keep := make([]asset, 0, len(assets))
			for _, a := range assets {
				if samePartyAsset(a) {
					keep = append(keep, a)
					continue
				}
				// Held back from the FETCH, not dropped. The
				// comment above has always said the reference is
				// kept either way, and until the re-join below it
				// was not: ticking "download the bundles" made the
				// run forget which CDNs the pages load from, which
				// is the one question this table exists to answer
				// and the one nobody would think to check.
				notOurs++
				pulled = append(pulled, a)
			}
			assets = keep
		}
		// What this project already has the bytes of. Asked once,
		// between finding the bundles and fetching them -- the only
		// point at which the list of URLs exists and no request has
		// been made yet.
		//
		// The reference is still reported for a held asset, because
		// "this page loads it" is a fact about THIS crawl and the
		// page may be one nothing had reached before. Only the
		// request is skipped. Oddjob's importer fills in bytes it
		// does not have and never blanks bytes it does, so a
		// body-less sighting of a stored asset is safe by
		// construction.
		if !refetchAssets {
			held := alreadyHeld(ctx, assets)
			if len(held) > 0 {
				keep := make([]asset, 0, len(assets))
				for _, a := range assets {
					if held[a.URL] {
						a.AlreadyHeld = true
						assetsHeld++
						pulled = append(pulled, a)
						continue
					}
					keep = append(keep, a)
				}
				assets = keep
			}
		}
		if len(assets) > 0 {
			assets = fetchAssets(ctx, assets, args,
				intOr(args, "max_asset_body", 5*1024*1024),
				intOr(args, "asset_budget", 64*1024*1024))
		}
		// Put back after the fetch, so the result carries every asset
		// the crawl saw -- held and fetched -- rather than only the
		// ones this run happened to request.
		assets = append(assets, pulled...)
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
			// Already in the database, so not asked for again. A
			// different fact from `assets_not_fetched`, which is
			// "somebody else's host and we did not touch it".
			"assets_already_held": assetsHeld,
			"assets_refetched":    refetchAssets,
			"assets_scope":        assetScope(args)}),
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
	// Recorded but deliberately NOT fetched because the project
	// already holds the bytes. Distinct from an empty asset with no
	// explanation, which reads as "nothing has tried".
	AlreadyHeld bool `json:"already_held,omitempty"`
	// Which product refused a PLAIN request for this file, if one
	// did. Kept even when the browser-handshake retry then
	// succeeded: "this host is behind Cloudflare and refuses a
	// plain client" is the difference between a quiet estate and
	// one that is quietly filtering us, and it is not visible
	// anywhere else.
	BlockedBy string `json:"blocked_by,omitempty"`
	// True when the bytes only arrived through the browser
	// handshake. An operator reading a file that could not be
	// fetched any other way should be told so.
	UsedBrowser bool `json:"used_browser,omitempty"`
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

// : Most asset URLs in one `held` question. The server caps this at
// : the same number; chunking here is what keeps a big crawl under it.
const heldChunk = 2000

// AssetsHeld asks Oddjob which asset URLs this project already holds
// the bytes of. Wired by the agent at startup, the way Parallelism is.
//
// **Nil means fetch everything, and that is the right default.** A
// task run standalone, or in a test, has nobody to ask -- and "we do
// not know" has to mean "fetch", because a missing bundle is a gap in
// the evidence and a repeated one is only traffic. The same applies
// to an error from the call: it is logged into the result and the
// fetch goes ahead.
var AssetsHeld func(ctx context.Context, urls []string) ([]string, error)

// alreadyHeld returns the subset of these URLs Oddjob already has the
// bytes of, asking in chunks. An empty set on any failure.
func alreadyHeld(ctx context.Context, in []asset) map[string]bool {
	if AssetsHeld == nil || len(in) == 0 {
		return nil
	}
	urls := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, a := range in {
		if !seen[a.URL] {
			seen[a.URL] = true
			urls = append(urls, a.URL)
		}
	}
	out := map[string]bool{}
	for start := 0; start < len(urls); start += heldChunk {
		end := start + heldChunk
		if end > len(urls) {
			end = len(urls)
		}
		held, err := AssetsHeld(ctx, urls[start:end])
		if err != nil {
			// Partial answers are kept. Knowing about the first
			// chunk is better than fetching all of it again, and
			// the only cost of a missing answer is one more
			// request to a host that has already served it.
			return out
		}
		for _, u := range held {
			out[u] = true
		}
	}
	return out
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
	timeout := time.Duration(intOr(args, "asset_timeout_s", 20)) * time.Second
	redirects := func(_ *http.Request, via []*http.Request) error {
		// Redirects followed: a CDN pointing at its own versioned
		// path is the normal case, and refusing to follow would
		// report the library as unreachable.
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}
	ua := userAgent(args)
	// A plain client first, always. The browser handshake is what
	// happens when a refusal says it is needed, not what we do by
	// default -- an engagement should look like what it is until
	// looking like what it is stops the work. See
	// internal/browserfetch.
	fetch := &browserfetch.Fetcher{
		Plain: &http.Client{Timeout: timeout, CheckRedirect: redirects},
		Browser: func() *http.Client {
			c := browserfetch.Client(timeout, true)
			c.CheckRedirect = redirects
			return c
		}(),
		UserAgent: ua,
		Disabled:  !boolOr(args, "bypass_waf", true),
	}
	spent := 0
	out := make([]asset, 0, len(in))
	for _, a := range in {
		if ctx.Err() != nil {
			out = append(out, in[len(out):]...)
			break
		}
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
		fetch.MaxBody = int64(lim) + 1
		res, err := fetch.Get(ctx, a.URL)
		if err != nil {
			a.FetchError = tail(err.Error(), 200)
			out = append(out, a)
			continue
		}
		a.Status = res.Status
		a.ContentType = res.ContentType
		a.BlockedBy = res.BlockedBy
		a.UsedBrowser = res.UsedBrowser
		body := res.Body
		if res.StillBlocked {
			// Not evidence about the file. Recorded as the refusal
			// it is rather than stored as the library's contents,
			// which is how a block page comes to be hashed as a
			// version of jQuery.
			a.FetchError = tail(fmt.Sprintf(
				"refused by %s; the body is its block page, not the file",
				res.BlockedBy), 200)
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
