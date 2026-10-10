package tasks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"

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
// The task kind `gospider` is still accepted and routed here. Tasks
// queued before this change are still in queues and still name it,
// and failing them to rename a tool would lose real work.
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

	var (
		mu     sync.Mutex
		seen   = map[string]bool{}
		urls   []string
		byType = map[string]int{}
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
			"sites": us, "depth": depth, "urls": out, "by_type": types_}),
		Stderr: tail(strings.Join(failures, "\n"), 4000),
		Summary: fmt.Sprintf("katana: %d url(s) across %d site(s)%s",
			len(out), len(us), capped),
	}
}

// headerList builds katana's custom headers.
//
// The user agent is always set. `headers` carries whatever else the
// task was given -- a session cookie, a bearer token, an
// anti-CSRF header -- as "Name: value" strings, which is the form
// both katana and an operator pasting from Burp already use.
func headerList(args map[string]any) []string {
	ua := str(args, "user_agent")
	if ua == "" {
		ua = defaultUserAgent
	}
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
