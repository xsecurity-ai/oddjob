package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Against a real site, because the thing worth proving is that it
// follows links and comes back with them — which a mock cannot show.
func TestKatanaCrawls(t *testing.T) {
	var mu sync.Mutex
	var sawUA, sawCookie, sawHeader string
	hits := map[string]int{}

	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hits[r.URL.Path]++
			sawUA = r.UserAgent()
			if c := r.Header.Get("Cookie"); c != "" {
				sawCookie = c
			}
			if h := r.Header.Get("X-Session"); h != "" {
				sawHeader = h
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, body)
		}
	}
	mux.HandleFunc("/", page(`<html><head><title>Root Page</title></head><body>
		<a href="/one">one</a><a href="/two">two</a>
		</body></html>`))
	mux.HandleFunc("/one", page(`<html><body>
		<a href="/deep">deep</a></body></html>`))
	mux.HandleFunc("/two", page(`<html><body>two</body></html>`))
	mux.HandleFunc("/deep", page(`<html><body>deep</body></html>`))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := runKatana(context.Background(), map[string]any{
		"url":     srv.URL,
		"depth":   3,
		"cookies": "session=abc123",
		"headers": []any{"X-Session: tok-xyz"},
	}, t.TempDir())

	if res.Status != "done" {
		t.Fatalf("status=%s err=%s stderr=%s", res.Status, res.Error, res.Stderr)
	}
	var out struct {
		Pages []struct {
			URL    string `json:"url"`
			Method string `json:"method"`
			Status int    `json:"status"`
			Title  string `json:"title"`
		} `json:"pages"`
		Sites []string `json:"sites"`
		Depth int      `json:"depth"`
		URLs  []string `json:"urls"`
	}
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("output is not the shape gospider produced: %v", err)
	}
	joined := strings.Join(out.URLs, "\n")

	// It followed links rather than just fetching the root.
	for _, want := range []string{"/one", "/two"} {
		if !strings.Contains(joined, want) {
			t.Errorf("did not crawl %s; got: %v", want, out.URLs)
		}
	}
	if len(out.URLs) < 3 {
		t.Errorf("only %d urls — it did not crawl, it fetched", len(out.URLs))
	}

	// The crawler asked for these pages and read the answers. It used
	// to report only the addresses, which left the Web view's Verb,
	// Status and Title columns empty on every crawled row — the data
	// existed and was discarded one function before it was needed.
	if len(out.Pages) == 0 {
		t.Fatal("no `pages` — the response detail was dropped again")
	}
	byURL := map[string]int{}
	var root struct {
		Method, Title string
		Status        int
	}
	for _, p := range out.Pages {
		byURL[p.URL]++
		if strings.HasSuffix(p.URL, "/") || p.URL == srv.URL {
			root.Method, root.Status, root.Title = p.Method, p.Status, p.Title
		}
	}
	if root.Method == "" {
		t.Error("no verb recorded, so the Verb column stays blank")
	}
	if root.Status != 200 {
		t.Errorf("status was %d, want 200 — the Status column needs this",
			root.Status)
	}
	if root.Title != "Root Page" {
		t.Errorf("title was %q, want %q", root.Title, "Root Page")
	}
	// One entry per address, matching `urls`. Two rows for one page
	// would double it in the inventory.
	for u, n := range byURL {
		if n != 1 {
			t.Errorf("%s appears %d times in pages", u, n)
		}
	}
	if len(out.Pages) != len(out.URLs) {
		t.Errorf("pages=%d urls=%d — the two lists disagree",
			len(out.Pages), len(out.URLs))
	}

	mu.Lock()
	defer mu.Unlock()
	// Authenticated crawling: a crawl of a site you cannot log into
	// sees the login page and nothing behind it.
	if !strings.Contains(sawCookie, "session=abc123") {
		t.Errorf("the session cookie never reached the site: %q", sawCookie)
	}
	if !strings.Contains(sawHeader, "tok-xyz") {
		t.Errorf("the custom header never reached the site: %q", sawHeader)
	}
	// Attribution. Against the constant, not a substring of it: the
	// old spelling-based check broke the moment the default was
	// recased, which told us about the literal rather than about the
	// behaviour under test.
	if sawUA != defaultUserAgent {
		t.Errorf("user agent %q, want the default %q", sawUA, defaultUserAgent)
	}
	// Credentials must not come back in the result.
	if strings.Contains(res.Output, "abc123") || strings.Contains(res.Summary, "abc123") {
		t.Error("the session cookie was echoed into the result")
	}
}

// The old name still routes, because tasks queued before the swap are
// still in queues and still say "gospider".
// The `gospider` half of this is gone with the alias: across the
// whole fleet not one task was ever queued under that name, so the
// compatibility it protected did not exist and the binary it kept
// installed could never run.
func TestKatanaIsRouted(t *testing.T) {
	if _, ok := Runners["katana"]; !ok {
		t.Error("task kind \"katana\" is not routed")
	}
	if _, ok := Runners["gospider"]; ok {
		t.Error("the retired gospider alias is routed again")
	}
}

func TestKatanaNeedsATarget(t *testing.T) {
	res := runKatana(context.Background(), map[string]any{}, t.TempDir())
	if res.Status != "failed" {
		t.Errorf("a crawl with no target reported %q", res.Status)
	}
}

// Technology fingerprinting is on, and the result reaches `tech`.
//
// This asserts the OUTCOME rather than `opts.TechDetect`, because
// the bug it guards against was not a wrong value -- it was a field
// nobody set, with a complete pipeline behind it. The agent read
// `Technologies`, crawl.py parsed `tech`, scans.py wrote the column
// and the Web view rendered it, all against an array katana never
// filled, on 122,542 rows. A test on the boolean would have been
// satisfied by the same mistake in a different place.
func TestKatanaReportsTechnologies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Two independent signatures, so the test does not hang on
		// one fingerprint staying in Wappalyzer's database.
		w.Header().Set("X-Powered-By", "PHP/8.1.2")
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><head><title>T</title>
			<meta name="generator" content="WordPress 6.0"></head>
			<body>hello</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := runKatana(context.Background(),
		map[string]any{"url": srv.URL, "depth": 1}, t.TempDir())
	if res.Status != "done" {
		t.Fatalf("status=%s err=%s", res.Status, res.Error)
	}
	var out struct {
		Pages []struct {
			URL  string   `json:"url"`
			Tech []string `json:"tech"`
		} `json:"pages"`
	}
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("output: %v", err)
	}
	if len(out.Pages) == 0 {
		t.Fatal("no pages reported")
	}
	var all []string
	for _, p := range out.Pages {
		all = append(all, p.Tech...)
	}
	if len(all) == 0 {
		t.Fatalf("no technologies on any of %d page(s); TechDetect is "+
			"off and the Tech column will be empty", len(out.Pages))
	}
	t.Logf("detected: %v", all)
}
