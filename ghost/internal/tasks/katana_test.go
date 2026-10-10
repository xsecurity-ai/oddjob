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
	mux.HandleFunc("/", page(`<html><body>
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
	// Attribution.
	if !strings.Contains(sawUA, "Oddjob") {
		t.Errorf("user agent %q does not identify the scan", sawUA)
	}
	// Credentials must not come back in the result.
	if strings.Contains(res.Output, "abc123") || strings.Contains(res.Summary, "abc123") {
		t.Error("the session cookie was echoed into the result")
	}
}

// The old name still routes, because tasks queued before the swap are
// still in queues and still say "gospider".
func TestGospiderNameStillRoutes(t *testing.T) {
	for _, kind := range []string{"gospider", "katana"} {
		if _, ok := Runners[kind]; !ok {
			t.Errorf("task kind %q is not routed", kind)
		}
	}
}

func TestKatanaNeedsATarget(t *testing.T) {
	res := runKatana(context.Background(), map[string]any{}, t.TempDir())
	if res.Status != "failed" {
		t.Errorf("a crawl with no target reported %q", res.Status)
	}
}
