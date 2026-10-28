package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The output shape, as the server's importer reads it.
type shotOut struct {
	Shots []struct {
		URL             string `json:"url"`
		FinalURL        string `json:"final_url"`
		Status          int    `json:"status"`
		Title           string `json:"title"`
		Server          string `json:"server"`
		PageContentType string `json:"page_content_type"`
		Width           int    `json:"width"`
		Height          int    `json:"height"`
		Bytes           int    `json:"bytes"`
		SHA256          string `json:"sha256"`
		PNG             string `json:"png_base64"`
	} `json:"shots"`
	Failed []struct {
		URL    string `json:"url"`
		Error  string `json:"error"`
		Reason string `json:"reason"`
	} `json:"failed"`
	Browser string `json:"browser"`
}

// Against a real browser, because the thing worth proving is that a
// PNG comes back -- which a mock cannot show.
//
// Skipped where there is no browser. That is not the test being
// lenient: a developer's laptop and the Go CI container have no
// chromium, the ghost IMAGE does, and a test that failed on the
// former would be a test nobody could run rather than one that
// proves anything about the latter. The skip says which it was.
func TestScreenshotCapturesAPage(t *testing.T) {
	exe, _ := browserPath(nil)
	if exe == "" {
		t.Skipf("no browser on this host (tried %s)",
			strings.Join(browserNames, ", "))
	}

	var mu sync.Mutex
	var sawUA, sawCookie, sawHeader string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawUA = r.UserAgent()
		sawCookie = r.Header.Get("Cookie")
		sawHeader = r.Header.Get("X-Session")
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "acme-httpd/1.0")
		// Drawn by script, so a pass proves the page was RENDERED
		// rather than merely fetched -- which is the whole
		// difference between this task and every other web task
		// here, and the reason it is state-changing in roe.py.
		_, _ = fmt.Fprint(w, `<html><head><title>ACME portal</title></head>
			<body style="background:#204080"><h1 id="h"></h1>
			<script>document.getElementById('h').textContent='rendered';
			document.title='ACME portal';</script></body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := runScreenshot(context.Background(), map[string]any{
		"url":        srv.URL,
		"user_agent": "OddJob-Test/1.0",
		"cookies":    "session=abc123",
		"headers":    []any{"X-Session: tok-xyz"},
		"settle_ms":  400,
	}, t.TempDir())

	if res.Status != "done" {
		t.Fatalf("status=%s err=%s stderr=%s", res.Status, res.Error, res.Stderr)
	}
	var out shotOut
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("output is not the shape the importer reads: %v", err)
	}
	if len(out.Shots) != 1 {
		t.Fatalf("wanted one shot, got %d (failed: %+v)",
			len(out.Shots), out.Failed)
	}
	s := out.Shots[0]

	// A PNG, proved by its magic bytes rather than by its name. A
	// field called `png_base64` holding something else is the one
	// thing the server cannot store and the one thing it checks for.
	png, err := base64.StdEncoding.DecodeString(s.PNG)
	if err != nil {
		t.Fatalf("the image is not valid base64: %v", err)
	}
	if !strings.HasPrefix(string(png), "\x89PNG\r\n\x1a\n") {
		t.Errorf("the image is not a PNG: % x", png[:min(8, len(png))])
	}
	if len(png) != s.Bytes {
		t.Errorf("bytes=%d but the image is %d bytes", s.Bytes, len(png))
	}

	// What the browser knew, which is the half of this a picture
	// cannot carry.
	if s.Status != 200 {
		t.Errorf("status=%d, wanted the main document's 200", s.Status)
	}
	if s.Title != "ACME portal" {
		t.Errorf("title=%q -- the title is set by script, so an empty one "+
			"means the page was fetched and not rendered", s.Title)
	}
	if s.Server != "acme-httpd/1.0" {
		t.Errorf("server=%q, wanted the response header", s.Server)
	}
	if s.Width != 1280 || s.Height != 800 {
		t.Errorf("viewport %dx%d, wanted 1280x800", s.Width, s.Height)
	}

	// Attribution and credentials, as every other web task carries
	// them.
	mu.Lock()
	defer mu.Unlock()
	if sawUA != "OddJob-Test/1.0" {
		t.Errorf("the browser called itself %q, not what the project set",
			sawUA)
	}
	if sawCookie != "session=abc123" {
		t.Errorf("cookie=%q -- a screenshot behind a login needs the "+
			"session to reach the browser", sawCookie)
	}
	if sawHeader != "tok-xyz" {
		t.Errorf("X-Session=%q, wanted the header the task supplied", sawHeader)
	}
}

// A URL nothing answers is one page that failed, not a task that
// failed -- unless it was the only one.
func TestScreenshotReportsWhatItCouldNotPhotograph(t *testing.T) {
	exe, _ := browserPath(nil)
	if exe == "" {
		t.Skipf("no browser on this host")
	}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, "<html><title>up</title><body>up</body></html>")
		}))
	defer srv.Close()

	// The second address is a port nothing is listening on, so the
	// browser's navigation fails outright.
	res := runScreenshot(context.Background(), map[string]any{
		"urls":           []any{srv.URL, "http://127.0.0.1:1"},
		"settle_ms":      200,
		"page_timeout_s": 15,
	}, t.TempDir())

	if res.Status != "done" {
		t.Fatalf("one good page should still be a result: %s %s",
			res.Status, res.Error)
	}
	var out shotOut
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("bad output: %v", err)
	}
	if len(out.Shots) != 1 {
		t.Errorf("wanted the one page that answered, got %d", len(out.Shots))
	}
	// The one that did not is NAMED. "1 of 2" with no account of the
	// other is the substitution this codebase treats as a bug.
	if len(out.Failed) != 1 {
		t.Fatalf("the page that failed was not reported: %+v", out.Failed)
	}
	if !strings.Contains(out.Failed[0].URL, "127.0.0.1:1") {
		t.Errorf("the wrong page was reported as failed: %+v", out.Failed[0])
	}
}

// Everything below needs no browser: these are the gates that run
// before one is started.

func TestScreenshotRefusesWhatIsNotTheWeb(t *testing.T) {
	// A browser will open all of these quite happily, which is the
	// point: a screenshot task is the one kind whose entire output is
	// a picture of whatever it was pointed at, and it must not be
	// pointable at the agent's own host.
	for _, bad := range []string{
		"file:///etc/shadow",
		"chrome://net-internals",
		"data:text/html,<h1>hello",
		"ftp://files.acme.example/",
	} {
		if webURL(bad) {
			t.Errorf("%q was accepted as a web URL", bad)
		}
	}
	for _, good := range []string{
		"http://acme.example/", "https://portal.acme.example:8443/login",
	} {
		if !webURL(good) {
			t.Errorf("%q was refused and is an ordinary web URL", good)
		}
	}

	res := runScreenshot(context.Background(), map[string]any{
		"urls": []any{"file:///etc/shadow"},
	}, t.TempDir())
	if res.Status != "failed" {
		t.Errorf("a task of nothing but local paths ran: %+v", res)
	}
}

func TestScreenshotNeedsATarget(t *testing.T) {
	res := runScreenshot(context.Background(), map[string]any{}, t.TempDir())
	if res.Status != "failed" || !strings.Contains(res.Error, "targets") {
		t.Errorf("an empty task should say what it wanted: %+v", res)
	}
}

// The User-Agent is set on the browser, not sent twice. Sending it
// through the extra-headers path as well would be two sources of
// truth for one header, and the one that lost would be the project's.
func TestScreenshotHeadersLeaveTheUserAgentAlone(t *testing.T) {
	h := extraHeaders(map[string]any{
		"headers": []any{"X-Session: tok", "User-Agent: not-this-one"},
		"cookies": "a=b",
	})
	if _, ok := h["User-Agent"]; ok {
		t.Error("the User-Agent was duplicated into the extra headers")
	}
	if h["X-Session"] != "tok" || h["Cookie"] != "a=b" {
		t.Errorf("headers lost on the way through: %+v", h)
	}
	if extraHeaders(map[string]any{}) != nil {
		t.Error("a task with no headers should send none, not an empty set")
	}
}
