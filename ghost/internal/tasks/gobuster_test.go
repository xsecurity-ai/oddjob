package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Against a real server, because the failure this replaces was silent
// in exactly the way a mock cannot show: the old implementation shelled
// out, and a missing binary or a missing wordlist produced a clean
// "0 paths found" that looked like a scanned site with nothing on it.
func TestGobusterFindsPaths(t *testing.T) {
	var seenUA, seenAuth, seenCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenUA = r.UserAgent()
		if a := r.Header.Get("Authorization"); a != "" {
			seenAuth = a
		}
		if c := r.Header.Get("Cookie"); c != "" {
			seenCookie = c
		}
		switch strings.TrimPrefix(r.URL.Path, "/") {
		case "admin":
			w.WriteHeader(http.StatusOK)
		case "secret":
			// A 403 says the path EXISTS. gobuster's own default
			// allowlist would hide it, which is why this uses a
			// blacklist of 404 instead.
			w.WriteHeader(http.StatusForbidden)
		case "login":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res := runGobuster(context.Background(), map[string]any{
		"url":      srv.URL,
		"threads":  4,
		"username": "scanner",
		"password": "hunter2",
		"cookies":  "session=abc123",
	}, t.TempDir())

	if res.Status != "done" {
		t.Fatalf("status=%s err=%s stderr=%s", res.Status, res.Error, res.Stderr)
	}
	var out struct {
		URL      string   `json:"url"`
		Wordlist string   `json:"wordlist"`
		Found    []string `json:"found"`
	}
	if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
		t.Fatalf("output is not the documented shape: %v", err)
	}
	joined := strings.Join(out.Found, "\n")

	for _, want := range []string{"admin", "secret", "login"} {
		if !strings.Contains(joined, want) {
			t.Errorf("did not find /%s; found: %v", want, out.Found)
		}
	}
	// 403 and 401 must survive. This is the assertion that would fail
	// if somebody "fixed" the status handling back to an allowlist.
	if !strings.Contains(joined, "secret") {
		t.Error("a 403 was dropped — a path that exists was reported as absent")
	}
	// ...and a 404 must not be reported as a find.
	if strings.Contains(joined, "nonexistent-path-xyz") {
		t.Error("a 404 was reported as a result")
	}

	// Attribution: the target's own logs should say who this was.
	if !strings.Contains(seenUA, "Oddjob") {
		t.Errorf("user agent was %q, which does not identify the scan", seenUA)
	}
	// Credentials reached the wire, which is the authenticated-
	// discovery case.
	if seenAuth == "" {
		t.Error("basic auth credentials were not sent")
	}
	if !strings.Contains(seenCookie, "session=abc123") {
		t.Errorf("cookies were not sent: %q", seenCookie)
	}
}

// The embedded list is what makes this work on a host with no dirb
// installed, which was the common failure.
func TestBuiltinWordlistIsUsable(t *testing.T) {
	if n := len(strings.Fields(builtinWordlist)); n < 1000 {
		t.Errorf("the built-in wordlist has %d entries, which is not a list", n)
	}
	for _, want := range []string{".env", "admin", "backup", "phpmyadmin"} {
		if !strings.Contains(builtinWordlist, want) {
			t.Errorf("the built-in wordlist is missing %q", want)
		}
	}
	// Staged into the task's own directory when nothing is on the host.
	dir := t.TempDir()
	p, builtin, err := wordlistPath(map[string]any{}, dir)
	if err != nil {
		t.Fatalf("staging failed: %v", err)
	}
	if !builtin && !strings.Contains(p, dir) {
		t.Logf("a host wordlist was found and preferred: %s", p)
	}
	// An explicitly named wordlist that does not exist is an error,
	// not a silent fallback to the built-in one: an operator who named
	// a list and got different results would have no way to tell.
	if _, _, err := wordlistPath(map[string]any{
		"wordlist": "/nonexistent/list.txt"}, dir); err == nil {
		t.Error("a missing named wordlist was accepted")
	}
}
