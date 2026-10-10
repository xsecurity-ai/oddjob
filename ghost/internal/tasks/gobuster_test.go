package tasks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// Against a real server, because the failure this replaces was silent
// in exactly the way a mock cannot show: the old implementation shelled
// out, and a missing binary or a missing wordlist produced a clean
// "0 paths found" that looked like a scanned site with nothing on it.
func TestGobusterFindsPaths(t *testing.T) {
	// Guarded: gobuster sends concurrently, so the handler runs on
	// several goroutines at once and the test reads these afterwards.
	// Without the mutex this is a data race, which `go test -race`
	// fails on — CI does, and this did.
	var mu sync.Mutex
	var seenUA, seenAuth, seenCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenUA = r.UserAgent()
		if a := r.Header.Get("Authorization"); a != "" {
			seenAuth = a
		}
		if c := r.Header.Get("Cookie"); c != "" {
			seenCookie = c
		}
		mu.Unlock()
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
	mu.Lock()
	defer mu.Unlock()
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

// A project's own paths are APPENDED, never substituted.
//
// The failure this guards against is the quiet one: reading "add
// these three" as "use only these three" turns a 4,751-entry sweep
// into a three-request one that still reports as content discovery
// and still says "done".
func TestProjectWordsAppend(t *testing.T) {
	dir := t.TempDir()
	merged, builtin, err := wordlistPath(map[string]any{
		// []any is what arrives over JSON.
		"extra_words": []any{"deploy-internal", "/leading-slash", "admin", ""},
	}, dir)
	if err != nil {
		t.Fatalf("merging failed: %v", err)
	}
	// #nosec G304 -- `merged` is the path wordlistPath just
	// returned, inside this test's own TempDir
	b, err := os.ReadFile(merged)
	if err != nil {
		t.Fatalf("reading the merged list: %v", err)
	}
	words := strings.Split(strings.TrimSpace(string(b)), "\n")
	set := map[string]int{}
	for _, w := range words {
		set[strings.TrimSpace(w)]++
	}

	// The base list survives in full.
	if len(words) < 4000 {
		t.Errorf("merged list has %d entries — the base list was replaced, "+
			"not appended to", len(words))
	}
	for _, keep := range []string{".env", "phpmyadmin", "backup"} {
		if set[keep] == 0 {
			t.Errorf("base entry %q was lost", keep)
		}
	}
	// The project's additions are there.
	if set["deploy-internal"] == 0 {
		t.Error("the project's path was not appended")
	}
	// A leading slash is stripped: a wordlist holds paths relative to
	// the base url, and `/admin` would be requested as `//admin`.
	if set["leading-slash"] == 0 {
		t.Errorf("a leading slash was not stripped: %v",
			[]string{"leading-slash", "/leading-slash"})
	}
	// `admin` is already in SecLists; it must not be requested twice.
	if set["admin"] > 1 {
		t.Errorf("%q appears %d times — the merge did not deduplicate",
			"admin", set["admin"])
	}
	// Blank entries are dropped rather than becoming a request for "/".
	if set[""] > 0 {
		t.Error("a blank line became a wordlist entry")
	}
	if !builtin {
		t.Log("a host wordlist was used as the base, which is also correct")
	}

	// No extras means no merged file and no copying.
	plain, _, err := wordlistPath(map[string]any{}, dir)
	if err != nil {
		t.Fatalf("plain path failed: %v", err)
	}
	if strings.Contains(plain, "gobuster-wordlist.txt") {
		t.Error("a merged file was written when there was nothing to merge")
	}
}
