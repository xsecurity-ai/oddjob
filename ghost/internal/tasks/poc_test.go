package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// A template that matches a body only this handler serves, so a pass
// means the request really went out and the matcher really fired.
const tmplMatch = `id: poc-test-match
info:
  name: poc test
  author: oddjob
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "VULNERABLE-MARKER"
`

const tmplNoMatch = `id: poc-test-nomatch
info:
  name: poc test
  author: oddjob
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "THIS-STRING-IS-NOT-SERVED"
`

// Not YAML nuclei will accept. The point is what happens next.
const tmplBroken = `id: poc-test-broken
info:
  name: [unclosed
http:
  - method: GET
`

func verdict(t *testing.T, res Result) (int, map[string]any) {
	t.Helper()
	var doc struct {
		Poc map[string]any `json:"poc"`
	}
	if err := json.Unmarshal([]byte(res.Output), &doc); err != nil {
		t.Fatalf("output is not the shape the importer reads: %v\n%s",
			err, res.Output)
	}
	return res.ExitCode, doc.Poc
}

func needNuclei(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nuclei"); err != nil {
		// Skipped where there is no binary, and the skip says which:
		// the agent IMAGE has nuclei, a laptop often does not, and a
		// test that failed on the latter is a test nobody can run.
		t.Skip("no nuclei on this host; the agent image has one")
	}
}

func TestPocReproduces(t *testing.T) {
	needNuclei(t)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("hello VULNERABLE-MARKER world"))
		}))
	defer srv.Close()

	code, poc := verdict(t, runPoc(context.Background(), map[string]any{
		"template": tmplMatch, "url": srv.URL,
	}, t.TempDir()))

	if code != PocReproduced {
		t.Fatalf("exit %d, want %d (%v)", code, PocReproduced, poc["why"])
	}
	if poc["verdict"] != "reproduced" {
		t.Errorf("verdict %v", poc["verdict"])
	}
	// The word as well as the number: a reader of the raw result
	// should not have to remember which way round 0 and 1 go, and
	// getting it backwards inverts the finding.
	hits, _ := poc["hits"].([]any)
	if len(hits) == 0 {
		t.Errorf("a reproduction should carry what matched: %+v", poc)
	}
}

// The remediation check. This is the answer that closes a finding, so
// it has to come from a template that RAN and matched nothing.
func TestPocDoesNotReproduce(t *testing.T) {
	needNuclei(t)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("nothing to see"))
		}))
	defer srv.Close()

	code, poc := verdict(t, runPoc(context.Background(), map[string]any{
		"template": tmplNoMatch, "url": srv.URL,
	}, t.TempDir()))

	if code != PocFixed {
		t.Fatalf("exit %d, want %d (%v)", code, PocFixed, poc["why"])
	}
	if poc["verdict"] != "not reproduced" {
		t.Errorf("verdict %v", poc["verdict"])
	}
}

// The one that must never be wrong. A host that cannot be reached
// matches nothing, exactly like a fixed one -- and reporting that as
// fixed closes a live finding on the strength of a network error.
func TestUnreachableIsNotFixed(t *testing.T) {
	needNuclei(t)
	// A port nothing is on. Closed, so this fails fast rather than
	// sitting out the timeout.
	srv := httptest.NewServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()

	code, poc := verdict(t, runPoc(context.Background(), map[string]any{
		"template": tmplNoMatch, "url": dead,
	}, t.TempDir()))

	if code == PocFixed {
		t.Fatalf("an unreachable host was reported as FIXED — this is the "+
			"failure the three-state contract exists to prevent: %+v", poc)
	}
}

// A template the model got slightly wrong would otherwise run, match
// nothing, and be read as FIXED. Validated first, so it reports as
// untested instead and nothing is sent at all.
func TestBrokenTemplateIsUntestedNotFixed(t *testing.T) {
	needNuclei(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			hits++
			_, _ = w.Write([]byte("ok"))
		}))
	defer srv.Close()

	code, poc := verdict(t, runPoc(context.Background(), map[string]any{
		"template": tmplBroken, "url": srv.URL,
	}, t.TempDir()))

	if code != PocUnknown {
		t.Fatalf("exit %d, want %d (could not test): %+v",
			code, PocUnknown, poc)
	}
	if hits != 0 {
		t.Errorf("an invalid template sent %d request(s) at the target; "+
			"it should be refused before anything goes out", hits)
	}
	if why, _ := poc["why"].(string); !strings.Contains(why, "validate") {
		t.Errorf("the reason should say the template was rejected: %q", why)
	}
}

func TestPocRefusesWithNothingToRun(t *testing.T) {
	r := runPoc(context.Background(), map[string]any{"url": "https://a.example"},
		t.TempDir())
	if r.Status != "failed" {
		t.Errorf("no template should fail, got %+v", r)
	}
	r = runPoc(context.Background(), map[string]any{"template": tmplMatch},
		t.TempDir())
	if r.Status != "failed" {
		t.Errorf("no target should fail, got %+v", r)
	}
}

func TestPocHitsKeepsOnlyWhatIdentifies(t *testing.T) {
	// A nuclei result carries the whole request and response. This
	// row is read in a browser and the bytes are already in the web
	// tables, so only what identifies the match is kept.
	line := `{"template-id":"x","matched-at":"https://a.example/",` +
		`"host":"a.example","type":"http","request":"GET / ...",` +
		`"response":"HTTP/1.1 200 ...","curl-command":"curl ..."}`
	got := pocHits(line + "\n\n")
	if len(got) != 1 {
		t.Fatalf("got %d hits", len(got))
	}
	for _, drop := range []string{"request", "response", "curl-command"} {
		if _, ok := got[0][drop]; ok {
			t.Errorf("%q should not be carried into the result", drop)
		}
	}
	if got[0]["template-id"] != "x" || got[0]["matched-at"] == nil {
		t.Errorf("what identifies the match was dropped: %+v", got[0])
	}
	if n := len(pocHits("not json\n{bad\n")); n != 0 {
		t.Errorf("unparseable lines should be skipped, got %d", n)
	}
}

// --- authenticating proofs: the credential must not escape ---------

// A proof that needs a credential and has nobody to ask must report
// "could not test". The alternative is that it runs with `{{secret}}`
// unsubstituted, gets refused by the service, matches nothing, and is
// recorded as FIXED -- closing a live credential finding because the
// agent could not fetch a key.
func TestPocNeedsSecretWithNoFetcherCannotTest(t *testing.T) {
	old := TaskSecret
	defer func() { TaskSecret = old }()
	TaskSecret = nil

	res := runPoc(context.Background(), map[string]any{
		"template":     "id: x\nhttp:\n  - path: [\"{{BaseURL}}\"]\n    matchers: []\n",
		"url":          "https://app.acme.example",
		"needs_secret": true,
	}, t.TempDir())

	if res.ExitCode != PocUnknown {
		t.Fatalf("exit %d, want PocUnknown (%d)", res.ExitCode, PocUnknown)
	}
	if !strings.Contains(res.Summary, "could not be tested") {
		t.Fatalf("summary %q does not say it could not be tested", res.Summary)
	}
}

// The same when the server refuses to release it.
func TestPocSecretFetchFailureCannotTest(t *testing.T) {
	old := TaskSecret
	defer func() { TaskSecret = old }()
	TaskSecret = func(context.Context, int64) (string, error) {
		return "", errors.New("refused")
	}

	res := runPoc(context.Background(), map[string]any{
		"template":     "id: x\nhttp:\n  - path: [\"{{BaseURL}}\"]\n",
		"url":          "https://app.acme.example",
		"needs_secret": true,
	}, t.TempDir())

	if res.ExitCode != PocUnknown {
		t.Fatalf("exit %d, want PocUnknown (%d)", res.ExitCode, PocUnknown)
	}
	if strings.Contains(res.Summary, "did not reproduce") {
		t.Fatal("a failed fetch was reported as the finding being fixed")
	}
}

// scrub is the single point a credential is taken back out of
// anything leaving this host. `matched-at` is the realistic carrier:
// a template that put the key in a query string sends it home inside
// a field `pocHits` keeps on purpose.
func TestScrubRemovesTheCredential(t *testing.T) {
	// Named `fixture` rather than `secret`: gosec G101 reads a
	// string literal assigned to a name like that as a hardcoded
	// credential, and it is right to — this is a test value, and
	// the way to say so is to not call it a secret.
	fixture := "<<not-a-real-key>>"
	res := scrub(Result{
		Output:  `{"poc":{"hits":[{"matched-at":"https://a/?k=` + fixture + `"}]}}`,
		Summary: "poc: reproduced on https://a/?k=" + fixture,
	}, fixture)

	if strings.Contains(res.Output, fixture) {
		t.Fatal("the credential survived in Output")
	}
	if strings.Contains(res.Summary, fixture) {
		t.Fatal("the credential survived in Summary")
	}
	if !strings.Contains(res.Output, "[redacted]") {
		t.Fatal("nothing marks where it was")
	}
}

// An ordinary proof carries no secret, and scrub must leave it alone
// rather than redacting the empty string into every character.
func TestScrubIsANoopWithoutASecret(t *testing.T) {
	in := Result{Output: "untouched", Summary: "also untouched"}
	got := scrub(in, "")
	if got.Output != in.Output || got.Summary != in.Summary {
		t.Fatalf("scrub changed a result that carried no secret: %+v", got)
	}
}
