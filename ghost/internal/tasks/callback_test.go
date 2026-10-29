package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// The whole point of the feature: a connection arriving on a port we
// held open is the evidence, and it comes back in the result.
func TestCallbackCatchesAConnection(t *testing.T) {
	old := ProbeCallback
	defer func() { ProbeCallback = old }()

	// Stands in for Oddjob dialling us from outside. It really
	// connects, so the listener really sees the nonce -- which is
	// what `reachable` is allowed to mean.
	ProbeCallback = func(_ context.Context, port int, proto string) (
		string, bool, string, error) {
		nonce := "oddjob-probe-test"
		c, err := net.Dial(proto, fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nonce, false, err.Error(), nil
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte(nonce))
		return nonce, true, "connected", nil
	}

	args := map[string]any{
		"callback":      "tcp",
		"callback_host": "127.0.0.1",
		"url":           "https://acme.example/?u={{callback_url}}",
		"nested":        map[string]any{"hdr": []any{"X-Out: {{callback}}"}},
	}
	var sawURL, sawHdr string
	runner := func(_ context.Context, a map[string]any, _ string) Result {
		sawURL, _ = a["url"].(string)
		n, _ := a["nested"].(map[string]any)
		hs, _ := n["hdr"].([]any)
		sawHdr, _ = hs[0].(string)
		// The "target" fetching the callback URL, which is the whole
		// shape of an out-of-band finding.
		host := strings.TrimPrefix(sawURL, "https://acme.example/?u=http://")
		host = strings.SplitN(host, "/", 2)[0]
		c, err := net.Dial("tcp", host)
		if err == nil {
			_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: acme\r\n\r\n"))
			_ = c.Close()
		}
		return Result{Status: "done", Output: `{"urls":[]}`, Summary: "ran"}
	}

	res := Run(context.Background(), runner, args, t.TempDir())

	// Substitution reaches a nested slice inside a nested map, which
	// is where a header actually lives.
	if !strings.Contains(sawURL, "http://127.0.0.1:") {
		t.Errorf("url was not substituted: %q", sawURL)
	}
	if strings.Contains(sawURL, "{{callback") {
		t.Errorf("placeholder survived: %q", sawURL)
	}
	if !strings.Contains(sawHdr, "127.0.0.1:") {
		t.Errorf("nested header was not substituted: %q", sawHdr)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(res.Output), &doc); err != nil {
		t.Fatalf("output is no longer the document the importer reads: %v", err)
	}
	cb, _ := doc["callback"].(map[string]any)
	if cb == nil {
		t.Fatal("no callback block in the output")
	}
	if cb["state"] != "found" {
		t.Errorf("state=%v why=%v", cb["state"], cb["why"])
	}
	if cb["reachable"] != true {
		t.Errorf("the probe connected, so reachable should be true: %+v", cb)
	}
	hits, _ := cb["hits"].([]any)
	// Exactly one: the probe is ours and must have been taken back
	// out. Reporting our own connection as a finding would be the
	// tool finding itself.
	if len(hits) != 1 {
		t.Fatalf("want 1 hit (the probe removed), got %d: %+v", len(hits), hits)
	}
	h, _ := hits[0].(map[string]any)
	if p, _ := h["preview"].(string); !strings.Contains(p, "GET /") {
		t.Errorf("the hit should carry what arrived, got %q", p)
	}
	if !strings.Contains(res.Summary, "callback: found") {
		t.Errorf("summary should say so too: %q", res.Summary)
	}
}

// The case the whole three-state design exists for. A port nothing
// can reach produces the same silence a clean result does, and
// calling that `absent` would be claiming a measurement never taken.
func TestUnreachablePortIsUnknownNotAbsent(t *testing.T) {
	old := ProbeCallback
	defer func() { ProbeCallback = old }()
	ProbeCallback = func(_ context.Context, _ int, _ string) (
		string, bool, string, error) {
		return "n", false, "timed out — nothing on the path answered", nil
	}

	res := Run(context.Background(),
		func(context.Context, map[string]any, string) Result {
			return Result{Status: "done", Output: `{}`}
		},
		// One second, not the 90 the agent uses: this asserts the
		// three-state logic, not how long a real callback is worth
		// waiting for.
		map[string]any{"callback": "tcp", "callback_host": "127.0.0.1",
			"callback_wait_s": 1},
		t.TempDir())

	var doc map[string]any
	_ = json.Unmarshal([]byte(res.Output), &doc)
	cb, _ := doc["callback"].(map[string]any)
	if cb["state"] != "unknown" {
		t.Fatalf("state=%v, want unknown: %+v", cb["state"], cb)
	}
	if cb["reachable"] != false {
		t.Errorf("reachable should be false: %+v", cb)
	}
	why, _ := cb["why"].(string)
	if !strings.Contains(why, "measured nothing") {
		t.Errorf("the reason has to say the test proved nothing, got %q", why)
	}
}

// Reachable and quiet IS a result, and a different one.
func TestReachableAndQuietIsAbsent(t *testing.T) {
	old := ProbeCallback
	defer func() { ProbeCallback = old }()
	ProbeCallback = func(_ context.Context, port int, proto string) (
		string, bool, string, error) {
		nonce := "oddjob-probe-quiet"
		c, err := net.Dial(proto, fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nonce, false, err.Error(), nil
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte(nonce))
		return nonce, true, "connected", nil
	}
	// A short window so the test does not sit out the real one.
	res := runWithWindow(t, map[string]any{
		"callback": "tcp", "callback_host": "127.0.0.1",
	})
	var doc map[string]any
	_ = json.Unmarshal([]byte(res.Output), &doc)
	cb, _ := doc["callback"].(map[string]any)
	if cb["state"] != "absent" {
		t.Fatalf("state=%v, want absent: %+v", cb["state"], cb)
	}
	if hits, _ := cb["hits"].([]any); len(hits) != 0 {
		t.Errorf("the probe must not be reported as a callback: %+v", hits)
	}
}

// Drives the same path with a window short enough for a test. The
// production window is 90s because an out-of-band callback is
// routinely minutes behind the request.
func runWithWindow(t *testing.T, args map[string]any) Result {
	t.Helper()
	cb := openCallback(context.Background(), args)
	if cb == nil || cb.l == nil {
		t.Fatalf("no listener: %+v", cb)
	}
	cb.prove(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	return withCallback(Result{Status: "done", Output: `{}`},
		cb.report(ctx, 400*time.Millisecond))
}

// A task that did not ask for one must not pay for one, and must not
// have a callback block invented in its output.
func TestNoCallbackUnlessAsked(t *testing.T) {
	res := Run(context.Background(),
		func(context.Context, map[string]any, string) Result {
			return Result{Status: "done", Output: `{"a":1}`}
		},
		map[string]any{"url": "https://acme.example/"}, t.TempDir())
	if strings.Contains(res.Output, "callback") {
		t.Errorf("output gained a callback block: %s", res.Output)
	}
}

func TestWantsCallback(t *testing.T) {
	cases := map[any]string{
		"tcp": "tcp", "TCP": "tcp", " udp ": "udp", "UDP": "udp",
		true: "tcp", false: "", "yes": "tcp", "dns": "", "": "", 1: "",
	}
	for in, want := range cases {
		if got := wantsCallback(map[string]any{"callback": in}); got != want {
			t.Errorf("callback=%#v gave %q, want %q", in, got, want)
		}
	}
	if got := wantsCallback(map[string]any{}); got != "" {
		t.Errorf("absent should be no callback, got %q", got)
	}
}

// Output that is not a JSON object -- nmap's XML -- keeps its document
// intact and says it in the summary instead.
func TestNonJSONOutputKeepsItsDocument(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun/>`
	res := withCallback(Result{Status: "done", Output: xml, Summary: "nmap"},
		map[string]any{"state": "absent", "why": "nothing connected"})
	if res.Output != xml {
		t.Errorf("the scanner's own document was altered: %s", res.Output)
	}
	if !strings.Contains(res.Summary, "callback: absent") {
		t.Errorf("summary should carry it instead: %q", res.Summary)
	}
}
