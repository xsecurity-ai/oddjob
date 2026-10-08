package tasks

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntArg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want int
	}{
		// What the server actually sends: JSON numbers decode as float64.
		{"a json number", map[string]any{"n": 500.0}, 500},
		{"a go int", map[string]any{"n": 500}, 500},
		{"absent", map[string]any{}, 7},
		// Zero means "use the default", not "no queries at all". The
		// second reading gives an agent that looks alive and finds
		// nothing, which is the worst of the three outcomes.
		{"zero falls back", map[string]any{"n": 0.0}, 7},
		{"negative falls back", map[string]any{"n": -1.0}, 7},
		{"a string is not a number", map[string]any{"n": "500"}, 7},
		{"nil", map[string]any{"n": nil}, 7},
	}
	for _, c := range cases {
		if got := intArg(c.args, "n", 7); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestBoolArg(t *testing.T) {
	// Absent and false are different answers. The default for
	// `recursive` is true, so reading a missing key as false would
	// silently turn recursion off for every task that did not mention
	// it -- a much smaller enumeration that still reports success.
	if !boolArg(map[string]any{}, "recursive", true) {
		t.Error("absent did not fall back to the default")
	}
	if boolArg(map[string]any{"recursive": false}, "recursive", true) {
		t.Error("an explicit false was overridden by the default")
	}
	if !boolArg(map[string]any{"recursive": true}, "recursive", false) {
		t.Error("an explicit true did not win")
	}
	if boolArg(map[string]any{"recursive": "yes"}, "recursive", false) {
		t.Error("a string was read as a bool")
	}
}

func TestResolversFor(t *testing.T) {
	// Stated rather than inherited: an agent inside a corporate network
	// picks up a resolver that answers for the INTERNAL view of a zone,
	// and an enumeration returning split-horizon records is a wrong
	// answer that looks like a right one.
	if got := resolversFor(map[string]any{}); len(got) != len(defaultResolvers) {
		t.Errorf("default resolvers: got %d want %d", len(got), len(defaultResolvers))
	}
	got := resolversFor(map[string]any{"resolvers": []any{"10.0.0.1", "10.0.0.2"}})
	if len(got) != 2 || got[0] != "10.0.0.1" {
		t.Errorf("explicit resolvers not used: %v", got)
	}
}

func TestAmassRefusesMoreThanOneZone(t *testing.T) {
	// Reached before any network setup, so this costs nothing and does
	// not enumerate anything.
	r := runAmassLib(context.Background(),
		map[string]any{"domains": []any{"a.example", "b.example"}}, t.TempDir())
	if r.Status != "failed" || !strings.Contains(r.Error, "one domain per task") {
		t.Fatalf("two zones were not refused: %+v", r)
	}
	r = runAmassLib(context.Background(), map[string]any{}, t.TempDir())
	if r.Status != "failed" {
		t.Fatalf("no domain was not refused: %+v", r)
	}
}

// TestAmassEnumerates is the only test here that touches the network.
//
// Off by default: it queries third-party OSINT sources, which is not
// something a unit test run should do on somebody's laptop or in CI on
// every push. `example.com` is reserved for documentation, so when it
// IS run it enumerates nothing belonging to anyone.
//
//	DRONE_TEST_AMASS=1 go test ./internal/tasks/ -run Enumerates -v
func TestAmassEnumerates(t *testing.T) {
	if os.Getenv("DRONE_TEST_AMASS") == "" {
		t.Skip("set DRONE_TEST_AMASS=1 to run the live enumeration")
	}
	start := time.Now()
	r := runAmassLib(context.Background(), map[string]any{
		"domain": "example.com", "timeout_seconds": 180.0,
	}, t.TempDir())
	if r.Status != "done" {
		t.Fatalf("status %s: %s", r.Status, r.Summary)
	}
	var out struct {
		Domain   string   `json:"domain"`
		Names    []string `json:"names"`
		Mode     string   `json:"mode"`
		Complete bool     `json:"complete"`
	}
	if err := json.Unmarshal([]byte(r.Output), &out); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if out.Domain != "example.com" {
		t.Errorf("domain %q", out.Domain)
	}
	if out.Mode != "passive" {
		t.Errorf("mode %q — passive is the default and must stay so", out.Mode)
	}
	// Under the zone asked about and nothing else: the graph holds
	// whatever the sources mentioned, which on a shared certificate is
	// somebody else's estate.
	for _, n := range out.Names {
		if n != "example.com" && !strings.HasSuffix(n, ".example.com") {
			t.Errorf("%q is not under example.com", n)
		}
	}
	t.Logf("%d name(s) in %s, complete=%v",
		len(out.Names), time.Since(start).Round(time.Second), out.Complete)
}
