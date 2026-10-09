package client

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The ghost and the server must agree on every path, and a rename is
// where they stop agreeing.
//
// This exists because of a real failure. The drone-to-ghost rename
// swept the word "drone" through 118 files, and the client's routes
// survived it untouched -- `/api/agents/heartbeat` contains neither
// "drone" nor "ghost", so there was nothing for the sweep to find. The
// server moved to `/api/ghosts/*`, the agent kept calling
// `/api/agents/*`, every test passed on both sides, and the fleet only
// failed when a real ghost was rolled onto the new image and could not
// register.
//
// Nothing in the unit suites could have caught it: each side was
// internally consistent. So this asserts the one thing that is not
// visible from inside either -- the literal prefix.
//
// The path is also an input to request signing and to the sealed-body
// channel binding, so a mismatch is not merely a 404: it is a 401 that
// reads like a credential problem, which is exactly how long it took
// to spot.
func TestRoutesUseTheCurrentPrefix(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatal(err)
	}
	paths := regexp.MustCompile(`"(/api/[a-z0-9/_{}%:-]*)`).FindAllStringSubmatch(string(src), -1)
	if len(paths) < 5 {
		t.Fatalf("found %d API paths in client.go; the pattern has stopped "+
			"matching and this test is no longer checking anything", len(paths))
	}
	for _, m := range paths {
		p := m[1]
		if !strings.HasPrefix(p, "/api/ghosts/") {
			t.Errorf("%s does not start with /api/ghosts/ — the server moved "+
				"and this did not", p)
		}
	}
}

// And the inverse: no production file in the module may still name the
// old prefix. Test fixtures may -- `sealvec_test.go` holds a ciphertext
// the server sealed with `/api/agents/heartbeat` in its AAD, which is
// recorded input and not a route anybody calls.
func TestNoProductionFileNamesTheOldPrefix(t *testing.T) {
	// Globs rather than filepath.Walk. The walk tripped gosec's G122
	// -- a callback that stats and then reads is open to a symlink
	// swap in between -- and the answer to a linter finding in a
	// guard test is not a second suppression on top of the first. The
	// layout here is two flat levels, so a glob says the same thing
	// with nothing to race.
	var files []string
	for _, pat := range []string{
		filepath.Join("..", "*", "*.go"),
		filepath.Join("..", "..", "cmd", "*", "*.go"),
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}

	var bad []string
	var checked int
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		// #nosec G304 -- a glob over this module's own source tree in
		// a test. There is no external input.
		b, err := os.ReadFile(path)
		if err != nil {
			// Not skipped: a file this cannot read is a file it cannot
			// check, and a guard that quietly passes over what it
			// could not open passes for the wrong reason.
			t.Fatalf("reading %s: %v", path, err)
		}
		checked++
		if strings.Contains(string(b), "/api/agents") {
			bad = append(bad, path)
		}
	}
	if checked < 10 {
		t.Fatalf("only checked %d production files; the globs are not "+
			"reaching the tree and this test is asserting almost nothing",
			checked)
	}
	if len(bad) > 0 {
		t.Errorf("production files still calling the old prefix: %s",
			strings.Join(bad, ", "))
	}
}
