//go:build linux

package capacity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCgroupBytes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name, body string
		want       uint64
		ok         bool
	}{
		{"a real limit", "536870912\n", 536870912, true},
		{"no trailing newline", "1048576", 1048576, true},
		// Three different ways of saying "no limit", all of which must
		// be distinguishable from a limit of zero -- which is why this
		// returns a bool rather than just a number.
		{"v2 unlimited", "max\n", 0, false},
		{"v1 unlimited", "9223372036854771712\n", 0, false},
		{"empty", "", 0, false},
		{"not a number", "lots\n", 0, false},
		// A petabyte is not something an operator typed.
		{"absurd is not a limit", "1125899906842624", 0, false},
		// Zero IS a readable value, even if a useless one; it must not
		// be confused with "no file".
		{"zero is a value", "0\n", 0, true},
	}
	for _, c := range cases {
		got, ok := readCgroupBytes(write(c.name, c.body))
		if got != c.want || ok != c.ok {
			t.Errorf("%s: got (%d, %v) want (%d, %v)", c.name, got, ok, c.want, c.ok)
		}
	}

	if _, ok := readCgroupBytes(filepath.Join(dir, "does-not-exist")); ok {
		t.Error("an absent file reported a limit")
	}
}

func TestAvailableMemIsSane(t *testing.T) {
	// Whatever this machine is, the answer has to be usable: a
	// negative or absurd figure would size the whole fleet wrongly,
	// and 0 is allowed only as "could not tell".
	got := availableMemMB()
	if got < 0 {
		t.Fatalf("negative memory: %d", got)
	}
	if got > 1<<24 { // 16 TB
		t.Fatalf("implausible memory: %d MB", got)
	}
	// /proc/meminfo exists on any Linux running these tests, so the
	// host figure at least should be readable. If this ever fails on a
	// stripped container, the fallback is already "unknown" and
	// `size()` handles it — but it is worth knowing.
	if procMemAvailableMB() == 0 {
		t.Log("MemAvailable unreadable here; sizing will fall back to cores")
	}
}
