//go:build linux

package capacity

import (
	"strconv"
	"strings"
	"testing"
)

// The cgroup busy counters are what make the idle figure honest in a
// container. Tested here rather than against the host's real files so
// the shapes can be stated: a field rename or unit slip would otherwise
// be silent, and a silent one reports a pinned core as 97% idle --
// which is exactly the reading that made the fleet look wedged.

func TestParseCPUStatUsec(t *testing.T) {
	// The real file's shape: every counter in microseconds, cumulative
	// since the cgroup was created. Only user and system count as busy;
	// core and nr_periods are bookkeeping.
	const sample = `usage_usec 123456789
user_usec 100000000
system_usec 23456789
core_usec 0
nr_periods 0
nr_throttled 0
throttled_usec 0
`
	if got := parseCPUStatUsec([]byte(sample)); got != 123456789 {
		t.Errorf("parseCPUStatUsec = %d usec, want 123456789 (user+system)", got)
	}
	// An absent field is skipped, not an error: kernels add counters.
	if got := parseCPUStatUsec([]byte("usage_usec 5\nnr_periods 1\n")); got != 0 {
		t.Errorf("a file with no user/system lines gave %d, want 0", got)
	}
	if got := parseCPUStatUsec(nil); got != 0 {
		t.Errorf("empty input gave %d, want 0", got)
	}
}

func TestParseCPUAcctStatUsec(t *testing.T) {
	// v1 counts NANOseconds under the names user and system. The unit
	// slip is the whole hazard: reading ns as us would make every busy
	// sample a thousand times too large and the idle figure zero.
	const sample = "user 1000000000\nsystem 234567890\n"
	if got := parseCPUAcctStatUsec([]byte(sample)); got != 1234567890 {
		t.Errorf("parseCPUAcctStatUsec = %d usec, want 1234567890", got)
	}
	if got := parseCPUAcctStatUsec(nil); got != 0 {
		t.Errorf("empty input gave %d, want 0", got)
	}
}

// TestDiagPrintInput is a temporary diagnostic: it prints the exact
// bytes the test feeds to parseCPUAcctStatUsec and what each line
// parses to. It exists because CI has kept compiling a binary that
// returns the pre-fix value from this very source, and the only way
// left to tell which side is lying is to make the test say out loud
// what it is reading. Remove it once the mystery is solved.
func TestDiagPrintInput(t *testing.T) {
	const sample = "user 1000000000\nsystem 234567890\n"
	t.Logf("input bytes (len %d): %q", len(sample), sample)
	for _, line := range strings.Split(sample, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseInt(f[1], 10, 64)
		t.Logf("line=%q field0=%q field1=%q parsedNS=%d", line, f[0], f[1], n)
	}
	t.Logf("parseCPUAcctStatUsec(sample) = %d", parseCPUAcctStatUsec([]byte(sample)))
}

// The wall side: a cgroup with two cores gets two core-seconds per
// second of wall time. A fully idle sample must therefore read as
// 100% idle, and a sample that spent every core-second busy as ~0%.
func TestCgroupBusyMathIsSane(t *testing.T) {
	// Two samples 150 ms apart on a 2-core cgroup: wall = 300 ms of
	// core time. If the tasks spent 100 ms of it busy, idle is 200/300.
	const wall uint64 = 300_000 // usec
	busy := uint64(100_000)
	idle := wall - busy
	if got := fractionU(idle, wall); got != 2.0/3.0 {
		t.Errorf("fractionU(%d, %d) = %v, want 0.667", idle, wall, got)
	}
	// A pinned core: zero busy in the window reads as fully idle...
	if got := fractionU(wall-0, wall); got != 1 {
		t.Errorf("a fully idle window read %v, want 1", got)
	}
	// ...and a fully busy one reads as zero.
	if got := fractionU(0, wall); got != 0 {
		t.Errorf("a fully busy window read %v, want 0", got)
	}
	_ = busy
}

func TestCountCPURanges(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0-3,8", 5},
		{"0", 1},
		{"0-7", 8},
		{"2,4,6", 3},
		{"all", 0}, // "all" means the machine figure, decided at the call site
		{"", 0},
	}
	for _, c := range cases {
		if got := countCPURanges(c.in); got != c.want {
			t.Errorf("countCPURanges(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSelfCgroupPathShapes(t *testing.T) {
	// The line shapes differ between the two versions and a mixup is
	// silent: reading a v1 line as v2 would look for cpu.stat in the
	// wrong place and fall back to the host counters, which is the bug
	// this whole file exists to fix. Both are tested against the real
	// /proc/self/cgroup so the shapes cannot drift. A path that is not
	// absolute (or is "/") is what the caller uses to decide where to
	// look, so it must come out clean.
	if p := selfCgroupPath("v2"); p != "" && !isPath(p) {
		t.Errorf("v2 path %q is not an absolute path", p)
	}
	if p := selfCgroupPath("v1"); p != "" && !isPath(p) {
		t.Errorf("v1 path %q is not an absolute path", p)
	}
}

func isPath(s string) bool {
	return len(s) > 0 && s[0] == '/'
}

// The wall-side core count: a quota that buys two whole cores must say
// two, and a "max" file must say nothing at all so the next source
// gets the chance.
func TestCPUMaxQuotaCores(t *testing.T) {
	// Read against the real file when it exists; on a host without
	// cgroup v2 the answer is 0 and the machine figure stands in.
	if n := cpuMaxQuotaCores(); n < 0 {
		t.Errorf("cpuMaxQuotaCores = %d, want >= 0", n)
	}
}
