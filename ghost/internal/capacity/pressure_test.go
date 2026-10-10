package capacity

import (
	"context"
	"strings"
	"testing"
)

// The rule: do not start anything new within 20% of either limit.
//
// Tested on the fractions rather than on a host, so the interesting
// cases -- a box at 19% free, a box whose figures cannot be read --
// can be stated instead of waited for.
func TestAssess(t *testing.T) {
	cases := []struct {
		name          string
		mem, cpu      float64
		blocked       bool
		reasonMention string
	}{
		{"plenty of both", 0.80, 0.90, false, ""},
		{"exactly at the line is fine", 0.20, 0.20, false, ""},
		{"a hair under on memory blocks", 0.19, 0.90, true, "memory"},
		{"a hair under on cpu blocks", 0.90, 0.19, true, "CPU"},
		{"nothing left at all", 0.00, 0.00, true, "memory"},
		{"both short reports memory first", 0.05, 0.05, true, "memory"},

		// The case that must never block: unmeasurable is not empty.
		// Reporting 0% free for "did not look" would idle every agent
		// on a platform whose figures we cannot read.
		{"unknown memory does not block", Unknown, 0.90, false, ""},
		{"unknown cpu does not block", 0.90, Unknown, false, ""},
		{"both unknown does not block", Unknown, Unknown, false, ""},
		// ...but a known-bad figure still blocks alongside an unknown.
		{"unknown cpu does not rescue starved memory", 0.01, Unknown, true, "memory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blocked, reason := assess(c.mem, c.cpu)
			if blocked != c.blocked {
				t.Fatalf("assess(%v, %v) blocked=%v, want %v (%q)",
					c.mem, c.cpu, blocked, c.blocked, reason)
			}
			if c.reasonMention != "" && !strings.Contains(reason, c.reasonMention) {
				t.Errorf("reason %q does not mention %q", reason, c.reasonMention)
			}
			if !blocked && reason != "" {
				t.Errorf("not blocked but gave a reason: %q", reason)
			}
			// An operator reading this has to be able to act on it,
			// which means it needs the numbers, not just a verdict.
			if blocked && !strings.Contains(reason, "%") {
				t.Errorf("reason %q carries no figure", reason)
			}
		})
	}
}

func TestFractionGuards(t *testing.T) {
	if got := fraction(100, 0); got != Unknown {
		t.Errorf("a zero denominator gave %v, want Unknown", got)
	}
	if got := fraction(-1, 100); got != Unknown {
		t.Errorf("a negative numerator gave %v, want Unknown", got)
	}
	// Available can exceed the limit on a cgroup that is not really
	// limiting; clamped rather than reporting 140% free.
	if got := fraction(140, 100); got != 1 {
		t.Errorf("fraction(140,100) = %v, want 1", got)
	}
	if got := fraction(20, 100); got != 0.2 {
		t.Errorf("fraction(20,100) = %v, want 0.2", got)
	}
}

// Check has to work on the machine running the test, whatever it is:
// either real figures in range, or Unknown. What it must never do is
// invent a reading, because a wrong one here stops a fleet.
func TestCheckIsSaneOnThisHost(t *testing.T) {
	p := Check(context.Background())
	for _, f := range []struct {
		name string
		v    float64
	}{{"MemFree", p.MemFree}, {"CPUIdle", p.CPUIdle}} {
		if f.v == Unknown {
			continue
		}
		if f.v < 0 || f.v > 1 {
			t.Errorf("%s = %v, outside [0,1]", f.name, f.v)
		}
	}
	if p.Blocked && p.Reason == "" {
		t.Error("blocked without saying why")
	}
	if !p.Blocked && p.Reason != "" {
		t.Errorf("not blocked but gave reason %q", p.Reason)
	}
}

// The /proc parsing, which is where a silent mistake would live.
//
// Tested here rather than against the host's real files so the
// failure modes can be stated: the field order is fixed by the
// kernel, and counting the wrong column reports a busy machine as
// idle, which is exactly the reading that would let a starving host
// keep taking work.
func TestParseProcStat(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	const sample = `cpu  100 10 50 800 40 0 0 0 0 0
cpu0 50 5 25 400 20 0 0 0 0 0
intr 12345
`
	idle, total, ok := parseProcStat([]byte(sample))
	if !ok {
		t.Fatal("the aggregate cpu line was not found")
	}
	// idle(800) + iowait(40)
	if idle != 840 {
		t.Errorf("idle = %d, want 840 (idle plus iowait)", idle)
	}
	if total != 1000 {
		t.Errorf("total = %d, want 1000", total)
	}
	// Only the aggregate line counts; per-core lines would double it.
	if total == 1500 {
		t.Error("per-core lines were summed in as well")
	}

	if _, _, ok := parseProcStat([]byte("intr 1\nctxt 2\n")); ok {
		t.Error("a file with no cpu line reported success")
	}
	if _, _, ok := parseProcStat(nil); ok {
		t.Error("empty input reported success")
	}
	// All-zero counters are "nothing has happened", not a valid 0%.
	if _, _, ok := parseProcStat([]byte("cpu  0 0 0 0 0\n")); ok {
		t.Error("all-zero counters reported success")
	}
}

func TestParseMeminfo(t *testing.T) {
	const sample = `MemTotal:       16384000 kB
MemFree:          512000 kB
MemAvailable:    2048000 kB
`
	if got := parseMeminfoMB([]byte(sample), "MemTotal:"); got != 16000 {
		t.Errorf("MemTotal = %d MB, want 16000", got)
	}
	if got := parseMeminfoMB([]byte(sample), "MemAvailable:"); got != 2000 {
		t.Errorf("MemAvailable = %d MB, want 2000", got)
	}
	// MemFree must not be mistaken for MemAvailable: on a box with a
	// large page cache they differ by gigabytes, and using the wrong
	// one would have every healthy host look starved.
	if parseMeminfoMB([]byte(sample), "MemFree:") ==
		parseMeminfoMB([]byte(sample), "MemAvailable:") {
		t.Error("MemFree and MemAvailable resolved to the same field")
	}
	if got := parseMeminfoMB([]byte(sample), "Nonsense:"); got != 0 {
		t.Errorf("an absent field gave %d, want 0", got)
	}
}

// And the two together: the fractions these produce have to land
// where `assess` expects them.
func TestParsedFiguresDriveTheRule(t *testing.T) {
	const starved = `MemTotal:       1000000 kB
MemAvailable:    100000 kB
`
	total := parseMeminfoMB([]byte(starved), "MemTotal:")
	avail := parseMeminfoMB([]byte(starved), "MemAvailable:")
	f := fraction(avail, total)
	if f >= reserveFraction {
		t.Fatalf("10%% free read as %v, which would not block", f)
	}
	blocked, reason := assess(f, 0.9)
	if !blocked {
		t.Errorf("a host with 10%% memory free was not held off (%q)", reason)
	}
}

// fractionU stays in uint64 on purpose. `int` is 32 bits on the
// targets this cross-compiles for, so narrowing a cgroup limit or a
// jiffy counter first would wrap — and a wrapped denominator sizes
// the whole fleet off one unusual reading.
func TestFractionU(t *testing.T) {
	if got := fractionU(20, 100); got != 0.2 {
		t.Errorf("fractionU(20,100) = %v, want 0.2", got)
	}
	if got := fractionU(1, 0); got != Unknown {
		t.Errorf("a zero denominator gave %v, want Unknown", got)
	}
	// A cgroup under reclaim can report usage above its own limit.
	if got := fractionU(140, 100); got != 1 {
		t.Errorf("fractionU(140,100) = %v, want 1", got)
	}
	// Past 2^31: the values that would wrap if this narrowed to int
	// on a 32-bit build. 8 GiB free of 32 GiB.
	const giB = uint64(1) << 30
	if got := fractionU(8*giB, 32*giB); got != 0.25 {
		t.Errorf("fractionU(8GiB, 32GiB) = %v, want 0.25", got)
	}
	// ...and that reading must not be mistaken for starvation.
	if blocked, why := assess(fractionU(8*giB, 32*giB), 0.9); blocked {
		t.Errorf("a host with 8 GiB of 32 GiB free was held off: %q", why)
	}
}
