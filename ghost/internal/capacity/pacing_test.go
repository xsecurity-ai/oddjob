package capacity

import (
	"fmt"
	"strings"
	"testing"
)

// The case this exists for, measured on a real host.
//
// A GCP e2-micro reports two cores and 953 MB and is a SHARED core:
// about a quarter of a vCPU sustained. nuclei's defaults put
// twenty-five workers in each of three processes on it, the load
// average reached 26.66, and the box stopped completing the SSH
// banner exchange. Nothing was out of memory. Cores and memory alone
// cannot see this -- only what the CPU is doing right now can.
func TestPacingBacksOffWhenTheCPUIsAlreadyGone(t *testing.T) {
	idle := pace(2, 953, 1, 0.95)
	busy := pace(2, 953, 1, 0.02)

	if busy.Concurrency >= idle.Concurrency {
		t.Errorf("a pinned host was paced no gentler than an idle one: "+
			"%d vs %d", busy.Concurrency, idle.Concurrency)
	}
	if busy.Concurrency < minWorkers {
		t.Errorf("paced below the floor: %d", busy.Concurrency)
	}
	// It must still scan. Refusing outright turns a slow result into
	// no result, and the task was already queued against a client.
	if busy.Concurrency < 1 || busy.RateLimit < 1 {
		t.Errorf("a busy host was paced to a standstill: %+v", busy)
	}
	if !strings.Contains(busy.Reason, "CPU idle") {
		t.Errorf("the reason does not name what bound it: %q", busy.Reason)
	}
}

// Three nuclei each sized as though they owned the box is exactly
// how the e2-micro went down. The budget is shared.
func TestPacingSplitsTheHostBetweenConcurrentTasks(t *testing.T) {
	one := pace(8, 8000, 1, Unknown)
	four := pace(8, 8000, 4, Unknown)
	if four.Concurrency >= one.Concurrency {
		t.Errorf("four concurrent tasks were each given as much as one: "+
			"%d vs %d", four.Concurrency, one.Concurrency)
	}
	if !strings.Contains(four.Reason, "split 4 ways") {
		t.Errorf("the reason does not mention the split: %q", four.Reason)
	}
}

// Never faster than the tool ships with. This exists to slow a
// scanner down on a small host, not to speed it up on a large one --
// going faster than nuclei's own default is a decision about someone
// else's network and belongs to a person.
func TestPacingNeverExceedsNucleiDefault(t *testing.T) {
	huge := pace(128, 512000, 1, 1.0)
	if huge.Concurrency > maxWorkers {
		t.Errorf("a big host was paced above nuclei's default: %d > %d",
			huge.Concurrency, maxWorkers)
	}
	if huge.RateLimit > maxRate {
		t.Errorf("rate above nuclei's default: %d > %d", huge.RateLimit, maxRate)
	}
}

// An unreadable figure must not be read as "the worst case". The
// veto in assess() treats Unknown as "do not block"; this treats it
// as "do not scale", for the same reason -- a measurement gap should
// not become an outage, or a scan so slow it never finishes.
func TestPacingIgnoresAnUnknownCPUReading(t *testing.T) {
	known := pace(4, 4000, 1, 1.0)
	unknown := pace(4, 4000, 1, Unknown)
	if unknown.Concurrency != known.Concurrency {
		t.Errorf("Unknown CPU changed the answer: %d vs %d",
			unknown.Concurrency, known.Concurrency)
	}
}

// Memory still binds. It is the input that genuinely kills a small
// host, and the CPU scaling must not paper over it.
func TestPacingIsBoundByMemoryOnATinyHost(t *testing.T) {
	p := pace(32, 200, 1, 1.0)
	if p.Concurrency > (200-reserveMemMB)/workerMemMB {
		t.Errorf("32 cores outvoted 200 MB of memory: %+v", p)
	}
	if !strings.Contains(p.Reason, "MB available") {
		t.Errorf("the reason does not name memory: %q", p.Reason)
	}
}

// Degenerate inputs must not produce a zero or negative argument:
// `-c 0` is not a gentler scan, it is a broken command line.
func TestPacingNeverProducesAnUnusableNumber(t *testing.T) {
	for _, p := range []Pacing{
		pace(0, 0, 0, Unknown),
		pace(-1, -1, -1, 0),
		pace(1, 1, 100, 0.0),
	} {
		if p.Concurrency < 1 || p.RateLimit < 1 {
			t.Errorf("unusable pacing from a degenerate host: %+v", p)
		}
	}
}

// The reason must account for the number, not name whichever step
// touched it last.
//
// The CPU scaling runs last and fires whenever idle is below 100%,
// so it used to overwrite the reason unconditionally: a host whose
// budget had been split six ways was reported as "bound by 83% CPU
// idle", which reads as "the box is busy" when the box was fine.
// Observed on a real agent -- 2 cores and 951MB reporting -c 1 and
// blaming the CPU.
func TestPacingReasonAccountsForEveryStep(t *testing.T) {
	p := pace(2, 951, 6, 0.83)

	// The step that actually did the work has to be visible.
	if !strings.Contains(p.Reason, "split 6 ways") {
		t.Errorf("the reason hides the split, which is what bound it: %q",
			p.Reason)
	}
	// And the arithmetic has to be followable to the answer, so
	// nobody raises a limit that was never the constraint.
	if !strings.Contains(p.Reason, "2 core(s)") {
		t.Errorf("the reason does not say where it started: %q", p.Reason)
	}
	// The chain has to arrive at the number actually used. This was
	// `HasSuffix(reason, lastSegmentOf(reason))` first time, which is
	// true by construction and could never fail -- a check that
	// tests the string against itself.
	if !strings.HasSuffix(p.Reason, fmt.Sprintf("→ %d", p.Concurrency)) {
		t.Errorf("the chain ends somewhere other than -c %d: %q",
			p.Concurrency, p.Reason)
	}
	t.Logf("azure, as measured: -c %d -rl %d (%s)",
		p.Concurrency, p.RateLimit, p.Reason)
}
