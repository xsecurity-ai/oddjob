// Package capacity works out how much this host can actually do at once.
//
// The agent is the only side that can answer this. Oddjob knows the
// engagement's appetite; it does not know whether the scanner is a
// 32-core server or a Raspberry Pi behind a domestic uplink, and
// guessing from the other end is how you get a box swapping itself to
// death because somebody typed 20 into a form.
//
// Three inputs, deliberately in this order:
//
//	cores   how many tasks can genuinely run at once. Most of what an
//	        agent runs is a child process that is either waiting on the
//	        network or burning one core, so cores is the ceiling that
//	        matters and everything else only lowers it.
//	memory  what is actually available, not what is installed. A box
//	        with 32 GB and 500 MB free cannot run eight nmaps, and the
//	        failure mode is the OOM killer taking the agent with it.
//	masscan what the host can emit, measured rather than assumed.
//
// # What the masscan probe does and does not tell you
//
// It measures what this HOST can put on the wire: the NIC, the kernel's
// socket path and the CPU behind them. It does NOT measure the path to
// the client, and nothing here could — finding the rate at which a
// client's network starts dropping packets means sending that traffic
// at the client's network, which is a scope decision and a disruptive
// one. The probe therefore runs against a discard address inside a
// range reserved for documentation, which routes nowhere.
//
// So: a high number means the host is not the bottleneck. It does not
// mean the path to the target will carry it, and the rate an operator
// sets for a real scan is still their decision.
package capacity

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Assessment is what this host can run at once, and the reasoning.
type Assessment struct {
	// Parallel is the number of simultaneous tasks. At least 1.
	Parallel int
	// MasscanRate is packets per second the host sustained in the
	// probe, 0 when it was not run or could not be measured.
	MasscanRate int
	// Reason is one line an operator can read. It names the input that
	// bound the result, because "4" on its own invites somebody to
	// raise the project ceiling and wonder why nothing changed.
	Reason string
	// Cores and MemMB as observed, for the same reason.
	Cores int
	MemMB int
}

// Headroom is how much memory one task is assumed to want. nmap against
// a large range and amass with a dozen sources both sit around a couple
// of hundred megabytes; 256 is a round number on the safe side of both.
const taskMemMB = 256

// Floor keeps a constrained host useful rather than idle: one task at a
// time is what every agent did before any of this existed.
const floor = 1

// Ceiling is not a resource limit. Beyond about this many concurrent
// scans the bottleneck is the network or the target, and the extra
// processes just compete; a number this high already needs an operator
// to have chosen it on the project.
const ceiling = 32

// Measure assesses the host. Never fails: an input that cannot be read
// is left out of the reasoning rather than taking the assessment down
// with it, because an agent that refuses to start because it could not
// read /proc is worse than one that runs two tasks.
func Measure(ctx context.Context, probeMasscan bool) Assessment {
	a := Assessment{Cores: runtime.NumCPU()}
	a.MemMB = availableMemMB()

	byCores := a.Cores
	limit, why := byCores, fmt.Sprintf("%d cores", a.Cores)

	if a.MemMB > 0 {
		byMem := a.MemMB / taskMemMB
		if byMem < limit {
			limit = byMem
			why = fmt.Sprintf("%d MB available (%d MB per task)",
				a.MemMB, taskMemMB)
		}
	}

	if probeMasscan {
		if rate, err := masscanRate(ctx); err == nil && rate > 0 {
			a.MasscanRate = rate
			why += fmt.Sprintf("; masscan sustained %s pps locally",
				thousands(rate))
		}
	}

	if limit < floor {
		limit = floor
	}
	if limit > ceiling {
		limit = ceiling
		why = fmt.Sprintf("capped at %d (beyond this the network is the "+
			"bottleneck, not the host)", ceiling)
	}
	a.Parallel = limit
	a.Reason = why
	return a
}

// masscanRate measures the packet rate this host can actually emit.
//
// Against 198.51.100.0/24 — TEST-NET-2, reserved for documentation and
// routed nowhere — so the probe measures the local send path and cannot
// reach anybody's network. The rate is read from masscan's own progress
// output, which reports what it achieved rather than what it was asked
// for; the difference between the two is the whole measurement.
func masscanRate(ctx context.Context) (int, error) {
	if _, err := exec.LookPath("masscan"); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	// --rate is the ASK. What comes back in the progress line is what
	// the host managed, and that is what is recorded.
	cmd := exec.CommandContext(ctx, "masscan",
		"198.51.100.0/24", "-p80", "--rate", "100000",
		"--wait", "0", "--open-only")
	out, _ := cmd.CombinedOutput()
	return parseMasscanRate(string(out)), nil
}

// parseMasscanRate pulls the achieved rate out of masscan's progress
// line, which looks like:
//
//	rate: 12.34-kpps, 45.67% done, ...
//
// Separated from the exec so it can be tested without sending anything.
func parseMasscanRate(out string) int {
	best := 0
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, "rate:")
		if i < 0 {
			continue
		}
		field := strings.TrimSpace(line[i+len("rate:"):])
		if j := strings.IndexByte(field, ','); j > 0 {
			field = field[:j]
		}
		field = strings.TrimSpace(field)
		// masscan writes the unit as "-kpps" in some builds and
		// "kpps" in others, and the plain form as "-pps". Order
		// matters: trimming "pps" first would leave "950.00-" from
		// "950.00-pps" and the parse would fail silently.
		mult := 1.0
		switch {
		case strings.HasSuffix(field, "mpps"):
			field, mult = strings.TrimSuffix(field, "mpps"), 1000000
		case strings.HasSuffix(field, "kpps"):
			field, mult = strings.TrimSuffix(field, "kpps"), 1000
		case strings.HasSuffix(field, "pps"):
			field = strings.TrimSuffix(field, "pps")
		}
		field = strings.TrimSuffix(strings.TrimSpace(field), "-")
		v, err := strconv.ParseFloat(strings.TrimSpace(field), 64)
		if err != nil {
			continue
		}
		if n := int(v * mult); n > best {
			best = n
		}
	}
	return best
}

func thousands(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
