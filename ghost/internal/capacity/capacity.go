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
//	cores   how much CPU there is, times how many tasks one core can
//	        carry. NOT a one-task-per-core ceiling: that was the model
//	        here and it was wrong. Almost everything an agent runs --
//	        nmap, amass, httpx, masscan -- spends its life in a syscall
//	        waiting for a packet, so a core carries several of them
//	        comfortably and a two-core box ran two tasks while sitting
//	        near-idle. See tasksPerCore.
//	memory  what is actually available, not what is installed. A box
//	        with 32 GB and 500 MB free cannot run eight nmaps, and the
//	        failure mode is the OOM killer taking the agent with it.
//	        This is the input that genuinely binds a small host, and it
//	        still does.
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

// Headroom is how much memory one task is assumed to want.
//
// 256 was chosen as "the safe side of amass with a dozen sources", and
// that was not a guess: an amass measured on one of our own ghosts was
// resident at 438 MB. It is the heaviest thing here by a wide margin.
//
// The cost of sizing EVERY task for the worst one is that a box with
// 300 MB free runs a single nmap, which wants a few tens of megabytes
// — which is how three ghosts on idle hosts came to report a capacity
// of one. 128 is still above what the common tools use.
//
// What stops that under-estimate hurting is not this constant but the
// retune: capacity is re-read from MemAvailable every 60 seconds, so a
// ghost that starts an amass watches its own headroom fall and stops
// taking new work. The loop is the real protection; this number only
// decides how fast it gets there.
//
// That was written as though it were unconditional, and for a long
// while it was not: setting a parallelism from Oddjob used to switch
// the loop off entirely, and two hosts were driven into the ground by
// a server number the agent had already measured as too high. The
// agent now clamps one against the other on every cycle, so the
// sentence above is true again — see clampCapacity in internal/agent.
//
// A per-tool weight would be better than one figure for all of them,
// and wants the scheduler to know what a slot is holding. Not done
// here.
const taskMemMB = 128

// How much memory to leave for the agent itself and the operating
// system. Subtracted before dividing, because "available" going to zero
// is the condition this is avoiding, not a budget to spend to the last
// megabyte.
const reserveMemMB = 64

// Tasks one core can carry. The work is network-bound: a scanner is
// overwhelmingly blocked on a socket, not computing, so a core runs
// several without any of them slowing down. Four is deliberately modest
// -- the point is to stop cores being a hard ceiling, not to pretend
// the CPU is infinite.
const tasksPerCore = 4

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
//
// `override` is the operator's own number and wins outright when it is
// above zero -- including over the memory estimate. That is the point
// of it: somebody who knows the box, or who is willing to find out,
// should not have to argue with a heuristic. It is still held to the
// ceiling, and the reason says plainly that a person chose it, so a
// ghost running one task on a 64-core machine is traceable to a
// decision rather than looking like a bug in this file.
func Measure(ctx context.Context, probeMasscan bool, override int) Assessment {
	a := Assessment{Cores: runtime.NumCPU()}
	a.MemMB = availableMemMB()
	a.Parallel, a.Reason = size(a.Cores, a.MemMB, override)

	if probeMasscan {
		if rate, err := masscanRate(ctx); err == nil && rate > 0 {
			a.MasscanRate = rate
			a.Reason += fmt.Sprintf("; masscan sustained %s pps locally",
				thousands(rate))
		}
	}
	return a
}

// size is the whole decision, with the host's numbers passed in rather
// than read, so the arithmetic can be tested on a machine that is not
// the one the case describes. `memMB` of 0 means "could not read it",
// which is not the same as "no memory" and must not size to zero.
func size(cores, memMB, override int) (int, string) {
	if cores < 1 {
		cores = 1
	}

	// Cores set the headline because the work is network-bound and a
	// core carries several blocked processes. Memory then lowers it,
	// and on a small host it is memory that decides -- which is
	// correct: the OOM killer does not care how idle the CPU is.
	limit := cores * tasksPerCore
	why := fmt.Sprintf("%d cores x %d (tasks wait on the network, "+
		"not the CPU)", cores, tasksPerCore)

	if memMB > 0 {
		if byMem := (memMB - reserveMemMB) / taskMemMB; byMem < limit {
			limit = byMem
			why = fmt.Sprintf("%d MB available, less %d MB reserved, "+
				"at %d MB per task", memMB, reserveMemMB, taskMemMB)
		}
	}

	if override > 0 {
		limit = override
		why = fmt.Sprintf("set to %d by the operator", override)
		// Said, not enforced. The operator asked for this; the job
		// here is to make sure the number they see in the fleet table
		// carries what the host makes of it.
		if memMB > 0 {
			if fits := (memMB - reserveMemMB) / taskMemMB; override > fits {
				if fits < floor {
					fits = floor
				}
				why += fmt.Sprintf(" (the %d MB available suggests %d)",
					memMB, fits)
			}
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
	return limit, why
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
