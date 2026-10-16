package capacity

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

// Pacing is how hard ONE scanner process may push this host.
//
// Separate from `size()` and from `Check()`, because it answers a
// third question. `size()` says how many tasks to run at once;
// `Check()` vetoes starting another one; this says how hard each of
// them may go once started. A host can have a free slot, pass the
// veto, and still be flattened by one process that opens
// twenty-five workers on a quarter of a core.
//
// That is not hypothetical. nuclei defaults to `-c 25` (twenty-five
// templates in parallel) and `-rl 150` (a hundred and fifty requests
// a second), PER PROCESS. On a shared-core GCP e2-micro -- roughly a
// quarter of a vCPU sustained -- three of those at once produced a
// load average of 26.66, the host stopped completing the SSH banner
// exchange, and the agent dropped out of the fleet. It was not out
// of memory: 693 MB of 953 MB used, zero OOM kills since boot and
// 1.9 GB of swap untouched. The agent had plenty of slots. It was
// starved of CPU by flags nothing had sized to the box.
//
// The numbers also face the client. A hundred and fifty requests a
// second per process, times however many agents, is a great deal of
// traffic at somebody's production estate, and nothing downstream of
// the agent paces it.
type Pacing struct {
	// Concurrency is nuclei's `-c`: templates in parallel.
	Concurrency int
	// RateLimit is nuclei's `-rl`: requests per second.
	RateLimit int
	// Reason names the input that bound the result, in the same
	// spirit as Assessment.Reason -- a bare "3" invites somebody to
	// raise a limit elsewhere and wonder why nothing changed.
	Reason string
}

// Workers one core can carry. Scanner workers are overwhelmingly
// blocked on a socket rather than computing, so a core runs several
// without any of them slowing down -- the same reasoning as
// tasksPerCore, and deliberately the same order of magnitude.
const workersPerCore = 8

// Memory one worker is assumed to want. nuclei measured at 147 MB
// resident with the default twenty-five workers, so about 6 MB each;
// 16 is comfortably above that without sizing the host for a worst
// case that has not been observed.
const workerMemMB = 16

// Never above nuclei's own default. This function exists to slow a
// scanner down on a small host, not to speed it up on a large one --
// going faster than the tool ships with is a decision about someone
// else's network and belongs to an operator, not to a heuristic.
const maxWorkers = 25

// Requests per second per worker. Four is a working assumption
// rather than a measurement: it keeps the rate proportional to the
// concurrency, so one knob moves both and they cannot drift into
// "five workers allowed to send a hundred and fifty a second".
const requestsPerWorker = 4

// Floors. A host that cannot be measured, or that is pinned, still
// runs the scan -- slowly. Refusing to scan at all because the box
// is busy would turn a slow result into no result, and the task has
// already been queued against a client.
const (
	minWorkers = 1
	minRate    = 5
	maxRate    = 150
)

// pace is the whole decision, taking its inputs rather than reading
// them so every case can be tested on a machine that is not the one
// it describes.
//
// `parallel` is how many tasks this agent may run at once. It
// divides the budget because the host's capacity is shared: three
// nuclei each sized as though they had the box to themselves is
// exactly how the e2-micro went down.
//
// `cpuIdle` is the self-throttle, and the input the others cannot
// stand in for. Cores and memory describe what the box IS; CPU idle
// describes what it is doing RIGHT NOW, which on a burstable or
// shared-core instance is a completely different number. An
// e2-micro reports two cores and spends its life at a fraction of
// one. Unknown leaves the estimate alone rather than assuming the
// worst, matching how `assess` treats an unreadable figure.
func pace(cores, memMB, parallel int, cpuIdle float64) Pacing {
	if cores < 1 {
		cores = 1
	}
	if parallel < 1 {
		parallel = 1
	}

	// The reason is a CHAIN, not a single name.
	//
	// It used to report whichever step last touched the number, and
	// the CPU scaling is last and fires whenever idle is below 100%
	// -- so a host bound by having its budget split six ways was
	// reported as "bound by 83% CPU idle", which reads as "the box
	// is busy" when the box was fine. A number nobody can account
	// for is how somebody raises the wrong limit and wonders why
	// nothing changed, which is the whole reason this field exists.
	bound := cores * workersPerCore
	steps := []string{fmt.Sprintf("%d core(s) → %d", cores, bound)}

	if memMB > 0 {
		if byMem := (memMB - reserveMemMB) / workerMemMB; byMem < bound {
			bound = byMem
			steps = append(steps,
				fmt.Sprintf("%d MB available → %d", memMB, bound))
		}
	}

	// Shared between the tasks that may run at once.
	if parallel > 1 {
		bound /= parallel
		steps = append(steps, fmt.Sprintf("split %d ways → %d", parallel, bound))
	}

	// What the host is actually doing. Scaled rather than vetoed: a
	// busy host should scan gently, not refuse.
	if cpuIdle != Unknown {
		if scaled := int(float64(bound) * cpuIdle); scaled < bound {
			bound = scaled
			steps = append(steps,
				fmt.Sprintf("%.0f%% CPU idle → %d", cpuIdle*100, bound))
		}
	}

	if bound > maxWorkers {
		bound = maxWorkers
		steps = append(steps, fmt.Sprintf("nuclei's own default → %d", bound))
	}
	if bound < minWorkers {
		bound = minWorkers
		steps = append(steps, fmt.Sprintf("floor → %d", bound))
	}

	rate := bound * requestsPerWorker
	if rate < minRate {
		rate = minRate
	}
	if rate > maxRate {
		rate = maxRate
	}
	return Pacing{Concurrency: bound, RateLimit: rate,
		Reason: fmt.Sprintf("%d worker(s) at %d req/s — %s",
			bound, rate, strings.Join(steps, ", "))}
}

// Pace reads this host and sizes one scanner run against it.
//
// Never fails, for the same reason Measure does not: an input that
// cannot be read is left out of the reasoning rather than taking the
// scan down with it.
func Pace(ctx context.Context, parallel int) Pacing {
	return pace(runtime.NumCPU(), availableMemMB(), parallel, cpuIdleFraction(ctx))
}
