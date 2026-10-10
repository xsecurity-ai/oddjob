package capacity

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Pressure is the live "is there room right now" question, which is a
// different question from `size()`.
//
// `size()` decides how many tasks this host should run at once, from
// cores and memory, and is re-derived on a timer. It deliberately has
// a floor of one: a host that cannot read its own memory still has to
// be useful. That floor is correct for sizing and wrong for starting,
// because a box with 40 MB free and one slot left will still take the
// task, and the slot was not the thing that ran out.
//
// So this is a veto, not a number. It asks what is free at this
// moment and refuses to start anything new when the host is within
// `reserveFraction` of either limit. Three hosts in this fleet have
// been driven to the point of not completing an SSH banner exchange
// while their agent was still reporting slots free and taking work.
//
// # Why the agent gets the final say
//
// Oddjob can set a per-ghost parallelism and that number normally
// wins. This is not subject to it, for the same reason the memory
// clamp is not: an operator's figure is a statement about appetite,
// and this is the host saying it is about to fall over. The heartbeat
// carries it as `ready: false`, which the server honours whether or
// not an override is set — the `slots_free` path is skipped when
// there is an override, and `ready` is not.
const reserveFraction = 0.20

// Unknown is what an unmeasurable figure reports. Negative rather
// than zero, because zero free is the most alarming reading there is
// and must never be produced by not looking.
const Unknown = -1.0

// Pressure is what the host has left, and whether that is enough.
type Pressure struct {
	// Blocked is the answer: do not start another task.
	Blocked bool
	// Reason names what ran out, for the fleet table and the log.
	Reason string
	// MemFree and CPUIdle are fractions in [0,1], or Unknown.
	MemFree float64
	CPUIdle float64
}

// assess is the whole decision, taking the two fractions rather than
// reading them, so every case can be tested on a machine that is not
// the one it describes.
//
// Unknown never blocks. An agent on a platform whose figures cannot be
// read must keep working: refusing all work because the measurement is
// missing turns a monitoring gap into an outage, and the sizing path
// already treats unreadable memory as "unknown" rather than as "none".
func assess(memFree, cpuIdle float64) (bool, string) {
	switch {
	case memFree != Unknown && memFree < reserveFraction:
		return true, fmt.Sprintf(
			"holding off: %.0f%% memory free, under the %.0f%% this host keeps spare",
			memFree*100, reserveFraction*100)
	case cpuIdle != Unknown && cpuIdle < reserveFraction:
		return true, fmt.Sprintf(
			"holding off: %.0f%% CPU idle, under the %.0f%% this host keeps spare",
			cpuIdle*100, reserveFraction*100)
	}
	return false, ""
}

// Check reads the host and applies the rule.
//
// Memory first and CPU second, because they fail differently. Running
// out of memory gets the agent killed mid-scan by something that does
// not explain itself; running out of CPU makes everything slow, which
// is unpleasant but recoverable. Both block, and the reason says
// which, so an operator looking at a stalled agent is not left
// guessing.
func Check(ctx context.Context) Pressure {
	p := Pressure{MemFree: memFreeFraction(), CPUIdle: cpuIdleFraction(ctx)}
	p.Blocked, p.Reason = assess(p.MemFree, p.CPUIdle)
	return p
}

// fractionU is a/b for counters that are already uint64.
//
// Kept in uint64 rather than narrowing to int first: `int` is 32 bits
// on the targets this cross-compiles for, and a cgroup limit or a
// jiffy counter past 2^31 would wrap to something negative or
// enormous — sizing the whole fleet off one unusual reading. The same
// hazard `headroomMB` guards against, in the same package.
func fractionU(free, total uint64) float64 {
	if total == 0 {
		return Unknown
	}
	f := float64(free) / float64(total)
	if f > 1 {
		return 1
	}
	return f
}

// fraction is a/b guarded, returning Unknown rather than NaN or a
// division by zero when the denominator was not readable.
func fraction(free, total int) float64 {
	if total <= 0 || free < 0 {
		return Unknown
	}
	f := float64(free) / float64(total)
	if f > 1 {
		return 1
	}
	return f
}

// parseProcStat reads the aggregate `cpu` line of /proc/stat.
//
// Separated from the file read so it can be tested on any platform.
// The field order is fixed by the kernel -- user, nice, system, idle,
// iowait, irq, softirq, steal, guest, guest_nice -- and getting the
// index wrong is silent: counting `system` as idle would report a
// busy host as free, which is the exact failure this package exists
// to prevent.
//
// iowait counts as idle. A core waiting on disk is not doing work and
// is available to anything that is not also waiting; treating it as
// busy would have a host doing one slow write look fully occupied.
func parseProcStat(b []byte) (idle, total uint64, ok bool) {
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		for i, v := range strings.Fields(line)[1:] {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
		return idle, total, total > 0
	}
	return 0, 0, false
}

// parseMeminfoMB pulls one /proc/meminfo field, in megabytes.
func parseMeminfoMB(b []byte, prefix string) int {
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0
		}
		kb, err := strconv.Atoi(f[1])
		if err != nil {
			return 0
		}
		return kb / 1024
	}
	return 0
}
