//go:build linux

package capacity

import (
	"context"
	"os"
	"time"
)

// memFreeFraction is how much of this host's memory is still
// available, as a fraction of what it is allowed to use.
//
// The denominator is the CGROUP limit where there is one, not
// MemTotal. Every ghost in this fleet runs in a container, and a
// 2 GB container on a 64 GB host is at 100% of its own limit while
// /proc/meminfo reports it using 3% of the machine. Taking the host
// figure there would report plenty of room right up to the OOM kill,
// which is the failure this whole file exists to prevent.
func memFreeFraction() float64 {
	// The container's own limit first, for the reason above.
	if lim, ok := readCgroupBytes(cgroup2Max); ok {
		used, _ := readCgroupBytes(cgroup2Current)
		return fractionU(freeBytes(lim, used), lim)
	}
	if lim, ok := readCgroupBytes(cgroup1Limit); ok {
		used, _ := readCgroupBytes(cgroup1Usage)
		return fractionU(freeBytes(lim, used), lim)
	}
	// No cgroup limit: the machine's own figures.
	total, avail := procMemTotalMB(), procMemAvailableMB()
	return fraction(avail, total)
}

func procMemTotalMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMeminfoMB(b, "MemTotal:")
}

// : How long to watch /proc/stat for. CPU use is a rate, so it needs
// : two readings and a gap. Short enough not to delay a task start
// : noticeably, long enough that the jiffy counters move: at 100 Hz a
// : 150 ms window is 15 ticks, which is coarse but good enough to tell
// : "busy" from "idle". Anything under about 50 ms reads as noise.
const cpuSampleWindow = 150 * time.Millisecond

// cpuIdleFraction is the share of CPU time spent idle over a short
// window, across all cores.
//
// Sampled rather than read, because /proc/stat holds cumulative
// counters since boot. Reading it once and dividing gives the average
// since the machine started, which on a box that has been up six
// weeks is a number that cannot change no matter what is happening
// now — and would have reported a wedged host as 98% idle.
//
// Load average is deliberately not used instead. It counts runnable
// AND uninterruptible processes, so a host blocked on slow disk or a
// stalled network mount shows a frightening load while the CPU is
// doing nothing. For scanners, which are mostly blocked on sockets,
// that would refuse work on a host with capacity to spare.
func cpuIdleFraction(ctx context.Context) float64 {
	idle1, total1, ok := procStatJiffies()
	if !ok {
		return Unknown
	}
	select {
	case <-ctx.Done():
		return Unknown
	case <-time.After(cpuSampleWindow):
	}
	idle2, total2, ok := procStatJiffies()
	if !ok || total2 <= total1 {
		// No movement in the counters. Not an error and not "busy" --
		// a very short window on a very idle machine can genuinely
		// tick nothing, and reporting 0% idle for that would stop the
		// fleet.
		return Unknown
	}
	return fractionU(idle2-idle1, total2-total1)
}

// procStatJiffies returns (idle, total) from the aggregate `cpu` line.
//
// Idle counts both `idle` and `iowait`: a core waiting on disk is not
// doing work and is available to anything that is not also waiting.
// Counting iowait as busy would have a host doing one slow write look
// fully occupied.
func procStatJiffies() (idle, total uint64, ok bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	return parseProcStat(b)
}

// freeBytes is limit-minus-used, floored at zero. A cgroup can report
// usage above its own limit momentarily under reclaim, and an
// unsigned subtraction there would wrap to an enormous "free".
func freeBytes(limit, used uint64) uint64 {
	if limit <= used {
		return 0
	}
	return limit - used
}
