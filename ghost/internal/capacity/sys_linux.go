//go:build linux

package capacity

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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

// cpuSampleWindow is how long to watch the counters for. CPU use is a
// rate, so it needs two readings and a gap. Short enough not to delay
// a task start noticeably, long enough that the jiffy counters move:
// at 100 Hz a 150 ms window is 15 ticks, which is coarse but good
// enough to tell "busy" from "idle". Anything under about 50 ms reads
// as noise.
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
	// The cgroup's own counters first, for the same reason memory
	// takes its denominator from the cgroup: the aggregate `cpu` line
	// of /proc/stat belongs to the HOST. Every ghost in this fleet
	// runs in a container, and a container with one core pinned busy
	// on a 32-core host still reads the host's counters — the other
	// thirty-one cores are idle, so the sample says "97% idle" while
	// the agent's own core is pegged. The fleet dashboard then shows
	// an idle ghost at 100% CPU load, which is what made these boxes
	// look wedged when they were not, and it makes the self-throttle
	// in `pace` fire on the wrong host entirely.
	if busy1, wall1, ok := cgroupCPUBusy(); ok {
		select {
		case <-ctx.Done():
			return Unknown
		case <-time.After(cpuSampleWindow):
		}
		busy2, wall2, ok := cgroupCPUBusy()
		if !ok || wall2 <= wall1 {
			// No movement in the counters. Not an error and not "busy"
			// -- a very short window on a very idle machine can
			// genuinely tick nothing, and reporting 0% idle for that
			// would stop the fleet.
			return Unknown
		}
		// `wall` counts every core-second the cgroup could have used;
		// `busy` is what it actually spent. The difference is idle,
		// iowait and steal in one figure, which is exactly how a
		// scanner that spends its time waiting on sockets should read:
		// available.
		return fractionU(wall2-wall1-(busy2-busy1), wall2-wall1)
	}
	// No cgroup counters readable: the machine's own figures, which is
	// the right answer when there is no container to be wrong about.
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

// cgroupCPUBusy returns (busy, wall) in microseconds from this
// process's own cgroup, or ok=false when neither cgroup version can
// be read.
//
// `wall` is what the clock says has passed since the agent started,
// multiplied by how many cores the container may use; `busy` is what
// the cgroup's tasks actually spent in user or system mode over the
// same span. The difference between two samples of each is the idle
// share, with no need for the kernel to name idle at all — which is
// the whole reason this works on both cgroup versions: neither
// exposes an idle counter, but both expose a busy one.
//
// Measuring wall from process start rather than from a fixed epoch is
// what keeps the two sides of the subtraction honest. The busy
// counters are cumulative since the container was created, which can
// be before this process; dividing by a wall span that includes the
// gap would read an idle agent as busy for however long the box ran
// before it started. From start to now, both counters cover exactly
// the same interval, and an idle agent's busy counter barely moves
// while the wall side advances the full window — which is the 100%
// idle reading these boxes were missing.
//
// The core count comes from cpu.max when it sets a quota, because that
// is what bounds the container; otherwise from the CPUSET when it
// names a set; otherwise from the machine. A 2-core limit on a 32-core
// host with cpu.max set to "200000 100000" is the common shape of
// these boxes, and reading 32 there would dilute every busy sample by
// sixteen.
func cgroupCPUBusy() (busy, wall uint64, ok bool) {
	b := cgroupCPUUsageUsec()
	if b < 0 {
		return 0, 0, false
	}
	// Both operands are non-negative: the wall clock since process
	// start and a core count of at least one, so the product cannot
	// overflow for any lifetime this agent will live.
	w := time.Since(cgroupWallStart).Microseconds()
	if w < 0 {
		w = 0
	}
	wall = uint64(w) * uint64(coresForWall()) // #nosec G115 — both operands non-negative, see above
	// b is checked >= 0 above; the conversion cannot overflow.
	bu := uint64(b) // #nosec G115
	return bu, wall, true
}

// cgroupWallStart is when this process began, read once. The busy
// counters are cumulative since the container was created, so the wall
// side must measure from the same origin or the second sample's
// difference would include boot time.
var cgroupWallStart = time.Now()

// coresForWall is how many core-seconds one second of wall time is
// worth for this cgroup: the cpu.max quota when it sets one, else the
// CPUSET size when it names a set, else the machine's core count.
func coresForWall() int {
	if n := cpuMaxQuotaCores(); n > 0 {
		return n
	}
	if n := cpuSetCores(); n > 0 {
		return n
	}
	n := runtimeNumCPU()
	if n < 1 {
		return 1
	}
	return n
}

// cpuMaxQuotaCores is how many whole cores the cpu.max quota buys, or
// 0 when it does not set one. "200000 100000" is two cores; a period
// that does not divide the quota is rounded down, which is the
// conservative reading for a busy fraction.
func cpuMaxQuotaCores() int {
	b, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 || f[0] == "max" {
		return 0
	}
	quota, err1 := strconv.Atoi(f[0])
	period, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || period <= 0 {
		return 0
	}
	n := quota / period
	if n < 1 && quota > 0 {
		// A sub-core quota still counts as a core for the wall side:
		// rounding it to zero would make every sample read as fully
		// busy. The fraction is wrong by less than one core either
		// way, which is coarser than the reading is useful.
		n = 1
	}
	return n
}

// cgroupCPUUsageUsec is this cgroup's cumulative user+system time in
// microseconds, or -1 when it cannot be read.
func cgroupCPUUsageUsec() int64 {
	// cgroup v2: cpu.stat under the cgroup's own directory, reached
	// through the path named in /proc/self/cgroup.
	if p := selfCgroupPath("v2"); p != "" {
		b, err := os.ReadFile("/sys/fs/cgroup" + p + "/cpu.stat") // #nosec G304 — p comes from /proc/self/cgroup, not from a request
		if err == nil {
			if u := parseCPUStatUsec(b); u > 0 {
				return u
			}
		}
	}
	// cgroup v1: cpuacct.stat under the cpu controller's hierarchy.
	if p := selfCgroupPath("v1"); p != "" {
		b, err := os.ReadFile("/sys/fs/cgroup/cpu" + p + "/cpuacct.stat") // #nosec G304 — p comes from /proc/self/cgroup, not from a request
		if err == nil {
			if u := parseCPUAcctStatUsec(b); u > 0 {
				return u
			}
		}
	}
	return -1
}

// selfCgroupPath is this process's path in the named cgroup hierarchy,
// or "" when it cannot be determined. v2 lines are "0::<path>"; v1
// lines are "<id>:<controllers>:<path>" and the cpu controller must
// be among them.
func selfCgroupPath(kind string) string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		switch kind {
		case "v2":
			if len(f) < 3 || f[1] != "" {
				continue
			}
			if f[2] == "/" {
				return ""
			}
			return f[2]
		default:
			if len(f) < 3 || !strings.Contains(f[1], "cpu") {
				continue
			}
			return f[2]
		}
	}
	return ""
}

// parseCPUStatUsec sums the v2 cpu.stat user and system counters, in
// microseconds. The kernel names them user_usec and system_usec; both
// are cumulative since the cgroup was created.
func parseCPUStatUsec(b []byte) int64 {
	var sum int64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "user_usec", "system_usec":
			sum += n
		}
	}
	return sum
}

// parseCPUAcctStatUsec sums the v1 cpuacct.stat user and system
// counters, in microseconds. The kernel names them `user` and
// `system` and counts NANOseconds, so the sum is divided down ONCE
// rather than each field: dividing per line loses up to 999 ns of
// remainder per counter, which at these magnitudes is a visible error.
func parseCPUAcctStatUsec(b []byte) int64 {
	var sumNS int64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "user", "system":
			sumNS += n
		}
	}
	return sumNS / 1000
}

// cpuSetCores is how many cores this cgroup's CPUSET names, or 0 when
// it does not. The file lists the set as ranges ("0-3,8") and can say
// "all" on some kernels; both shapes are handled rather than guessed.
func cpuSetCores() int {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		var p string
		switch {
		case f[1] == "": // v2
			p = "/sys/fs/cgroup" + f[2] + "/cpuset.cpus.effective"
		case strings.Contains(f[1], "cpuset"):
			p = "/sys/fs/cgroup/cpuset" + f[2] + "/cpuset.cpus"
		default:
			continue
		}
		b, err := os.ReadFile(p) // #nosec G703,G304 — p is built from /proc/self/cgroup fields, not from a request
		if err != nil {
			continue
		}
		return countCPURanges(string(b))
	}
	return 0
}

// countCPURanges counts the cores named by a cpuset file: "0-3,8" is
// five, "all" falls through to the machine figure at the call site.
func countCPURanges(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return 0
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := splitRange(part); ok {
			n += hi - lo + 1
		} else if _, err := strconv.Atoi(part); err == nil {
			n += 1
		}
	}
	return n
}

func splitRange(s string) (lo, hi int, ok bool) {
	i := strings.IndexByte(s, '-')
	if i < 0 {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(s[:i])
	b, err2 := strconv.Atoi(s[i+1:])
	if err1 != nil || err2 != nil || b < a {
		return 0, 0, false
	}
	return a, b, true
}

// runtimeNumCPU is the machine's core count, isolated so the tests can
// see what `coresForWall` would do without touching the real machine.
func runtimeNumCPU() int {
	n := runtime.NumCPU()
	if n < 1 {
		return 1
	}
	return n
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

// diskFreeFraction is the share of the filesystem holding the workdir
// that is still available.
//
// Read from /proc/mounts to find the device backing the workdir, then
// statfs'd for free/total. The workdir is what fills up: spool files,
// scanner output staged before upload, and the occasional multi-GB
// amass graph. A full disk kills every task with "no space left on
// device" and the operator needs to see it coming.
func diskFreeFraction(workDir string) float64 {
	// statfs the workdir directly; the kernel resolves the mount point.
	var st syscall.Statfs_t
	if err := syscall.Statfs(workDir, &st); err != nil {
		return Unknown
	}
	if st.Bsize <= 0 {
		return Unknown
	}
	bsize := uint64(st.Bsize) // #nosec G115 — Bsize is a block size from statfs; the kernel never reports a negative one, and the guard above makes the conversion safe.
	total := st.Blocks * bsize
	free := st.Bavail * bsize // available to unprivileged users
	if total == 0 {
		return Unknown
	}
	return fractionU(free, total)
}
