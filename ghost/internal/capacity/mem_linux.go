//go:build linux

package capacity

import (
	"os"
	"strconv"
	"strings"
)

// availableMemMB is what this process can actually allocate.
//
// Two sources, and the smaller wins, because either one alone is wrong
// in a way that matters here:
//
//	/proc/meminfo   MemAvailable, the kernel's own estimate of what can
//	                be allocated without swapping — not MemFree, which
//	                excludes reclaimable page cache and reads as almost
//	                nothing on any box up for a week.
//	cgroup          the container's own limit, when there is one.
//
// A Ghost in a container with `mem_limit: 512m` on a 64 GB host reads
// 60-odd GB from /proc/meminfo: that file is the HOST's, and the cgroup
// is the thing that will actually kill it. Sizing from the host figure
// there is not conservative-but-wrong, it is the direction that ends in
// the OOM killer taking the agent out mid-scan. Most of this fleet runs
// in Docker, so this is the common case rather than an exotic one.
//
// Returns 0 for "could not tell", which the caller treats as unknown
// rather than as none.
func availableMemMB() int {
	n := procMemAvailableMB()
	if c := cgroupAvailableMB(); c > 0 && (n == 0 || c < n) {
		n = c
	}
	return n
}

func procMemAvailableMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
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

// cgroupAvailableMB is the container's limit less what it is already
// using, or 0 when there is no limit to speak of.
//
// Both cgroup versions, v2 first because that is what current Docker
// and systemd use. An unlimited cgroup says "max" on v2 and a number
// near 2^63 on v1; neither is a limit, and treating either as one would
// have every unconstrained host report an absurd amount of headroom
// and then be ignored anyway for being larger than MemAvailable.
func cgroupAvailableMB() int {
	// v2
	if lim, ok := readCgroupBytes(cgroup2Max); ok {
		used, _ := readCgroupBytes(cgroup2Current)
		return headroomMB(lim, used)
	}
	// v1
	if lim, ok := readCgroupBytes(cgroup1Limit); ok {
		used, _ := readCgroupBytes(cgroup1Usage)
		return headroomMB(lim, used)
	}
	return 0
}

// The files, named once. Passing them as arguments is what lets the
// test drive `readCgroupBytes` against a temp directory.
const (
	cgroup2Max     = "/sys/fs/cgroup/memory.max"
	cgroup2Current = "/sys/fs/cgroup/memory.current"
	cgroup1Limit   = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	cgroup1Usage   = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
)

// headroomMB is limit-minus-used in megabytes, clamped into an int.
//
// The clamp is not decoration. `int` is 32 bits on the 32-bit targets
// this cross-compiles for, and an unchecked uint64 conversion there
// wraps — a wrap to a negative or enormous figure would size the whole
// fleet off one unusual cgroup value. `readCgroupBytes` already refuses
// anything past a petabyte, so this cannot trigger in practice; it is
// here so that it cannot trigger in theory either.
func headroomMB(limit, used uint64) int {
	if limit <= used {
		return 0
	}
	mb := (limit - used) / (1 << 20)
	const maxMB = 1 << 30 // an exabyte; far past any real machine
	if mb > maxMB {
		mb = maxMB
	}
	return int(mb)
}

// readCgroupBytes reads one cgroup number. The bool is false for an
// absent file, an unparseable one, or a value that means "no limit" —
// all three of which have to be distinguishable from a real limit of
// zero, which is why this does not just return an int.
func readCgroupBytes(path string) (uint64, bool) {
	// #nosec G304 -- the callers pass the four cgroup paths named
	// above as constants. It takes a parameter so the test can point
	// it at a temp directory; nothing reaches it from a request.
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	// v1 spells "unlimited" as a huge number rather than a word. The
	// exact value varies with page size, so this tests the shape:
	// anything past a petabyte is not a memory limit somebody set.
	if v >= 1<<50 {
		return 0, false
	}
	return v, true
}
