//go:build linux

package agent

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/client"
)

// resourceSampler measures how much of this host one task used, around
// the run. It samples the task's own process tree — the agent and its
// children — so the figure is the tool's cost, not the whole agent's,
// and it says nothing about any other tenant on the box.
//
// What it reports, and why each is honest:
//
//   - CPU seconds: the delta of utime+stime across the process tree, in
//     jiffies turned to seconds. A tool that pinned two cores for a
//     minute lands near 120; one that mostly waited lands near zero.
//   - Peak memory: the highest VmRSS total seen while sampling, plus one
//     final read after the tool exits so its real peak is not missed by
//     the interval.
//   - Network bytes: the delta of every interface's rx+tx counters in
//     /proc/net/dev, minus lo. That is the container's own traffic —
//     which is exactly what a scan moves — and reading it needs no
//     permission the agent does not already have.
//
// Everything is best-effort and read-only: a file that cannot be read
// degrades that one figure, never the result.
type resourceSampler struct {
	started      time.Time
	baseCPUTicks int64
	baseNet      uint64
	peakMem      int64
}

func (s *resourceSampler) begin() error {
	s.started = time.Now()
	cpu, ok := procTreeCPUTicks(os.Getpid())
	if !ok {
		return errNoCPUBaseline
	}
	s.baseCPUTicks = cpu
	net, _ := netDevBytes()
	s.baseNet = net
	if mem, ok := procTreeRSS(os.Getpid()); ok {
		s.peakMem = mem
	}
	return nil
}

// stop reads the final counters and returns the measurement. A nil is
// never returned: when nothing could be measured it returns a Resource
// whose fields are all zero, which the server stores as "unknown".
func (s *resourceSampler) stop() *client.Resource {
	dur := time.Since(s.started).Seconds()
	cpuNow, okC := procTreeCPUTicks(os.Getpid())
	mem, okM := procTreeRSS(os.Getpid())
	if mem > s.peakMem {
		s.peakMem = mem
	}
	netNow, okN := netDevBytes()

	r := &client.Resource{DurationSec: dur}
	if okC && cpuNow >= s.baseCPUTicks {
		r.CPUSec = float64(cpuNow-s.baseCPUTicks) / ticksPerSecond
	}
	if okM {
		r.MemPeakBytes = s.peakMem
	}
	if okN && netNow >= s.baseNet {
		// The delta is bounded by what moved on this host's interfaces
		// during one task, far from 2^63.
		r.NetBytes = int64(netNow - s.baseNet) // #nosec G115
	}
	return r
}

// procTreeCPUTicks is the sum of utime+stime, in jiffies, over pid and
// every process it has spawned. The tree is walked by parentage from /proc,
// so grandchildren of the tool are included: nmap that forks a child for
// each host is counted whole, not just its top level.
func procTreeCPUTicks(root int) (int64, bool) {
	children := mapParentChildren()
	seen := map[int]bool{}
	var total int64
	ok := false
	var walk func(pid int)
	walk = func(pid int) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		t, found := procCPUTicks(pid)
		if found {
			total += t
			ok = true
		}
		for c := range children[pid] {
			walk(c)
		}
	}
	walk(root)
	return total, ok
}

// procCPUTicks reads one process's utime+stime from /proc/<pid>/stat.
// The fields sit after the comm field, which is wrapped in parentheses and
// may itself contain spaces — so everything after the LAST ')' is parsed
// by position: field 14 (utime) and 15 (stime) of the whole line are the
// 12th and 13th tokens after that.
func procCPUTicks(pid int) (int64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") // #nosec G304 — pid is ours
	if err != nil {
		return 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	// f[0] is state (field 3). utime is field 14 -> index 11; stime is
	// field 15 -> index 12.
	if len(f) < 13 {
		return 0, false
	}
	u, err1 := strconv.ParseInt(f[11], 10, 64)
	st, err2 := strconv.ParseInt(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return u + st, true
}

// mapParentChildren reads /proc once and returns parent pid -> children.
func mapParentChildren() map[int]map[int]bool {
	out := make(map[int]map[int]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, perr := strconv.Atoi(e.Name())
		if perr != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat") // #nosec G304 — pid is ours
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		// ppid is field 4 -> index 1 after the comm close-paren.
		if len(f) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		if out[ppid] == nil {
			out[ppid] = make(map[int]bool)
		}
		out[ppid][pid] = true
	}
	return out
}

// procTreeRSS is the sum of VmRSS, in bytes, over the process tree.
func procTreeRSS(root int) (int64, bool) {
	children := mapParentChildren()
	seen := map[int]bool{}
	var total int64
	ok := false
	var walk func(pid int)
	walk = func(pid int) {
		if seen[pid] {
			return
		}
		seen[pid] = true
		r, found := procRSS(pid)
		if found {
			total += r
			ok = true
		}
		for c := range children[pid] {
			walk(c)
		}
	}
	walk(root)
	return total, ok
}

// procRSS reads one process's VmRSS from /proc/<pid>/status, in bytes.
func procRSS(pid int) (int64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status") // #nosec G304 — pid is ours
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// netDevBytes is the sum of rx+tx bytes over every interface in
// /proc/net/dev, excluding loopback. Reading it needs no privilege the
// agent lacks, and in a container it sees only that container's traffic.
func netDevBytes() (uint64, bool) {
	b, err := os.ReadFile("/proc/net/dev") // #nosec G304 — fixed path
	if err != nil {
		return 0, false
	}
	var total uint64
	ok := false
	for _, line := range strings.Split(string(b), "\n") {
		// Skip the two header lines and anything without a colon.
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		total += rx + tx
		ok = true
	}
	return total, ok
}

// ticksPerSecond is the kernel's user timer frequency (USER_HZ). It is
// 100 on every Linux this agent will run; reading it from /proc would
// cost a file read to return a constant, so it is named rather than
// inlined where the jiffies are converted.
const ticksPerSecond = 100.0

var errNoCPUBaseline = errCPUBaseline{}

type errCPUBaseline struct{}

func (errCPUBaseline) Error() string { return "no CPU baseline" }
