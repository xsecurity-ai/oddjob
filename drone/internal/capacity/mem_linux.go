//go:build linux

package capacity

import (
	"os"
	"strconv"
	"strings"
)

// availableMemMB reads MemAvailable, which is the kernel's own estimate
// of what can be allocated without swapping — not MemFree, which
// excludes reclaimable page cache and would read as almost nothing on
// any box that has been up for a week.
func availableMemMB() int {
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
