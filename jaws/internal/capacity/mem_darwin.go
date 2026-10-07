//go:build darwin

package capacity

import (
	"os/exec"
	"strconv"
	"strings"
)

// availableMemMB on macOS: free plus inactive plus speculative pages.
// Not "free" alone — Darwin keeps very little genuinely free and a box
// with 8 GB spare routinely reports a few hundred megabytes, which
// would have the agent decide it can run one thing.
func availableMemMB() int {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0
	}
	pageSize := 4096
	counts := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "page size of") {
			f := strings.Fields(line)
			for i, w := range f {
				if w == "of" && i+1 < len(f) {
					if n, err := strconv.Atoi(f[i+1]); err == nil {
						pageSize = n
					}
				}
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(parts[1]), "."))
		n, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		counts[strings.TrimSpace(parts[0])] = n
	}
	pages := counts["Pages free"] + counts["Pages inactive"] +
		counts["Pages speculative"]
	if pages == 0 {
		return 0
	}
	return pages * pageSize / (1024 * 1024)
}
