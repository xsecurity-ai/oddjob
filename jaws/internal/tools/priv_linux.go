//go:build linux

package tools

import (
	"os"
	"strconv"
	"strings"
)

// : CAP_NET_RAW is capability 13. Opening a raw socket needs it; so do
// : SYN scanning, OS fingerprinting and masscan.
const capNetRaw = 13

// linuxEffectiveNetRaw reports whether this process can actually open a
// raw socket, as opposed to merely being uid 0.
//
// Those came apart the moment the agent went into a container. Root
// there is root with a capability bounding set, and `--cap-drop=ALL`
// leaves a uid-0 process that cannot raw-socket at all — at which
// point masscan refuses and nmap quietly connect-scans, which is a
// different scan from the one the report will say was run. Checking
// euid alone claimed the capability and shipped the wrong scan, the
// same mistake Windows made by trusting elevation without Npcap.
//
// Read from the kernel rather than inferred: /proc/self/status is the
// authority on what this process actually holds.
func linuxEffectiveNetRaw() (bool, bool) {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		// No procfs to ask. Unknown, not false — saying "no" here
		// would downgrade a perfectly capable host.
		return false, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(
			strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false, false
		}
		return v&(1<<capNetRaw) != 0, true
	}
	return false, false
}
