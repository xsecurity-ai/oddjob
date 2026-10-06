package tools

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Privileged reports whether this process can do the things that need
// raw sockets: SYN scanning, OS fingerprinting, masscan at all.
//
// It is reported rather than assumed because the failure is quiet. An
// unprivileged nmap falls back to a connect scan, which touches every
// port with a full handshake — louder on the wire, different results,
// and no longer the scan the report says was run.
func Privileged() bool {
	switch runtime.GOOS {
	case "windows":
		return windowsElevated()
	default:
		return os.Geteuid() == 0
	}
}

// RawSocketCapable is the softer question: root is one way, but on
// Linux a capability on the binary is another, and a box set up that
// way can SYN scan without Jaws being root at all.
func RawSocketCapable() (bool, string) {
	if Privileged() {
		return true, "running as root"
	}
	if runtime.GOOS == "linux" {
		if p := Path("nmap"); p != "" && Path("getcap") != "" {
			out, err := exec.Command("getcap", p).Output()
			if err == nil && strings.Contains(string(out), "cap_net_raw") {
				return true, "nmap has cap_net_raw"
			}
		}
	}
	return false, unprivilegedAdvice()
}

func unprivilegedAdvice() string {
	switch runtime.GOOS {
	case "linux":
		return "not privileged — run as root, or: " +
			"sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)"
	case "darwin":
		return "not privileged — run with sudo; macOS has no capability equivalent"
	case "windows":
		return "not elevated — run from an Administrator prompt, and install Npcap"
	}
	return "not privileged"
}
