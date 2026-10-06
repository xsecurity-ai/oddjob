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
	// Windows is the exception: being elevated is necessary and not
	// sufficient. nmap and masscan reach the wire through Npcap, and
	// without the driver an elevated process still cannot SYN scan.
	// Reporting "privileged" on elevation alone sent exactly the
	// tasks that need raw sockets to a host that would fail them.
	if runtime.GOOS == "windows" {
		if !Privileged() {
			return false, unprivilegedAdvice()
		}
		if !npcapPresent() {
			return false, "elevated, but Npcap is not installed — " +
				"masscan will refuse and nmap will fall back to connect " +
				"scans; install it from npcap.com"
		}
		return true, "elevated, Npcap present"
	}
	if runtime.GOOS == "linux" {
		// Ask the kernel what this process holds before trusting uid.
		// In a container, root with CAP_NET_RAW dropped cannot open a
		// raw socket, and claiming otherwise sends SYN work to an
		// agent that will connect-scan instead.
		if has, known := linuxEffectiveNetRaw(); known {
			if has {
				if Privileged() {
					return true, "running as root with cap_net_raw"
				}
				return true, "holds cap_net_raw"
			}
			if Privileged() {
				return false, "running as root but CAP_NET_RAW is not in " +
					"this process's capability set — in a container, add " +
					"--cap-add=NET_RAW; masscan will refuse and nmap will " +
					"fall back to connect scans"
			}
			return false, unprivilegedAdvice()
		}
	}
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

// npcapPresent looks for the driver rather than the installer's
// registry entry: what matters is whether a capture library is there
// to be loaded now.
func npcapPresent() bool {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	for _, p := range []string{
		root + `\System32\Npcap\wpcap.dll`,
		root + `\SysWOW64\Npcap\wpcap.dll`,
		root + `\System32\Npcap\packet.dll`,
		// WinPcap's old location. Deprecated and unmaintained, but a
		// host that has it can still capture, and claiming otherwise
		// would be its own wrong answer.
		root + `\System32\wpcap.dll`,
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
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
