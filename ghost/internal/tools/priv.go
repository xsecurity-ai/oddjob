package tools

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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
// way can SYN scan without the Ghost being root at all.
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
			// Bounded, because of where this runs. RawSocketCapable is
			// called from the call-in status handler while the agent
			// mutex is held, so a getcap that does not return takes the
			// heartbeat, the task dispatcher and the spool drain down
			// with it — a wedged agent on a host nobody will log back
			// into. getcap reads one file's xattrs and answers in
			// microseconds; two seconds is already absurdly generous,
			// and the failure path here is just "assume not capable",
			// which is the safe answer anyway.
			ctx, cancel := context.WithTimeout(context.Background(),
				2*time.Second)
			// `p` is not user input: it is whatever exec.LookPath found
			// for "nmap" on this host's PATH, and the command name is a
			// literal. No shell is involved.
			out, err := exec.CommandContext(ctx, "getcap", p).Output() //nolint:gosec // G204: p is exec.LookPath("nmap"); command name is a literal; no shell
			cancel()
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
		// gosec traces %SystemRoot% in and calls the join a traversal.
		// Nothing is opened and nothing is read: this is a Stat whose
		// only output is the boolean "a capture library is present",
		// and the path is a constant suffix on an environment variable
		// Windows itself sets. An attacker who can rewrite this
		// process's environment can set PATH and is already executing
		// as us, at which point lying about Npcap is not the move.
		if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: Stat only, result is a bool; see above
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
