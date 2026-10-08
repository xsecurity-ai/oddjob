package tools

import (
	"runtime"
	"strings"
	"testing"
)

// Being uid 0 and being able to open a raw socket came apart the
// moment the agent went into a container: `--cap-drop=ALL` leaves a
// root process that cannot raw-socket, and the euid check claimed it
// could. masscan then refuses and nmap quietly connect-scans, which is
// a different scan from the one the report says was run.
//
// There is no way to drop a capability from inside a test, so this
// asserts the shape of the answer rather than both branches: whatever
// is reported, the advice must match it, and it must never be the bare
// "running as root" on Linux now that the kernel is being asked.
func TestRawSocketAnswerMatchesItsExplanation(t *testing.T) {
	ok, why := RawSocketCapable()
	if strings.TrimSpace(why) == "" {
		t.Fatal("no explanation given either way")
	}
	if !ok && !strings.Contains(strings.ToLower(why), "not") &&
		!strings.Contains(strings.ToLower(why), "cap_net_raw") {
		t.Errorf("reported incapable but the reason does not say why: %q", why)
	}
	if runtime.GOOS == "linux" {
		if has, known := linuxEffectiveNetRaw(); known && has != ok {
			t.Errorf("kernel says CAP_NET_RAW=%v, we reported %v (%q)",
				has, ok, why)
		}
	}
}

func TestCapabilityIsReadFromTheKernelNotInferred(t *testing.T) {
	has, known := linuxEffectiveNetRaw()
	if runtime.GOOS != "linux" {
		if known {
			t.Errorf("claimed to know a Linux capability on %s", runtime.GOOS)
		}
		return
	}
	if !known {
		t.Skip("no readable /proc/self/status")
	}
	// Unprivileged CI has no CAP_NET_RAW; a privileged runner does.
	// Either is fine — what must not happen is the answer disagreeing
	// with what RawSocketCapable goes on to report, covered above.
	t.Logf("CAP_NET_RAW effective here: %v", has)
}

// Whatever the platform, an agent that cannot raw-socket has to say
// something an operator can act on. "not privileged" alone sends
// people to the wrong place — on Windows the answer is Npcap, in a
// container it is --cap-add, on Linux it is setcap or sudo.
func TestTheAdviceIsActionable(t *testing.T) {
	a := unprivilegedAdvice()
	if len(a) < 20 {
		t.Fatalf("advice is too thin to act on: %q", a)
	}
	want := map[string]string{
		"linux": "setcap", "darwin": "sudo", "windows": "Npcap",
	}[runtime.GOOS]
	if want != "" && !strings.Contains(a, want) {
		t.Errorf("advice on %s does not mention %q: %q", runtime.GOOS, want, a)
	}
}
