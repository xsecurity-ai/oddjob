package recon

import (
	"os"
	"runtime"
	"strings"
)

// rootFS is the filesystem the environment detection reads.
//
// An interface rather than direct os calls because every signal that
// tells a container from its host, or WSL from Linux, is a file:
// /proc/version, /.dockerenv, /sys/class/net/*/iflink. Those files are
// by definition absent from the machine the tests run on, and
// detection that can only be exercised on the one kind of host it was
// written on is how a heuristic ships broken and stays broken.
type rootFS interface {
	ReadFile(name string) ([]byte, error)
	// Exists is separate from ReadFile because some of the signals are
	// directories, and because a file that is present and unreadable
	// is a different fact from one that is not there.
	Exists(name string) bool
}

type osFS struct{}

// The variable path is the entire purpose of the interface. Every
// caller in this package passes a string constant — /proc/version,
// /.dockerenv, /sys/class/net/<iface>/iflink — and the only non-constant
// element is an interface name this process read back from the kernel.
// Nothing here is reachable from the server or from task arguments.
func (osFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) //nolint:gosec // G304: callers pass constant /proc and /sys paths; see above
}

func (osFS) Exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// Container is the container runtime this process appears to be
// inside, and what said so.
//
// An empty Runtime means no marker we know to look for was found. That
// is not the same claim as "not in a container" — an unfamiliar
// runtime leaves no marker this code recognises — and the Why field
// exists so the difference is readable rather than inferred.
type Container struct {
	Runtime string
	Why     string
}

// detectContainer looks for the markers a container runtime leaves.
//
// Ordered cheapest and most reliable first. Every one of these is a
// convention rather than a guarantee, which is why the evidence is
// carried alongside the answer instead of being thrown away.
func detectContainer(fs rootFS, getenv func(string) string) Container {
	// Docker drops this into every container it creates. It is the
	// single most reliable marker there is, and it survives whatever
	// the image is built from.
	if fs.Exists("/.dockerenv") {
		return Container{"docker", "/.dockerenv exists"}
	}
	if fs.Exists("/run/.containerenv") {
		return Container{"podman", "/run/.containerenv exists"}
	}
	// podman, systemd-nspawn and LXC set this in the environment. Read
	// through the injected getenv rather than os.Getenv so a test can
	// put a process in a container without being in one.
	if v := strings.TrimSpace(getenv("container")); v != "" {
		return Container{v, "container=" + v + " in the environment"}
	}
	// PID 1's cgroup path names the runtime under cgroup v1. Under
	// cgroup v2 the same file is frequently just "0::/" with nothing
	// in it, so a miss here means "no marker", not "no container".
	if b, err := fs.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, m := range []struct{ needle, runtime string }{
			{"kubepods", "kubernetes"},
			{"/docker", "docker"},
			{"docker-", "docker"},
			{"containerd", "containerd"},
			{"/lxc", "lxc"},
		} {
			if strings.Contains(s, m.needle) {
				return Container{m.runtime,
					"/proc/1/cgroup mentions " + m.needle}
			}
		}
	}
	return Container{}
}

// HostPlatform separates what this binary is from what the machine
// under it is.
//
// They are usually the same and occasionally not, and when they differ
// the difference is the whole answer to the operator's question. A
// ghost enrolled as the Windows target, running in Docker CE inside
// WSL2 on a Windows Server VM, reported `platform: linux` — true of
// the binary, true of the container, and useless for picking the
// Windows machine out of a fleet list.
type HostPlatform struct {
	// Platform is runtime.GOOS: the OS this binary was built for and
	// is executing on. Never a guess, and never overwritten — code and
	// operators that already depend on it keep reading the same thing.
	Platform string
	// Host is the best supportable judgement about the machine
	// underneath: "windows", "linux", "darwin", or empty when it could
	// not be determined. Empty is a real answer. Collapsing "could not
	// tell" into "linux" is the bug this type exists to fix, and
	// collapsing it into a confident guess would be a worse one.
	Host string
	// HostWhy is the evidence for Host in words, so the claim can be
	// checked instead of trusted.
	HostWhy string
	// Container is the detected runtime, empty when no marker was
	// found.
	Container string
}

// String renders the pair the way it should be read: the binary's OS
// first, because that is the one that is certain, with the layering as
// a qualifier.
func (h HostPlatform) String() string {
	var qual []string
	if h.Container != "" {
		qual = append(qual, "container")
	}
	switch {
	case h.Host == "":
		qual = append(qual, "host OS unknown")
	case h.Host != h.Platform:
		qual = append(qual, "on "+h.Host)
	}
	if len(qual) == 0 {
		return h.Platform
	}
	return h.Platform + " (" + strings.Join(qual, " ") + ")"
}

// DetectHostPlatform inspects this machine.
func DetectHostPlatform() HostPlatform {
	return detectHostPlatform(runtime.GOOS, osFS{}, os.Getenv)
}

func detectHostPlatform(goos string, fs rootFS, getenv func(string) string) HostPlatform {
	h := HostPlatform{Platform: goos}
	c := detectContainer(fs, getenv)
	h.Container = c.Runtime

	if goos != "linux" {
		// A windows/amd64 binary is running on Windows and a darwin one
		// on macOS. The layering this function exists for is specific
		// to Linux: it is the only one of the three that routinely runs
		// as a container or a utility VM standing in front of a
		// different host OS.
		h.Host, h.HostWhy = goos, "runtime.GOOS"
		return h
	}

	// Both files say what kernel is running. In a container that is the
	// HOST's kernel, not the image's — containers share it — which is
	// exactly why this works through the container boundary for the
	// case it was written for: Docker CE inside WSL2 on Windows.
	ver, verOK := readString(fs, "/proc/version")
	rel, relOK := readString(fs, "/proc/sys/kernel/osrelease")
	kernel := strings.ToLower(ver + " " + rel)

	switch {
	case !verOK && !relOK:
		// No /proc to read. Rather than fall through to the default and
		// call it Linux on no evidence, say so: a Linux binary is
		// running, but nothing here speaks to what it is running on.
		h.HostWhy = "could not read /proc/version or /proc/sys/kernel/osrelease"

	case strings.Contains(kernel, "microsoft-standard-wsl2"),
		strings.Contains(kernel, "-wsl2"):
		h.Host = "windows"
		h.HostWhy = "WSL2 kernel (" + kernelQuote(ver, rel) + ")"

	case strings.Contains(kernel, "microsoft"):
		// WSL1's kernel version string ends in "-Microsoft". Same
		// conclusion, different mechanism, and worth distinguishing in
		// the evidence because WSL1 shares the Windows host's network
		// stack while WSL2 does not.
		h.Host = "windows"
		h.HostWhy = "WSL1 kernel (" + kernelQuote(ver, rel) + ")"

	case strings.Contains(kernel, "linuxkit"):
		// Docker Desktop runs containers inside a LinuxKit VM. That VM
		// sits on macOS or on Windows — with the WSL2 backend we would
		// have matched above instead — and nothing inside it says
		// which. Guessing here is precisely the failure being fixed, so
		// it stays unknown.
		h.HostWhy = "LinuxKit VM (Docker Desktop); the host OS is not " +
			"visible from inside it"

	default:
		// A Linux kernel with no marker suggesting anything else is in
		// front of it. Still only a statement about the kernel: a Linux
		// VM on a Windows hypervisor looks exactly like this from in
		// here, and there is no honest way to tell from userspace.
		h.Host = "linux"
		h.HostWhy = "Linux kernel, no WSL or Docker Desktop markers in " +
			"/proc/version"
	}

	// /mnt/c is where WSL mounts the Windows C: drive, and it is
	// corroboration only — never the deciding vote. Any Linux box can
	// have a directory called /mnt/c, or a CIFS share mounted there,
	// and a plain Linux host that starts announcing itself as Windows
	// costs more than a WSL instance whose kernel string was somehow
	// unrecognisable.
	if fs.Exists("/mnt/c/Windows/System32") {
		if h.Host == "windows" {
			h.HostWhy += "; /mnt/c/Windows/System32 present"
		} else {
			h.HostWhy += "; /mnt/c/Windows/System32 present, which hints at " +
				"WSL but is not enough on its own"
		}
	}
	if c.Runtime != "" {
		h.HostWhy += "; container: " + c.Runtime + " (" + c.Why + ")"
	}
	return h
}

// kernelQuote names whichever kernel string was actually readable, so
// the evidence points at a real file rather than at a conclusion.
func kernelQuote(ver, rel string) string {
	if rel = strings.TrimSpace(rel); rel != "" {
		return "/proc/sys/kernel/osrelease: " + trunc(rel, 60)
	}
	return "/proc/version: " + trunc(strings.TrimSpace(ver), 80)
}

func readString(fs rootFS, name string) (string, bool) {
	b, err := fs.ReadFile(name)
	if err != nil {
		return "", false
	}
	return string(b), true
}
