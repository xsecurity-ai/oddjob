package recon

import (
	"io/fs"
	"strings"
	"testing"
)

// fakeFS is a root filesystem built from a map: a key is a path that
// exists, its value the contents. Directories are keys with no
// contents.
//
// The whole point of injecting the filesystem is that none of these
// paths can be present on the machine running the tests — a mac
// laptop and a Linux CI runner between them can produce exactly one of
// the situations this code has to tell apart.
type fakeFS map[string]string

func (f fakeFS) ReadFile(name string) ([]byte, error) {
	v, ok := f[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(v), nil
}

func (f fakeFS) Exists(name string) bool {
	_, ok := f[name]
	return ok
}

func noEnv(string) string { return "" }

const (
	wsl2Version = "Linux version 5.15.153.1-microsoft-standard-WSL2 " +
		"(root@941d701f84f1) (gcc (GCC) 11.2.0) #1 SMP Fri Mar 29 23:14:13 UTC 2024"
	debianVersion = "Linux version 6.1.0-21-amd64 " +
		"(debian-kernel@lists.debian.org) (gcc-12 12.2.0) #1 SMP Debian 6.1.90-1"
	linuxkitVersion = "Linux version 6.6.26-linuxkit " +
		"(root@buildkitsandbox) (gcc (Alpine 13.2.1) ) #1 SMP Sat Apr 27 2024"
)

// The case this change exists for: a ghost enrolled as the Windows
// target, running in Docker CE inside WSL2 on an Azure Windows Server
// VM. It reported platform=linux, which is true of the container and
// useless for picking the Windows machine out of a fleet list.
//
// It works through the container boundary because containers share the
// host's kernel, so /proc/version inside the container is still the
// WSL2 kernel's.
func TestLinuxContainerOnWSL2ReportsAWindowsHost(t *testing.T) {
	f := fakeFS{
		"/proc/version":                  wsl2Version,
		"/proc/sys/kernel/osrelease":     "5.15.153.1-microsoft-standard-WSL2",
		"/.dockerenv":                    "",
		"/sys/class/net/eth0/ifindex":    "11",
		"/sys/class/net/eth0/iflink":     "12",
		"/proc/1/cgroup":                 "0::/",
		"/sys/fs/cgroup/memory.pressure": "",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Platform != "linux" {
		t.Errorf("platform = %q, want linux — the binary's OS is not a guess "+
			"and must not be rewritten", h.Platform)
	}
	if h.Host != "windows" {
		t.Errorf("host = %q, want windows (%s)", h.Host, h.HostWhy)
	}
	if h.Container != "docker" {
		t.Errorf("container = %q, want docker", h.Container)
	}
	if got, want := h.String(), "linux (container on windows)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	// The claim has to be checkable, not just correct.
	if !strings.Contains(h.HostWhy, "WSL2") {
		t.Errorf("evidence does not name the signal: %q", h.HostWhy)
	}
}

// The error in the other direction is worse, because it would be
// invisible: a plain Linux host in a plain container quietly claiming
// to be a Windows box.
func TestPlainLinuxContainerDoesNotClaimWindows(t *testing.T) {
	f := fakeFS{
		"/proc/version":              debianVersion,
		"/proc/sys/kernel/osrelease": "6.1.0-21-amd64",
		"/.dockerenv":                "",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Host != "linux" {
		t.Errorf("host = %q, want linux (%s)", h.Host, h.HostWhy)
	}
	if got, want := h.String(), "linux (container)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestPlainLinuxHostIsJustLinux(t *testing.T) {
	f := fakeFS{
		"/proc/version":              debianVersion,
		"/proc/sys/kernel/osrelease": "6.1.0-21-amd64",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Host != "linux" || h.Container != "" {
		t.Errorf("host = %q container = %q, want linux and none (%s)",
			h.Host, h.Container, h.HostWhy)
	}
	if got := h.String(); got != "linux" {
		t.Errorf("String() = %q, want plain %q", got, "linux")
	}
}

// WSL1 has a different mechanism — it shares the Windows network stack
// rather than running its own kernel in a VM — but the same answer to
// the question being asked.
func TestWSL1AlsoMeansAWindowsHost(t *testing.T) {
	f := fakeFS{
		"/proc/version": "Linux version 4.4.0-19041-Microsoft " +
			"(Microsoft@Microsoft.com) #1237-Microsoft Sat Sep 11 14:32:00 PST 2021",
		"/proc/sys/kernel/osrelease": "4.4.0-19041-Microsoft",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Host != "windows" {
		t.Errorf("host = %q, want windows (%s)", h.Host, h.HostWhy)
	}
	if !strings.Contains(h.HostWhy, "WSL1") {
		t.Errorf("evidence should distinguish WSL1 from WSL2: %q", h.HostWhy)
	}
}

// Docker Desktop's LinuxKit VM runs on macOS and on Windows alike, and
// from inside it nothing says which. "Unknown" is the honest answer
// and the one that must survive: a guess here is the bug this change
// removes, pointing the other way.
func TestDockerDesktopVMWillNotGuessItsHost(t *testing.T) {
	f := fakeFS{
		"/proc/version":              linuxkitVersion,
		"/proc/sys/kernel/osrelease": "6.6.26-linuxkit",
		"/.dockerenv":                "",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Host != "" {
		t.Errorf("host = %q, want empty — the host OS is not visible from "+
			"inside a LinuxKit VM (%s)", h.Host, h.HostWhy)
	}
	if got, want := h.String(), "linux (container host OS unknown)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// /mnt/c is a WSL convention, not a fact about the kernel. Any Linux
// box can have that directory, or a CIFS share mounted there, so it
// corroborates and never decides.
func TestMountedCDriveAloneIsNotEnough(t *testing.T) {
	f := fakeFS{
		"/proc/version":              debianVersion,
		"/proc/sys/kernel/osrelease": "6.1.0-21-amd64",
		"/mnt/c/Windows/System32":    "",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Host != "linux" {
		t.Errorf("host = %q — a directory is not a kernel (%s)",
			h.Host, h.HostWhy)
	}
	if !strings.Contains(h.HostWhy, "/mnt/c") {
		t.Errorf("the hint should still be recorded: %q", h.HostWhy)
	}
}

func TestMountedCDriveCorroboratesWSL(t *testing.T) {
	f := fakeFS{
		"/proc/version":              wsl2Version,
		"/proc/sys/kernel/osrelease": "5.15.153.1-microsoft-standard-WSL2",
		"/mnt/c/Windows/System32":    "",
	}
	h := detectHostPlatform("linux", f, noEnv)
	if h.Host != "windows" {
		t.Fatalf("host = %q, want windows (%s)", h.Host, h.HostWhy)
	}
	if got, want := h.String(), "linux (on windows)"; got != want {
		t.Errorf("String() = %q, want %q — WSL without a container is still "+
			"a Linux binary on a Windows machine", got, want)
	}
}

// No /proc to read is a gap in what we could see, not evidence that
// the host is Linux. Collapsing the two is exactly the mistake the
// whole package is written against.
func TestUnreadableProcIsUnknownNotLinux(t *testing.T) {
	h := detectHostPlatform("linux", fakeFS{}, noEnv)
	if h.Host != "" {
		t.Errorf("host = %q, want empty with no /proc to read (%s)",
			h.Host, h.HostWhy)
	}
	if !strings.Contains(h.HostWhy, "could not read") {
		t.Errorf("the gap should say it is a gap: %q", h.HostWhy)
	}
}

// A windows/amd64 or darwin/arm64 binary is running on that OS. Linux
// is the only one of the three that is routinely a layer in front of
// something else.
func TestNonLinuxBinariesReportTheirOwnOS(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		h := detectHostPlatform(goos, fakeFS{}, noEnv)
		if h.Host != goos {
			t.Errorf("%s: host = %q, want %q", goos, h.Host, goos)
		}
		if h.String() != goos {
			t.Errorf("%s: String() = %q, want no qualifier", goos, h.String())
		}
	}
}

func TestContainerRuntimeMarkers(t *testing.T) {
	cases := []struct {
		name   string
		fs     fakeFS
		getenv func(string) string
		want   string
	}{
		{"docker", fakeFS{"/.dockerenv": ""}, noEnv, "docker"},
		{"podman file", fakeFS{"/run/.containerenv": ""}, noEnv, "podman"},
		{"env var", fakeFS{}, func(k string) string {
			if k == "container" {
				return "podman"
			}
			return ""
		}, "podman"},
		{"kubernetes cgroup", fakeFS{"/proc/1/cgroup": "12:memory:/kubepods/besteffort/pod1234/abcd"}, noEnv, "kubernetes"},
		{"docker cgroup", fakeFS{"/proc/1/cgroup": "11:cpu:/docker/3f9a"}, noEnv, "docker"},
		{"lxc cgroup", fakeFS{"/proc/1/cgroup": "9:devices:/lxc/web01"}, noEnv, "lxc"},
		// cgroup v2 on a real host: a root cgroup and nothing to see.
		{"plain host", fakeFS{"/proc/1/cgroup": "0::/init.scope"}, noEnv, ""},
		// cgroup v2 inside a container frequently looks identical to a
		// host, which is why the dedicated marker files are checked
		// first and why an empty answer is "no marker found" rather
		// than "not a container".
		{"nothing readable", fakeFS{}, noEnv, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectContainer(c.fs, c.getenv)
			if got.Runtime != c.want {
				t.Errorf("runtime = %q, want %q (%s)", got.Runtime, c.want, got.Why)
			}
			if got.Runtime != "" && got.Why == "" {
				t.Error("claimed a container with no evidence recorded")
			}
		})
	}
}
