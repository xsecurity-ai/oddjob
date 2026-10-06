// Package tools finds, installs and reports on the scanners Jaws drives.
//
// Installation goes through whatever package manager the host already
// has. Jaws does not download binaries from the internet and run them:
// on an engagement host that is indistinguishable from the thing we are
// usually hired to find, and it would make the agent a far better
// malware delivery system than scanner.
package tools

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Baseline is installed on init without being asked.
var Baseline = []string{"amass", "nmap", "masscan", "gobuster"}

// Known is everything Jaws will install at all. The server has its own
// copy of this list and refuses anything outside it; this is the second
// gate, because the agent runs privileged and should not be one
// compromised server away from running arbitrary installs.
var Known = map[string]pkg{
	"amass": {apt: "", brew: "amass", choco: "amass", version: "-version",
		snap: "amass", gomod: "github.com/owasp-amass/amass/v4/cmd/amass@master"},
	"nmap":    {apt: "nmap", brew: "nmap", choco: "nmap", version: "--version"},
	"masscan": {apt: "masscan", brew: "masscan", choco: "masscan", version: "--version"},
	"gobuster": {apt: "gobuster", brew: "gobuster", choco: "gobuster", version: "version",
		gomod: "github.com/OJ/gobuster/v3@latest"},
	"nuclei": {apt: "", brew: "nuclei", choco: "nuclei", version: "-version",
		gomod: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	"httpx": {apt: "", brew: "", choco: "", version: "-version",
		gomod: "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
	"subfinder": {apt: "", brew: "subfinder", choco: "", version: "-version",
		gomod: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
	"ffuf": {apt: "ffuf", brew: "ffuf", choco: "ffuf", version: "-V",
		gomod: "github.com/ffuf/ffuf/v2@latest"},
	// Crawls a site and reports what it links to, including URLs found
	// in JavaScript, which is where the interesting endpoints usually
	// are. Go-only: there is no distro package anywhere.
	"gospider": {apt: "", brew: "", choco: "", version: "--version",
		gomod: "github.com/jaeles-project/gospider@latest"},
	"whatweb": {apt: "whatweb", brew: "whatweb", choco: "", version: "--version"},
	"nikto":   {apt: "nikto", brew: "nikto", choco: "", version: "-Version"},
	"dnsx": {apt: "", brew: "dnsx", choco: "", version: "-version",
		gomod: "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
	"naabu": {apt: "", brew: "naabu", choco: "", version: "-version",
		gomod: "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
}

type pkg struct {
	apt, brew, choco string
	version          string
	// snap and gomod are fallbacks for tools the distribution does not
	// package. Both are upstream distribution channels, not "download
	// a binary from somewhere and run it" — amass genuinely is not in
	// Debian or Ubuntu, and without a fallback the baseline install
	// simply fails on the most common agent platform there is.
	snap  string
	gomod string
}

// Path returns the absolute path of a tool, or "" if it is absent.
func Path(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

var versionRe = regexp.MustCompile(`\d+\.\d+(\.\d+)?`)

// Version runs the tool's own version flag. Reporting the version
// matters because findings get attributed to it: "nmap said this" is a
// weaker claim without knowing which nmap.
func Version(ctx context.Context, name string) string {
	p, ok := Known[name]
	if !ok || Path(name) == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, name, p.version).CombinedOutput()
	if m := versionRe.FindString(string(out)); m != "" {
		return m
	}
	if s := strings.TrimSpace(string(out)); s != "" {
		if i := strings.IndexByte(s, '\n'); i > 0 {
			s = s[:i]
		}
		return trunc(s, 60)
	}
	return "present"
}

// Installed reports every known tool that is on the box, with versions.
func Installed(ctx context.Context) map[string]string {
	out := map[string]string{}
	names := make([]string, 0, len(Known))
	for n := range Known {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if Path(n) != "" {
			out[n] = Version(ctx, n)
		}
	}
	return out
}

// Manager describes how to install on this host.
type Manager struct {
	Name    string
	Install []string // argv prefix; the package name is appended
	Refresh []string // argv to update the index first, may be nil
	Sudo    bool
}

// DetectManager picks the package manager, or returns nil with a
// reason that names what to do by hand.
func DetectManager() (*Manager, string) {
	switch runtime.GOOS {
	case "linux":
		switch {
		case Path("apt-get") != "":
			return &Manager{Name: "apt", Sudo: true,
				Refresh: []string{"apt-get", "update", "-qq"},
				Install: []string{"apt-get", "install", "-y", "--no-install-recommends"}}, ""
		case Path("dnf") != "":
			return &Manager{Name: "dnf", Sudo: true,
				Install: []string{"dnf", "install", "-y"}}, ""
		case Path("yum") != "":
			return &Manager{Name: "yum", Sudo: true,
				Install: []string{"yum", "install", "-y"}}, ""
		case Path("apk") != "":
			return &Manager{Name: "apk", Sudo: true,
				Install: []string{"apk", "add", "--no-cache"}}, ""
		case Path("pacman") != "":
			return &Manager{Name: "pacman", Sudo: true,
				Install: []string{"pacman", "-S", "--noconfirm"}}, ""
		}
		return nil, "no supported package manager found (looked for apt-get, dnf, yum, apk, pacman)"
	case "darwin":
		if Path("brew") != "" {
			// Never with sudo: Homebrew refuses, and insisting would
			// leave root-owned files in the Cellar that break every
			// later install.
			return &Manager{Name: "brew", Install: []string{"brew", "install"}}, ""
		}
		return nil, "Homebrew is not installed — see https://brew.sh"
	case "windows":
		if Path("choco") != "" {
			return &Manager{Name: "choco",
				Install: []string{"choco", "install", "-y"}}, ""
		}
		if Path("winget") != "" {
			return &Manager{Name: "winget",
				Install: []string{"winget", "install", "--silent",
					"--accept-package-agreements", "--accept-source-agreements"}}, ""
		}
		return nil, "neither Chocolatey nor winget is available"
	}
	return nil, "unsupported platform: " + runtime.GOOS
}

func (m *Manager) pkgFor(name string) string {
	p, ok := Known[name]
	if !ok {
		return ""
	}
	switch m.Name {
	case "brew":
		return p.brew
	case "choco", "winget":
		return p.choco
	default:
		return p.apt
	}
}

type InstallReport struct {
	Tool    string `json:"tool"`
	Action  string `json:"action"` // present | installed | failed | unavailable
	Version string `json:"version,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Ensure installs any of `names` that are missing. Already-present
// tools are left alone: re-installing nmap on every start would be
// slow, noisy in the package log, and occasionally destructive.
func Ensure(ctx context.Context, names []string, elevated bool) []InstallReport {
	reports := make([]InstallReport, 0, len(names))
	var mgr *Manager
	var why string
	refreshed := false

	for _, name := range names {
		if _, ok := Known[name]; !ok {
			reports = append(reports, InstallReport{Tool: name, Action: "unavailable",
				Detail: "not in the allowed list"})
			continue
		}
		if Path(name) != "" {
			reports = append(reports, InstallReport{Tool: name, Action: "present",
				Version: Version(ctx, name)})
			continue
		}
		if mgr == nil {
			mgr, why = DetectManager()
			if mgr == nil {
				reports = append(reports, InstallReport{Tool: name,
					Action: "failed", Detail: why})
				continue
			}
		}
		// Package manager first, then the tool's other upstream
		// channels. amass is not in Debian or Ubuntu at all, so
		// without this the baseline install fails on the single most
		// common agent platform.
		var why []string
		installed := false

		if p := mgr.pkgFor(name); p != "" {
			if mgr.Refresh != nil && !refreshed {
				_ = run(ctx, mgr, elevated, mgr.Refresh, 5*time.Minute)
				refreshed = true
			}
			argv := append(append([]string{}, mgr.Install...), p)
			if out := run(ctx, mgr, elevated, argv, 15*time.Minute); out == "" {
				installed = true
			} else {
				why = append(why, mgr.Name+": "+trunc(out, 200))
			}
		} else {
			why = append(why, "no "+mgr.Name+" package")
		}

		if !installed {
			if out, tried := installSnap(ctx, name, elevated); tried {
				if out == "" {
					installed = true
				} else {
					why = append(why, "snap: "+trunc(out, 200))
				}
			}
		}
		if !installed {
			if out, tried := installGo(ctx, name, elevated); tried {
				if out == "" {
					installed = true
				} else {
					why = append(why, "go install: "+trunc(out, 200))
				}
			}
		}
		if !installed {
			reports = append(reports, InstallReport{Tool: name, Action: "failed",
				Detail: strings.Join(why, "; ")})
			continue
		}
		if Path(name) == "" {
			reports = append(reports, InstallReport{Tool: name, Action: "failed",
				Detail: mgr.Name + " reported success but the binary is still not on PATH"})
			continue
		}
		reports = append(reports, InstallReport{Tool: name, Action: "installed",
			Version: Version(ctx, name)})
	}
	return reports
}

// run returns "" on success or the combined output on failure.
func run(ctx context.Context, m *Manager, elevated bool, argv []string,
	limit time.Duration) string {

	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	if m.Sudo && !elevated {
		if Path("sudo") == "" {
			return "needs root and sudo is not available — run Jaws as root"
		}
		// -n: never prompt. There is no terminal here, and a package
		// manager silently waiting on a password is the hang that looks
		// like a network problem for half an hour.
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(cmd.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)) + " (" + err.Error() + ")"
	}
	return ""
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// installSnap installs via snapd. -> (failure output, whether tried).
func installSnap(ctx context.Context, name string, elevated bool) (string, bool) {
	p, ok := Known[name]
	if !ok || p.snap == "" || runtime.GOOS != "linux" || Path("snap") == "" {
		return "", false
	}
	m := &Manager{Name: "snap", Sudo: true, Install: []string{"snap", "install"}}
	return run(ctx, m, elevated, []string{"snap", "install", p.snap}, 15*time.Minute), true
}

// installGo builds from source with the Go toolchain.
//
// Most of these tools are Go programs whose upstream distribution IS
// `go install`; this is their packaging, not a workaround. Skipped
// silently when Go is absent, which is the common case on a host that
// is only there to run scans.
func installGo(ctx context.Context, name string, elevated bool) (string, bool) {
	p, ok := Known[name]
	if !ok || p.gomod == "" || Path("go") == "" {
		return "", false
	}
	// GOBIN explicitly: `go install` otherwise lands in ~/go/bin, which
	// is not on PATH for the service user, and the tool would look
	// uninstalled the moment it finished installing.
	bin := goBin()
	m := &Manager{Name: "go"}
	cmd := []string{"go", "install", p.gomod}
	if out := runEnv(ctx, m, elevated, cmd, 20*time.Minute,
		"GOBIN="+bin, "GOFLAGS=-trimpath", "CGO_ENABLED=0"); out != "" {
		return out, true
	}
	return "", true
}

func goBin() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("USERPROFILE"), "go", "bin")
	}
	for _, d := range []string{"/usr/local/bin"} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	return filepath.Join(os.Getenv("HOME"), "go", "bin")
}

func runEnv(ctx context.Context, m *Manager, elevated bool, argv []string,
	limit time.Duration, env ...string) string {

	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if m.Sudo && !elevated {
		if Path("sudo") == "" {
			return "needs root and sudo is not available"
		}
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(cmd.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)) + " (" + err.Error() + ")"
	}
	return ""
}
