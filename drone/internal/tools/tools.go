// Package tools finds, installs and reports on the scanners a Drone drives.
//
// Installation goes through whatever package manager the host already
// has. A Drone does not download binaries from the internet and run them:
// on an engagement host that is indistinguishable from the thing we are
// usually hired to find, and it would make the agent a far better
// malware delivery system than scanner.
package tools

import (
	"context"
	"fmt"
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
//
// Everything a task kind actually needs, not a subset. An agent that
// starts without nuclei and is then given a nuclei task fails it three
// times and stops — the operator's answer to "why" is "the agent did
// not try to get it", which is not an answer. Trying at startup costs
// one package install on a machine that is about to spend hours
// scanning, and an agent that cannot get one says so and is simply not
// given that kind of work.
var Baseline = []string{
	"amass", "nmap", "masscan", "gobuster", "gospider", "nuclei", "httpx",
}

// Known is everything a Drone will install at all. The server has its own
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
		gomod:       "github.com/projectdiscovery/httpx/cmd/httpx@latest",
		mustMention: "projectdiscovery"},
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
	// mustMention is a string the version output has to contain for
	// this to be the tool we meant.
	//
	// `httpx` is the case that forced it: the Python HTTP library
	// installs a CLI of the same name, and on a developer's machine it
	// usually wins the PATH. A Drone would report httpx as installed,
	// accept an httpx task, run the wrong program against a client's
	// estate and report no findings — indistinguishable from a clean
	// result. A name on PATH is not proof of identity.
	mustMention string
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

	// The same tool spells this differently between releases --
	// gobuster 3.6 wants `version` and 3.8 wants `--version`, and the
	// one that is wrong prints "No help topic for 'version'". Taking
	// the first line of whatever came back recorded that sentence as
	// the version and reported it to the server as fact.
	probes := []string{p.version}
	for _, alt := range []string{"--version", "-version", "version", "-V", "-v"} {
		if alt != p.version {
			probes = append(probes, alt)
		}
	}
	var firstLine string
	for _, probe := range probes {
		// `name` has already been checked against `Known` at the top of
		// this function, and `probe` comes from the literal list above.
		// Both are compile-time constants by the time they get here,
		// and argv goes to execve as a slice, so there is no shell to
		// reinterpret either of them.
		out, _ := exec.CommandContext(ctx, name, probe).CombinedOutput() //nolint:gosec // G204: name is gated by Known, probe is a literal; no shell — see above
		if m := versionRe.FindString(string(out)); m != "" {
			return m
		}
		if firstLine == "" {
			if t := strings.TrimSpace(string(out)); t != "" && !looksLikeRefusal(t) {
				if i := strings.IndexByte(t, '\n'); i > 0 {
					t = t[:i]
				}
				firstLine = trunc(t, 60)
			}
		}
	}
	if firstLine != "" {
		return firstLine
	}
	// Installed, version unknown. Better than a usage message dressed
	// up as a version number in the agent inventory.
	return "present"
}

// looksLikeRefusal spots a tool complaining about the flag rather than
// answering it. Such output is not a version, and recording it as one
// puts a lie in the inventory an operator reads.
func looksLikeRefusal(s string) bool {
	l := strings.ToLower(s)
	for _, bad := range []string{
		"no help topic", "unknown command", "unknown flag", "unknown option",
		"usage:", "invalid option", "unrecognized", "not a valid",
		"flag provided but not defined",
	} {
		if strings.Contains(l, bad) {
			return true
		}
	}
	return false
}

// Verify reports whether the binary on PATH under this name is
// actually the tool meant, and why not when it is not.
func Verify(ctx context.Context, name string) (ok bool, why string) {
	p, known := Known[name]
	if !known {
		return false, "not a tool this agent knows"
	}
	if Path(name) == "" {
		return false, "not installed"
	}
	if p.mustMention == "" {
		return true, ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var seen string
	for _, probe := range []string{p.version, "--version", "-version", "version"} {
		// As in Version() above: `name` was checked against `Known` at
		// the top of this function and `probe` is from the literal
		// list on the line above. No shell.
		out, _ := exec.CommandContext(ctx, name, probe).CombinedOutput() //nolint:gosec // G204: name is gated by Known, probe is a literal; no shell
		t := strings.TrimSpace(string(out))
		if t == "" {
			continue
		}
		if strings.Contains(strings.ToLower(t), strings.ToLower(p.mustMention)) {
			return true, ""
		}
		if seen == "" {
			seen = trunc(strings.SplitN(t, "\n", 2)[0], 80)
		}
	}
	return false, fmt.Sprintf(
		"a different program called %q is on PATH at %s (it says %q); "+
			"expected the one from %s", name, Path(name), seen, p.mustMention)
}

// Installed reports every known tool that is on the box, with versions.
//
// A tool that fails verification is left out entirely rather than
// listed with a warning: this inventory is what the server uses to
// decide whether it can run a task, and "present but wrong" would get
// the task dispatched anyway.
func Installed(ctx context.Context) map[string]string {
	out := map[string]string{}
	names := make([]string, 0, len(Known))
	for n := range Known {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if Path(n) == "" {
			continue
		}
		if ok, _ := Verify(ctx, n); !ok {
			continue
		}
		out[n] = Version(ctx, n)
	}
	return out
}

// Impostors are names on PATH that are not the tool they appear to be.
// Reported separately so an operator sees why a tool they believe is
// installed is missing from the inventory.
func Impostors(ctx context.Context) map[string]string {
	out := map[string]string{}
	for n := range Known {
		if Path(n) == "" {
			continue
		}
		if ok, why := Verify(ctx, n); !ok {
			out[n] = why
		}
	}
	return out
}

// Manager describes how to install on this host.
type Manager struct {
	Name    string
	Install []string // argv prefix; the package name is appended
	Refresh []string // argv to update the index first, may be nil
	Remove  []string // argv prefix for uninstalling; the package is appended
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
				Install: []string{"apt-get", "install", "-y", "--no-install-recommends"},
				// --auto-remove takes the dependencies that came with
				// it and nothing else; purge would also delete config
				// belonging to a package somebody else installed.
				Remove: []string{"apt-get", "remove", "-y", "--auto-remove"}}, ""
		case Path("dnf") != "":
			return &Manager{Name: "dnf", Sudo: true,
				Install: []string{"dnf", "install", "-y"},
				Remove:  []string{"dnf", "remove", "-y"}}, ""
		case Path("yum") != "":
			return &Manager{Name: "yum", Sudo: true,
				Install: []string{"yum", "install", "-y"},
				Remove:  []string{"yum", "remove", "-y"}}, ""
		case Path("apk") != "":
			return &Manager{Name: "apk", Sudo: true,
				Install: []string{"apk", "add", "--no-cache"},
				Remove:  []string{"apk", "del"}}, ""
		case Path("pacman") != "":
			return &Manager{Name: "pacman", Sudo: true,
				Install: []string{"pacman", "-S", "--noconfirm"},
				Remove:  []string{"pacman", "-Rns", "--noconfirm"}}, ""
		}
		return nil, "no supported package manager found (looked for apt-get, dnf, yum, apk, pacman)"
	case "darwin":
		if Path("brew") != "" {
			// Never with sudo: Homebrew refuses, and insisting would
			// leave root-owned files in the Cellar that break every
			// later install.
			return &Manager{Name: "brew", Install: []string{"brew", "install"},
				Remove: []string{"brew", "uninstall"}}, ""
		}
		return nil, "Homebrew is not installed — see https://brew.sh"
	case "windows":
		if Path("choco") != "" {
			return &Manager{Name: "choco",
				Install: []string{"choco", "install", "-y"},
				Remove:  []string{"choco", "uninstall", "-y"}}, ""
		}
		if Path("winget") != "" {
			return &Manager{Name: "winget",
				Install: []string{"winget", "install", "--silent",
					"--accept-package-agreements", "--accept-source-agreements"},
				Remove: []string{"winget", "uninstall", "--silent"}}, ""
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
	// How it arrived, and under what package name. Recorded because a
	// Drone that cleans up after itself has to undo exactly what it
	// did: apt, snap and `go install` put the binary in three
	// different places, and guessing at retirement time means either
	// leaving tools behind on someone's host or removing one that was
	// already there before we arrived.
	Via  string `json:"via,omitempty"`  // apt | dnf | yum | apk | pacman | brew | choco | snap | go
	Pkg  string `json:"pkg,omitempty"`  // the package/module name used
	Path string `json:"path,omitempty"` // where the binary landed, for `go`
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
		via, viaPkg := "", ""

		if p := mgr.pkgFor(name); p != "" {
			if mgr.Refresh != nil && !refreshed {
				_ = run(ctx, mgr, elevated, mgr.Refresh, 5*time.Minute)
				refreshed = true
			}
			argv := append(append([]string{}, mgr.Install...), p)
			if out := run(ctx, mgr, elevated, argv, 15*time.Minute); out == "" {
				installed, via, viaPkg = true, mgr.Name, p
			} else {
				why = append(why, mgr.Name+": "+trunc(out, 200))
			}
		} else {
			why = append(why, "no "+mgr.Name+" package")
		}

		if !installed {
			if out, tried := installSnap(ctx, name, elevated); tried {
				if out == "" {
					installed, via, viaPkg = true, "snap", Known[name].snap
				} else {
					why = append(why, "snap: "+trunc(out, 200))
				}
			}
		}
		if !installed {
			if out, tried := installGo(ctx, name, elevated); tried {
				if out == "" {
					installed, via, viaPkg = true, "go", Known[name].gomod
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
			Version: Version(ctx, name), Via: via, Pkg: viaPkg,
			Path: Path(name)})
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
			return "needs root and sudo is not available — run the Drone as root"
		}
		// -n: never prompt. There is no terminal here, and a package
		// manager silently waiting on a password is the hang that looks
		// like a network problem for half an hour.
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	// Running a package manager as root is what this function is for,
	// so G204 cannot be designed away — but nothing here is tainted.
	// argv[0] and the flags come from a Manager literal in this file.
	// The only variable element is a package name, and Ensure refuses
	// any tool not in `Known` before reaching this point, so a
	// compromised server picking the argument can still only pick one
	// of thirteen compile-time constants. There is no shell: argv goes
	// to execve as a slice, so no element can become a second command
	// whatever it contains.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: argv is Manager literals plus a name gated by the Known allowlist; no shell — see above
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
	// As in run() above, and narrower: the only caller is installGo,
	// whose argv is {"go", "install", p.gomod} with p.gomod read from
	// the `Known` map. Every element is a compile-time constant, and
	// there is no shell.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: argv is entirely compile-time constants from the Known map; no shell — see above
	cmd.Env = append(cmd.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(out)) + " (" + err.Error() + ")"
	}
	return ""
}

// RemovalReport is the outcome of undoing one install.
type RemovalReport struct {
	Tool   string `json:"tool"`
	Action string `json:"action"` // removed | kept | failed
	Detail string `json:"detail,omitempty"`
	Via    string `json:"via,omitempty"`
}

// Remove uninstalls tools this Drone installed, and ONLY those.
//
// The input is the ledger written at install time, not a list of
// baseline tools: nmap that was already on the host when the Drone
// arrived belongs to whoever put it there, and removing it on our way
// out is a worse trespass than leaving ours behind. Anything whose
// ledger entry does not say we installed it is kept and reported as
// kept.
//
// Each entry is undone the way it was done. `go install` wrote a
// binary into GOBIN and the package manager never heard about it, so
// the only correct removal is deleting that file; conversely deleting
// a file apt owns leaves the package database claiming it is still
// there.
//
// Never fails the caller. Retirement has to finish even on a host
// where the package manager is wedged — a Drone that refuses to shut
// down because it could not uninstall gobuster is worse than one that
// leaves gobuster behind and says so.
func Remove(ctx context.Context, entries []InstallReport, elevated bool) []RemovalReport {
	out := make([]RemovalReport, 0, len(entries))
	var mgr *Manager

	for _, e := range entries {
		if e.Action != "installed" {
			out = append(out, RemovalReport{Tool: e.Tool, Action: "kept",
				Detail: "was already on this host before the drone arrived"})
			continue
		}
		switch e.Via {
		case "go":
			// Delete the binary. `go install` leaves no package record
			// to ask, so the path recorded at install time is the only
			// handle there is.
			path := e.Path
			if path == "" {
				path = Path(e.Tool)
			}
			if path == "" {
				out = append(out, RemovalReport{Tool: e.Tool, Action: "failed",
					Via: e.Via, Detail: "cannot find the binary to delete"})
				continue
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				out = append(out, RemovalReport{Tool: e.Tool, Action: "failed",
					Via: e.Via, Detail: trunc(err.Error(), 200)})
				continue
			}
			out = append(out, RemovalReport{Tool: e.Tool, Action: "removed",
				Via: e.Via, Detail: path})
		case "":
			out = append(out, RemovalReport{Tool: e.Tool, Action: "failed",
				Detail: "the ledger does not say how it was installed"})
		default:
			if mgr == nil {
				var why string
				if mgr, why = DetectManager(); mgr == nil {
					out = append(out, RemovalReport{Tool: e.Tool,
						Action: "failed", Via: e.Via, Detail: why})
					continue
				}
			}
			if mgr.Remove == nil {
				out = append(out, RemovalReport{Tool: e.Tool, Action: "failed",
					Via: e.Via, Detail: mgr.Name + " has no uninstall command here"})
				continue
			}
			name := e.Pkg
			if name == "" {
				name = e.Tool
			}
			if e.Via == "snap" {
				if o := run(ctx, mgr, elevated,
					[]string{"snap", "remove", name}, 10*time.Minute); o != "" {
					out = append(out, RemovalReport{Tool: e.Tool, Action: "failed",
						Via: e.Via, Detail: trunc(o, 200)})
					continue
				}
			} else {
				argv := append(append([]string{}, mgr.Remove...), name)
				if o := run(ctx, mgr, elevated, argv, 10*time.Minute); o != "" {
					out = append(out, RemovalReport{Tool: e.Tool, Action: "failed",
						Via: e.Via, Detail: trunc(o, 200)})
					continue
				}
			}
			out = append(out, RemovalReport{Tool: e.Tool, Action: "removed",
				Via: e.Via, Detail: name})
		}
	}
	return out
}
