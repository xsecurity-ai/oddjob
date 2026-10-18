// Package tasks runs one unit of work and produces something Oddjob
// can read.
//
// The guiding rule: scanners are asked for their NATIVE output format
// — nmap -oX, masscan -oX, nuclei -jsonl — and that is shipped home
// unchanged. Oddjob already has a parser for each. Reformatting here
// would mean two parsers for one format, which drift, and the one that
// drifts is the one nobody is testing.
package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/capacity"
	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
	"github.com/xsecurity-ai/oddjob/ghost/internal/tools"
)

type Result struct {
	Status   string // done | failed
	Output   string
	Stderr   string
	Summary  string
	ExitCode int
	Error    string
}

func failed(format string, a ...any) Result {
	return Result{Status: "failed", Error: fmt.Sprintf(format, a...), ExitCode: -1}
}

// Runner executes one task kind.
type Runner func(ctx context.Context, args map[string]any, workDir string) Result

var Runners = map[string]Runner{
	"nmap":    runNmap,
	"masscan": runMasscan,
	// Port discovery with no binary. A CONNECT scan, so not a
	// replacement for masscan's SYN sweep — see portscan.go.
	"portscan": runPortscan,
	"amass":    runAmass,
	"gobuster": runGobuster,
	// Content discovery's sibling: gobuster asks one server what
	// paths it has, this asks one address what SERVERS it has. Same
	// library, same wordlist, different question -- and on a shared
	// address or behind a CDN the default vhost is often a holding
	// page with an entire application hidden behind a Host header.
	"vhost": runVhost,
	// katana, in process. The `gospider` alias it replaced is gone:
	// it was kept so that tasks queued under the old name would not
	// be stranded mid-swap, and not one was ever queued. Keeping a
	// name nothing has ever used is how a tool nobody can run stays
	// installed on every agent.
	"katana": runKatana,
	"nuclei": runNuclei,
	// Same runner, same binary. A separate KIND so that the server
	// can tell "this URL has had the CVE templates" apart from "this
	// URL has been fingerprinted" -- it dedupes on (kind, subject),
	// so one name would mean whichever ran first suppressed the
	// other. The flags that make them different arrive in `extra`.
	"nuclei_tech": runNuclei,
	// The same runner. The difference is entirely in the flags
	// Oddjob sends: `-id CVE-…` naming only what the corpus
	// already suspects on that host, which turns the run from
	// discovery into confirmation.
	"nuclei_confirm": runNuclei,
	"httpx":          runHTTPX,
	"nslookup":       runNSLookup,
	"reverse_ip":     runReverseIP,
	"install":        runInstall,
}

// ---------------------------------------------------------------- args
// subjects gathers the thing a task is meant to act on.
//
// Each runner wraps a tool that names its input differently -- nmap has
// targets, amass a domain, gobuster a url, nslookup a query -- and the
// first cut of this file passed that straight through. The result was
// that an operator who had learned the shape for nmap got a hard
// failure from nslookup for saying `targets`, which is the same word
// meaning the same thing. Every runner now takes its native name *and*
// `targets`/`target`, so one habit works across the catalogue and the
// tool-specific name stays available for anyone who prefers it.
func subjects(args map[string]any, names ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range append(names, "targets", "target") {
		for _, v := range list(args, n) {
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// intOr reads a bound a caller may have sent as a JSON number, which
// decodes as float64, or as a string from a form field.
func intOr(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// boolOr reads a switch a caller may have sent as a JSON bool, as a
// string from a form field, or as a number. Anything unrecognised
// leaves the default alone: a task that misspells a flag should run
// the way it would have without it, not silently invert it.
func boolOr(args map[string]any, key string, def bool) bool {
	switch v := args[key].(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	case float64:
		return v != 0
	}
	return def
}

func str(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func list(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		return strings.Fields(t)
	}
	return nil
}

// extraArgs are operator-supplied flags. They are split on whitespace
// and passed as separate argv entries — never through a shell. There
// is no shell in this process, so `; rm -rf /` in a target name is an
// odd-looking hostname and nothing more.
func extraArgs(args map[string]any) []string {
	return strings.Fields(str(args, "extra"))
}

// Said on every request that carries one, because an engagement's
// traffic should be attributable from the target's own logs without
// anybody having to ask us who was scanning them.
//
// The contact URL is the point of it: whoever is reading their logs
// at 03:00 can find out what hit them without opening a ticket. The
// Chrome compatibility note is there because a bare tool name is
// enough for some WAFs and CDNs to serve a challenge page instead of
// the site, which turns a scan into a page of nothing that still
// reports as a result.
//
// A project can override it -- see projects.user_agent -- and an
// engagement that must be attributable to the tester rather than to
// the tool normally should.
const defaultUserAgent = "OddJob/1.0 (+https://oddjob.dev; " +
	"Security Research; Compatible with Chrome/155.0.0.0)"

// userAgent is what this task should call itself on the wire.
//
// The engagement sets it per project and Oddjob fills it in when the
// task is handed over, so that a client's own logs can answer "who
// was scanning us" without anybody having to ask us. Empty means the
// built-in default, which is attributable already.
//
// Sanitised here as well as on the server. The agent is the thing
// that actually writes the header, a CR or LF in it would end the
// header early and start another -- request splitting, against the
// client's own infrastructure -- and "the server checked" is not a
// property this function can verify at the point it matters. Control
// characters are dropped rather than the task refused: the string is
// attribution, and losing a stray byte from it is a far better
// outcome than failing a scan over one.
func userAgent(args map[string]any) string {
	ua := strings.TrimSpace(str(args, "user_agent"))
	if ua == "" {
		return defaultUserAgent
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, ua)
	if clean = strings.TrimSpace(clean); clean == "" {
		return defaultUserAgent
	}
	return clean
}

// headerArgs gives the `-H "User-Agent: x"` pair that nuclei and
// httpx both take. One function because they spell it identically and
// two copies would be two things to keep in step.
func headerArgs(args map[string]any) []string {
	return []string{"-H", "User-Agent: " + userAgent(args)}
}

// nmapUserAgent renders the NSE script argument.
//
// nmap's own default announces the Nmap Scripting Engine, which is
// accurate but is not the engagement's attribution. `--script-args`
// is parsed by nmap itself and splits on commas, so the value is
// quoted and the quoting characters escaped; an unquoted UA with a
// comma in it -- "Mozilla/5.0 (X11; Linux)" has none, but a real
// engagement string like "Acme, authorised test" does -- would be
// read as two arguments and nmap would reject the second.
func nmapUserAgent(args map[string]any) []string {
	ua := userAgent(args)
	esc := strings.ReplaceAll(ua, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	return []string{"--script-args", `http.useragent="` + esc + `"`}
}

func targets(args map[string]any) []string { return subjects(args) }

// ------------------------------------------------------------- running
type execResult struct {
	stdout, stderr string
	code           int
	err            error
}

func runCmd(ctx context.Context, limit time.Duration, name string,
	argv ...string) execResult {

	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	// Running a scanner with arguments chosen per task is what a Ghost
	// is, so G204 cannot be designed out of this line. What is true
	// and what is not, written down rather than waved at:
	//
	// `name` is always a string literal at the call site — "nmap",
	// "masscan", "nuclei" and so on — never anything off the wire. The
	// argv slice goes to execve directly: there is no shell, so no
	// argument can become a second command, a pipe or a redirect
	// however it is spelled.
	//
	// The argv CONTENTS, though, include extraArgs(), which is
	// `strings.Fields(args["extra"])` passed through unvalidated from
	// the task. That is deliberate — operators need to hand flags to
	// their own scanners — and it means a server that can task this
	// agent can also pick nmap's flags, `--script` among them. So this
	// is not a boundary that holds against a hostile Oddjob; it is not
	// meant to be. The agent pins one server's key at enrollment and
	// treats tasking from it as trusted, which is the same trust that
	// lets a task say "install nuclei" or "scan this /8".
	//
	// Worth knowing, because `Known` in internal/tools is explicitly a
	// second gate against "one compromised server away from running
	// arbitrary installs". That gate is real for installs and there is
	// no equivalent for scanner flags. Narrowing this would mean an
	// allowlist of permitted flags per tool, which is a product
	// decision, not a lint fix.
	cmd := exec.CommandContext(ctx, name, argv...) //nolint:gosec // G204: name is a literal, no shell; argv intentionally carries operator-supplied flags — see above
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()

	r := execResult{stdout: out.String(), stderr: errb.String(), err: err}
	// errors.As, not a bare type assertion. cmd.Run() returns the
	// *ExitError unwrapped today, so the assertion happened to work —
	// but the moment anything between here and there wraps it, the
	// assertion stops matching and every tool that exited non-zero is
	// reported with code -1 instead of the code it actually gave. nmap
	// uses its exit codes to distinguish "host down" from "I crashed",
	// and losing that turns a real result into an unexplained failure.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.code = ee.ExitCode()
	} else if err != nil {
		r.code = -1
	}
	if ctx.Err() == context.DeadlineExceeded {
		r.err = fmt.Errorf("timed out after %s", limit)
	}
	return r
}

func timeout(args map[string]any, def time.Duration) time.Duration {
	if v, ok := args["timeout_seconds"]; ok {
		if f, ok := v.(float64); ok && f > 0 {
			return time.Duration(f) * time.Second
		}
	}
	return def
}

// outFile stages a tool's -o output. Tools that write XML to a file
// produce cleaner output than the same tool told to write to stdout,
// which interleaves progress chatter on some versions.
func outFile(workDir, kind, ext string) (string, func(), error) {
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return "", func() {}, err
	}
	f, err := os.CreateTemp(workDir, fmt.Sprintf("%s-*.%s", kind, ext))
	if err != nil {
		return "", func() {}, err
	}
	p := f.Name()
	_ = f.Close()
	return p, func() { _ = os.Remove(p) }, nil
}

func readOut(path string) string {
	b, err := os.ReadFile(path) // #nosec G304 — path is ours, from CreateTemp
	if err != nil {
		return ""
	}
	return string(b)
}

// nmapArgv builds the command line. Split out from runNmap because the
// flags have combinations nmap rejects outright, and the only way to
// know we have not reintroduced one is to assert on the argv without
// needing nmap, a network or root.
func nmapArgv(args map[string]any, outPath string, tg []string, rawSockets bool) []string {
	argv := []string{"-oX", outPath}
	ports := str(args, "ports")
	if ports != "" {
		argv = append(argv, "-p", ports)
	}

	// An explicit technique, when the server asked for one. Oddjob
	// tracks which of these has covered which port and only sends work
	// that would learn something new, so "do a -sT here" has to mean
	// exactly that.
	//
	// The trap this exists for: nmap's DEFAULT is -sS whenever it has
	// the privileges for it. Leaving the technique off and hoping for
	// a connect scan gets a syn scan on any root agent, which then
	// records syn coverage and leaves the -sT owed for ever.
	switch str(args, "technique") {
	case "syn":
		// Not degraded to a connect scan. Without raw sockets nmap
		// would quietly run -sT, which is a different scan that is
		// louder on the wire and answers a different question; the
		// caller asked for this one specifically. Refusing lets the
		// server hand it to an agent that can -- see runNmap.
		argv = append(argv, "-sS")
	case "connect":
		argv = append(argv, "-sT")
	case "version":
		// Discovery is left to nmap: -sS where it can, -sT otherwise.
		// Either is fine because -sV is the strongest level either
		// way, and letting it pick keeps the privileged case fast.
		argv = append(argv, "-sV")
	case "udp":
		// The ground nobody covers. Everything else this agent runs
		// is TCP, so SNMP, IPMI, NTP, mDNS and the rest are simply
		// not looked at -- which is exactly why they stay unclaimed.
		//
		// The commonest ports ONLY, and not negotiable upward by
		// accident. A full -sU sweep is both ruinously slow (nmap
		// rate-limits itself against ICMP unreachables) and mostly
		// noise: one 2,051-host sweep produced 42,890 open|filtered
		// rows against 13 genuinely open ports. The importer drops
		// non-open states, so that noise never reaches the database,
		// but the scan still has to be waited for.
		//
		// `--top-ports` and `-p` are mutually exclusive the way -F
		// and -p are, so the top list is only asked for when the
		// caller named no ports of their own.
		argv = append(argv, "-sU")
		if ports == "" {
			argv = append(argv, "--top-ports", UDPTopPorts)
		}
		// -sV on the few that answer. A UDP port with no service
		// behind the number is the same dead end as a TCP one.
		argv = append(argv, "-sV")
	default:
		// No technique named: the behaviour from before this existed.
		if str(args, "profile") == "quick" {
			argv = append(argv, "-T4")
			// -F and -p are mutually exclusive: nmap refuses the pair
			// rather than preferring one, exits 1, and writes an XML
			// file containing a successful-looking run of zero hosts.
			// Only ask for the fast list when no explicit ports were
			// given.
			if ports == "" {
				argv = append(argv, "-F")
			}
		}
		// -sV on BOTH paths, including `quick`.
		//
		// It used to be the else-branch only, so the quick profile
		// reported which ports were open and nothing whatever about
		// them. On the production estate that was 993 of 1,997 nmap
		// runs: the Services view held 2,033 rows carrying 11
		// versions and 49 banners between them, and every SSH service
		// on the estate had a blank product despite SSH announcing
		// itself in its first packet.
		//
		// It is still the cheap profile. -F limits the sweep to
		// nmap's hundred commonest ports and -sV then probes only the
		// ones that ANSWERED, which on a typical host is one or two.
		// A port scan that cannot say what is listening is most of
		// the cost of one that can and a fraction of the value.
		argv = append(argv, "-sV")
		// SYN only when we can actually do it. Asking for -sS without
		// raw sockets makes nmap fall back to a connect scan silently:
		// a different scan, louder on the wire, still labelled -sS in
		// the report.
		if rawSockets {
			argv = append(argv, "-sS")
		}
	}
	extra := extraArgs(args)
	// Scripts, whenever version detection is on.
	//
	// -sV asks what is listening; the script engine is what turns
	// that answer into something the rest of Oddjob can act on.
	// `pop3-capabilities` on 995 settles that the port is POP3S and
	// not, as the web classifier had been assuming of every TLS
	// port, an https server -- and the importer already stores every
	// script's output per service, so the evidence lands where it is
	// needed without a second scan.
	//
	// Only when the caller has not chosen their own set: a task that
	// says `--script ssl-cert` means that script, and nmap takes the
	// LAST --script on the line, so appending ours would silently
	// replace theirs.
	ownScripts := nseEnabled(extra)
	if !ownScripts && hasFlag(argv, "-sV") {
		argv = append(argv, "--script", NSEScripts)
	}
	// The User-Agent only reaches the wire through nmap's http NSE
	// scripts. Adding `--script-args` to a scan running no scripts
	// would be a flag on every command line that changes nothing, so
	// it is added only when something will read it -- which now
	// includes the set selected just above, not only a caller's.
	//
	// Skipped entirely when the caller set their own `--script-args`.
	// nmap takes the last occurrence and silently discards the
	// earlier one, so appending ours would quietly drop whatever
	// they wrote.
	if (ownScripts || hasFlag(argv, "--script")) && !hasFlag(extra, "--script-args") {
		argv = append(argv, nmapUserAgent(args)...)
	}
	argv = append(argv, extra...)
	return append(argv, tg...)
}

// NSEScripts is the script selection that rides with -sV.
//
// `default` is what -sC runs: the service-identifying scripts, which
// is the category that answers "what protocol is this really" --
// pop3-capabilities, imap-capabilities, smtp-commands, ssh2-enum-algos,
// ftp-syst, mysql-info, rdp-ntlm-info and the rest. Oddjob's importer
// keeps each script's output against the service it ran on, so these
// are what make a service record say more than a port number.
//
// `safe` adds the scripts nmap itself warrants as non-intrusive: they
// do not crash services, do not use significant resources and are not
// designed to be noticed. Cheap breadth.
//
// `ssl-cert` is named although `default` and `safe` both already
// include it. It is the single highest-value script on this
// engagement -- a certificate names every host it is valid for, and
// on a real estate that is the richest source of hostnames there is,
// frequently the only evidence that an address serves something we
// have no name for. Naming it means a future edit to the categories
// cannot drop it silently.
//
// `vuln` is the one to think about before changing. These are
// checks for known vulnerabilities, and nmap does not promise they
// are safe -- some probe for the bug rather than inferring it from a
// banner. On this engagement that is authorised ("full authority to
// test anything in scope"), and it is the category that turns a
// version string into a finding. Two things follow that are NOT
// handled here and are the operator's to watch: appliances are
// supposed to get low-volume fingerprinting only, and a scan with
// `vuln` on is materially slower -- the queue was already moving at
// roughly seven nmap tasks an hour.
const NSEScripts = "default,safe,vuln,ssl-cert"

// UDPTopPorts is how many of nmap's commonest UDP ports a `udp` task
// sweeps when the caller names none.
//
// Twenty, which is DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, SMB, IKE,
// syslog, RIP, IPP, SSDP and SQL Server browse -- the services that
// are actually found on an external estate and the ones nobody
// scans for. Past about this many the yield falls off a cliff while
// the runtime does not: nmap rate-limits itself against ICMP
// unreachables, so each extra port costs the same second whether or
// not anything is listening.
const UDPTopPorts = "20"

// nseEnabled reports whether these arguments turn the script engine
// on. `-A` implies `-sC`, which is why it counts.
func nseEnabled(extra []string) bool {
	for _, a := range extra {
		if a == "-A" || a == "-sC" || a == "--script" ||
			strings.HasPrefix(a, "--script=") {
			return true
		}
	}
	return false
}

// hasFlag reports whether any of `flags` appears in `extra`, bare or
// as `--flag=value`. Variadic because tools spell the same option two
// ways -- nuclei takes both `-c` and `-concurrency` -- and checking
// only one of them means an operator who wrote the long form gets
// silently overridden.
func hasFlag(extra []string, flags ...string) bool {
	for _, a := range extra {
		for _, flag := range flags {
			if a == flag || strings.HasPrefix(a, flag+"=") {
				return true
			}
		}
	}
	return false
}

// needsRawSockets reports whether this task cannot run unprivileged.
//
// Only -sS. -sT is the ordinary connect() syscall and -sV is probing
// over normal connections on top of whatever discovery ran, so an
// unprivileged agent can do both -- and, under Oddjob's ordering,
// therefore produces STRONGER coverage than a privileged one running
// the default -sS.
func needsRawSockets(args map[string]any) bool {
	// -sU is as privileged as -sS: nmap has to build the datagrams
	// and read the ICMP unreachables that are the whole signal. An
	// unprivileged -sU does not quietly downgrade to something
	// weaker, it fails -- so refusing here gives the server a chance
	// to hand the task to an agent that can run it, instead of
	// burning three attempts on one that cannot.
	t := str(args, "technique")
	return t == "syn" || t == "udp"
}

// --------------------------------------------------------------- nmap
func runNmap(ctx context.Context, args map[string]any, workDir string) Result {
	tg := targets(args)
	if len(tg) == 0 {
		return failed("nmap needs `targets`")
	}
	if tools.Path("nmap") == "" {
		return failed("nmap is not installed on this agent")
	}
	// An explicit -sS this agent cannot perform is refused rather than
	// quietly downgraded. nmap would run a connect scan instead and
	// report success, and Oddjob would record syn coverage for a scan
	// that never happened -- which suppresses the real one for good.
	if needsRawSockets(args) {
		if ok, advice := tools.RawSocketCapable(); !ok {
			return failed("a -sS scan needs raw sockets: %s", advice)
		}
	}
	path, cleanup, err := outFile(workDir, "nmap", "xml")
	if err != nil {
		return failed("staging output: %v", err)
	}
	defer cleanup()

	raw, _ := tools.RawSocketCapable()
	argv := nmapArgv(args, path, tg, raw)

	r := runCmd(ctx, timeout(args, 2*time.Hour), "nmap", argv...)
	xml := readOut(path)

	// nmap exits 0 for a scan that ran, even when nothing was up.
	// Non-zero means it did not run — a bad flag, a refused target, a
	// permission problem. Reporting that as `done` turns "we never
	// looked" into "we looked and found nothing", which is the one
	// mistake that makes a coverage report actively misleading.
	if r.code != 0 || r.err != nil {
		detail := firstLine(r.stderr)
		if detail == "" && r.err != nil {
			detail = r.err.Error()
		}
		return Result{Status: "failed", Output: xml, Stderr: tail(r.stderr, 4000),
			ExitCode: r.code,
			Error:    fmt.Sprintf("nmap did not complete: %s", detail)}
	}
	priv, advice := tools.RawSocketCapable()
	sum := fmt.Sprintf("nmap over %d target(s)", len(tg))
	if !priv {
		sum += " — unprivileged, connect scan: " + advice
	}
	return Result{Status: "done", Output: xml, Stderr: tail(r.stderr, 4000),
		Summary: sum, ExitCode: r.code}
}

// ------------------------------------------------------------ masscan
func runMasscan(ctx context.Context, args map[string]any, workDir string) Result {
	tg := targets(args)
	if len(tg) == 0 {
		return failed("masscan needs `targets`")
	}
	if tools.Path("masscan") == "" {
		return failed("masscan is not installed on this agent")
	}
	if ok, advice := tools.RawSocketCapable(); !ok {
		// masscan does not degrade; it builds its own packets or it
		// does nothing. Refusing beats a confusing crash.
		return failed("masscan needs raw sockets: %s", advice)
	}
	path, cleanup, err := outFile(workDir, "masscan", "xml")
	if err != nil {
		return failed("staging output: %v", err)
	}
	defer cleanup()

	ports := str(args, "ports")
	if ports == "" {
		ports = "80,443,8080,8443"
	}
	rate := str(args, "rate")
	if rate == "" {
		rate = "1000"
	}
	argv := []string{"-oX", path, "-p", ports, "--rate", rate}
	argv = append(argv, extraArgs(args)...)
	argv = append(argv, tg...)

	r := runCmd(ctx, timeout(args, 4*time.Hour), "masscan", argv...)
	xml := readOut(path)
	// Same reasoning as nmap: a scan that did not run is not a scan
	// that found nothing.
	if r.code != 0 || r.err != nil {
		detail := firstLine(r.stderr)
		if detail == "" && r.err != nil {
			detail = r.err.Error()
		}
		return Result{Status: "failed", Output: xml, Stderr: tail(r.stderr, 4000),
			ExitCode: r.code,
			Error:    fmt.Sprintf("masscan did not complete: %s", detail)}
	}
	return Result{Status: "done", Output: xml, Stderr: tail(r.stderr, 4000),
		Summary: fmt.Sprintf("masscan %s at %s/s over %d range(s)",
			ports, rate, len(tg)), ExitCode: r.code}
}

// -------------------------------------------------------------- amass
// The implementation moved to amass.go, which drives the v4 library in
// process instead of shelling out to whatever binary the host had. The
// task contract is unchanged: one domain, `mode`, and a JSON result of
// names under that zone.
func runAmass(ctx context.Context, args map[string]any, workDir string) Result {
	return runAmassLib(ctx, args, workDir)
}

// ------------------------------------------------------ nuclei, httpx

// Parallelism reports how many tasks this agent may run at once.
//
// A scanner sizing itself has to know it is sharing the host: three
// nuclei each sized as though they owned the box is exactly how a
// shared-core e2-micro reached a load average of 26 and dropped out
// of the fleet. Set by the agent once it has measured; 1 until then,
// which is the safe direction to be wrong in.
var Parallelism = func() int { return 1 }

// Where ghost/Dockerfile puts the nuclei template corpus.
//
// An override exists because an agent installed by hand -- `go
// install`, brew, choco -- has no image and therefore no bundled
// templates, and should be able to point at wherever it put them.
var nucleiTemplates = envOr("GHOST_NUCLEI_TEMPLATES", "/opt/nuclei-templates")

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// nucleiArgv builds the command line and reports how it was paced.
//
// Split out of runNuclei for the same reason nmapArgv is: the flags
// are the part worth asserting on, and asserting on them through a
// subprocess means a test that can only check what a stub happened
// to echo back. The first version of the pacing test did exactly
// that and could not tell "the operator's flag won" from "nothing
// was computed".
func nucleiArgv(ctx context.Context, tg []string,
	args map[string]any, path string) ([]string, string) {
	// `-irr` puts the request and the response in the JSONL.
	//
	// Without it nuclei says a template matched and not what was sent
	// or what came back, which makes a finding something to take on
	// trust rather than something to show. Medium-and-above findings
	// need a runnable proof; the exchange is where that starts.
	argv := []string{"-jsonl", "-o", path, "-silent", "-duc", "-irr"}
	// The templates, from the image rather than from $HOME.
	//
	// `-duc` above disables the update check, which also disables the
	// first-run install -- so without this nuclei has no templates at
	// all and exits 1 saying so. That is how 193 CVE scans came back
	// "done, 0 findings" against a live estate having sent nothing.
	// Named explicitly so the failure, if the path is ever wrong, is
	// a missing directory rather than a silent fallback to an empty
	// default.
	if _, err := os.Stat(nucleiTemplates); err == nil {
		argv = append(argv, "-t", nucleiTemplates)
	}
	argv = append(argv, headerArgs(args)...)
	for _, t := range tg {
		argv = append(argv, "-u", t)
	}
	extra := extraArgs(args)
	argv = append(argv, extra...)
	// Sized against THIS host, right now.
	//
	// nuclei's defaults are `-c 25` and `-rl 150` per process, which
	// is a reasonable guess for a workstation and flattens a
	// shared-core cloud instance. The agent is the only side that can
	// know which it is -- Oddjob knows the engagement's appetite, not
	// whether the scanner is a 32-core server or a quarter of a vCPU
	// -- so the number comes from cores, free memory and what the CPU
	// is doing at this moment.
	//
	// An operator who names either flag wins outright, PER FLAG: a
	// person who has looked at the box should not have to argue with
	// a heuristic, and overriding one should not silently discard the
	// other.
	paced := ""
	if p := capacity.Pace(ctx, Parallelism()); p.Concurrency > 0 {
		if !hasFlag(extra, "-c", "-concurrency") {
			argv = append(argv, "-c", strconv.Itoa(p.Concurrency))
		}
		if !hasFlag(extra, "-rl", "-rate-limit") {
			argv = append(argv, "-rl", strconv.Itoa(p.RateLimit))
		}
		paced = "; paced to " + p.Reason
	}
	return argv, paced
}

func runNuclei(ctx context.Context, args map[string]any, workDir string) Result {
	tg := targets(args)
	if len(tg) == 0 {
		return failed("nuclei needs `targets`")
	}
	if tools.Path("nuclei") == "" {
		return failed("nuclei is not installed on this agent")
	}
	path, cleanup, err := outFile(workDir, "nuclei", "jsonl")
	if err != nil {
		return failed("staging output: %v", err)
	}
	defer cleanup()
	// `-irr` puts the request and the response in the JSONL.
	//
	// Without it nuclei says a template matched and not what was sent
	// or what came back, which makes a finding something to take on
	// trust rather than something to show. Medium-and-above findings
	// need a runnable proof; the exchange is where that starts.
	argv, paced := nucleiArgv(ctx, tg, args, path)
	r := runCmd(ctx, timeout(args, 2*time.Hour), "nuclei", argv...)
	out := readOut(path)
	// A scanner that could not start has not examined anything.
	//
	// nuclei exits 0 whether or not it matched, so a non-zero code
	// means it did not run -- no templates, a bad flag, a target it
	// would not accept. Reporting that as `done` with zero findings
	// says "we looked and the estate is clean", which is a statement
	// about a client that nothing here is entitled to make. The
	// operator gets "this did not run" instead, and the URL stays
	// eligible to be tasked again.
	if r.code != 0 && out == "" {
		return failed("nuclei did not run (exit %d): %s",
			r.code, tail(r.stderr, 400))
	}
	return Result{Status: "done", Output: out, Stderr: tail(r.stderr, 4000),
		// The pacing rides in the summary rather than a log line.
		// This package does not log, and the ghost's global logger
		// is not dependable anyway -- katana kills it on first use.
		// An operator looking at a slow scan needs to see what it
		// was told to do, where they are already looking.
		Summary: fmt.Sprintf("nuclei over %d target(s), %d finding(s)%s",
			len(tg), countLines(out), paced),
		ExitCode: r.code}
}

func runHTTPX(ctx context.Context, args map[string]any, workDir string) Result {
	tg := targets(args)
	if len(tg) == 0 {
		return failed("httpx needs `targets`")
	}
	if tools.Path("httpx") == "" {
		return failed("httpx is not installed on this agent")
	}
	path, cleanup, err := outFile(workDir, "httpx", "jsonl")
	if err != nil {
		return failed("staging output: %v", err)
	}
	defer cleanup()
	// `-irr` likewise. httpx knows exactly what it sent and what came
	// back; reporting only that the address is alive throws away the
	// part a tester reads.
	//
	// `-cname` and `-tech-detect` are here because the importer has
	// always parsed `cname` and `tech` and httpx has never been asked
	// to emit them: both keys were simply absent from every line this
	// agent has ever sent. They cost nothing extra on the wire -- the
	// resolution and the response body have already happened by the
	// time httpx decides whether to report them.
	//
	// `-asn` is deliberately NOT here, though the importer parses that
	// too. httpx v1.12 resolves ASNs through ProjectDiscovery's hosted
	// service, so without a PDCP key the field comes back null, and
	// with one every address we look up is sent to a third party. The
	// server already carries GeoLite2-ASN and reads it locally, so the
	// answer is on our side of the wire already.
	argv := []string{"-json", "-o", path, "-silent", "-duc", "-irr",
		"-cname", "-tech-detect"}
	// The favicon mmh3 hash and the JARM fingerprint are the two that
	// pivot: they cluster hosts by what is running rather than by what
	// it is called, which finds estate nobody has attributed. They are
	// also the two that cost an extra round trip each -- a GET for the
	// icon and a set of TLS handshakes -- and the smallest ghost in the
	// fleet is a 458MB droplet that OOM-killed httpx during exactly
	// this probe. On by default because the pivot is the point; the
	// switch is here so a host that cannot afford them can say so
	// rather than failing the whole task.
	if boolOr(args, "fingerprint", true) {
		argv = append(argv, "-favicon", "-jarm")
	}
	argv = append(argv, headerArgs(args)...)
	for _, t := range tg {
		argv = append(argv, "-u", t)
	}
	argv = append(argv, extraArgs(args)...)
	r := runCmd(ctx, timeout(args, 60*time.Minute), "httpx", argv...)
	out := readOut(path)
	return Result{Status: "done", Output: out, Stderr: tail(r.stderr, 4000),
		Summary:  fmt.Sprintf("httpx over %d target(s), %d alive", len(tg), countLines(out)),
		ExitCode: r.code}
}

// ------------------------------------------------------------- lookups
func runNSLookup(ctx context.Context, args map[string]any, _ string) Result {
	qs := subjects(args, "queries", "query", "names", "name")
	if len(qs) == 0 {
		return failed("nslookup needs `targets` (or `query`/`queries`)")
	}
	out := make([]*recon.Lookup, 0, len(qs))
	resolved := 0
	for _, q := range qs {
		l := recon.NSLookup(ctx, q)
		if l.Error == "" {
			resolved++
		}
		out = append(out, l)
	}
	return Result{Status: "done", Output: recon.JSON(out),
		Summary: fmt.Sprintf("resolved %d of %d", resolved, len(qs))}
}

func runReverseIP(ctx context.Context, args map[string]any, _ string) Result {
	ips := subjects(args, "ips", "ip", "addresses", "address")
	if len(ips) == 0 {
		return failed("reverse_ip needs `targets` (or `ip`/`ips`)")
	}
	// Names the project already holds, for forward confirmation. DNS
	// cannot be asked "what points here"; it can only be asked
	// "where does this name point", so the only honest way to answer
	// the first question with DNS alone is to try the names we know.
	// Deliberately NOT subjects(): that folds in `targets`, which for
	// this task kind IS the list of addresses. Resolving an address
	// forward returns itself, and an address has dots in it, so every
	// IP would have been confirmed as its own "domain".
	candidates := append(list(args, "candidates"), list(args, "known_names")...)
	// Resolved once for the whole batch, not once per address: the
	// first cut did the latter and turned 1,500 names over 2,661
	// addresses into four million queries.
	index := recon.BuildNameIndex(ctx, candidates)

	out := make([]*recon.ReverseIP, 0, len(ips))
	total, partial := 0, false
	for _, ip := range ips {
		r := recon.ReverseIPLookup(ctx, ip, index)
		total += len(r.Domains)
		partial = partial || r.Partial
		out = append(out, r)
	}
	sum := fmt.Sprintf("%d domain(s) across %d address(es)", total, len(ips))
	if partial {
		sum += " — at least one source did not answer, so this is a floor"
	}
	return Result{Status: "done", Output: recon.JSON(out), Summary: sum}
}

// ------------------------------------------------------------ install
func runInstall(ctx context.Context, args map[string]any, _ string) Result {
	want := list(args, "tools")
	if len(want) == 0 {
		return failed("install needs a `tools` list")
	}
	reports := tools.Ensure(ctx, want, tools.Privileged())
	ok, bad := 0, 0
	for _, r := range reports {
		if r.Action == "failed" || r.Action == "unavailable" {
			bad++
		} else {
			ok++
		}
	}
	status := "done"
	if ok == 0 {
		status = "failed"
	}
	return Result{
		Status:  status,
		Output:  recon.JSON(reports),
		Summary: fmt.Sprintf("%d ready, %d could not be installed", ok, bad),
	}
}

// --------------------------------------------------------------- util
// hostnamesUnder keeps the lines that are actually names in the zone.
//
// Two filters, and the second is the one that matters: a line has to
// LOOK like a hostname, and it has to be under the domain we asked
// about. Tools print banners, counts, timings and apologies, and
// anything that survives this ends up in somebody's inventory as a
// host they will later try to scan.
func hostnamesUnder(lines []string, domain string) []string {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		n := strings.ToLower(strings.Trim(strings.TrimSpace(l), "."))
		// amass -nocolor still emits "name (FQDN) --> record --> value"
		// for some sources; the name is the first field.
		if i := strings.IndexAny(n, " \t"); i > 0 {
			n = n[:i]
		}
		if n == "" || !isHostname(n) {
			continue
		}
		if domain != "" && n != domain &&
			!strings.HasSuffix(n, "."+domain) {
			// A neighbouring zone is somebody else's estate. Dropped
			// here rather than relied on being refused later.
			continue
		}
		// Deduplicated AFTER normalising, not before: uniqueLines sees
		// raw text, so WWW.EXAMPLE.COM and www.example.com reach here
		// as two lines and would be counted as two names.
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// isHostname is deliberately strict: letters, digits, hyphen and dot,
// at least one dot, no leading or trailing separator, labels within
// length. Anything looser lets a sentence through.
func isHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// firstLine is what a person needs: tools put the actual reason on
// line one and a paragraph of usage after it.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Decode turns the server's JSON args into a map.
func Decode(raw json.RawMessage) map[string]any {
	m := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

var _ = filepath.Join
