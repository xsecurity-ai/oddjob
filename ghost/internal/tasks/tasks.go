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
	"sort"
	"strconv"
	"strings"
	"time"

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
	"portscan":   runPortscan,
	"amass":      runAmass,
	"gobuster":   runGobuster,
	"gospider":   runGospider,
	"nuclei":     runNuclei,
	"httpx":      runHTTPX,
	"nslookup":   runNSLookup,
	"reverse_ip": runReverseIP,
	"install":    runInstall,
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
		} else {
			argv = append(argv, "-sV")
		}
		// SYN only when we can actually do it. Asking for -sS without
		// raw sockets makes nmap fall back to a connect scan silently:
		// a different scan, louder on the wire, still labelled -sS in
		// the report.
		if rawSockets {
			argv = append(argv, "-sS")
		}
	}
	argv = append(argv, extraArgs(args)...)
	return append(argv, tg...)
}

// needsRawSockets reports whether this task cannot run unprivileged.
//
// Only -sS. -sT is the ordinary connect() syscall and -sV is probing
// over normal connections on top of whatever discovery ran, so an
// unprivileged agent can do both -- and, under Oddjob's ordering,
// therefore produces STRONGER coverage than a privileged one running
// the default -sS.
func needsRawSockets(args map[string]any) bool {
	return str(args, "technique") == "syn"
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

// ----------------------------------------------------------- gospider
// gospider crawls a site and reports what it links to, including URLs
// it finds inside JavaScript. Run with -json so the output is parsed
// rather than scraped, and the URLs are pulled out into a plain list
// so the result is useful without knowing gospider's record shape.
func runGospider(ctx context.Context, args map[string]any, workDir string) Result {
	us := subjects(args, "url", "urls", "site", "sites")
	if len(us) == 0 {
		return failed("gospider needs `targets` (or `url`)")
	}
	if tools.Path("gospider") == "" {
		return failed("gospider is not installed on this agent")
	}

	depth := intOr(args, "depth", 2)
	concurrency := intOr(args, "concurrency", 5)
	argv := []string{"--json", "--quiet", "-d", strconv.Itoa(depth),
		"-c", strconv.Itoa(concurrency)}
	for _, u := range us {
		argv = append(argv, "-s", u)
	}
	// Off unless asked for. Following a link off the target is how a
	// crawl ends up touching something nobody authorised.
	if b, ok := args["subdomains"].(bool); ok && b {
		argv = append(argv, "--subs")
	}
	if b, ok := args["other_sources"].(bool); ok && b {
		// Pulls from the Wayback Machine, Common Crawl and friends:
		// third-party lookups, not traffic to the target.
		argv = append(argv, "--other-source")
	}
	argv = append(argv, extraArgs(args)...)

	r := runCmd(ctx, timeout(args, 45*time.Minute), "gospider", argv...)
	if r.code != 0 && strings.TrimSpace(r.stdout) == "" {
		return Result{Status: "failed", Stderr: tail(r.stderr, 4000),
			ExitCode: r.code,
			Error: fmt.Sprintf("gospider did not complete: %s",
				firstLine(r.stderr))}
	}

	type rec struct {
		Output string `json:"output"`
		Source string `json:"source"`
		Type   string `json:"type"`
		Status int    `json:"status"`
	}
	seen := map[string]bool{}
	urls := []string{}
	byType := map[string]int{}
	for _, line := range strings.Split(r.stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var x rec
		if json.Unmarshal([]byte(line), &x) != nil {
			continue
		}
		byType[x.Type]++
		u := strings.TrimSpace(x.Output)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		urls = append(urls, u)
	}
	sort.Strings(urls)

	return Result{
		Status: "done",
		Output: recon.JSON(map[string]any{
			"sites": us, "depth": depth, "urls": urls, "by_type": byType}),
		Stderr: tail(r.stderr, 4000),
		Summary: fmt.Sprintf("gospider: %d url(s) across %d site(s)",
			len(urls), len(us)),
		ExitCode: r.code,
	}
}

// ------------------------------------------------------ nuclei, httpx
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
	argv := []string{"-jsonl", "-o", path, "-silent", "-duc"}
	for _, t := range tg {
		argv = append(argv, "-u", t)
	}
	argv = append(argv, extraArgs(args)...)
	r := runCmd(ctx, timeout(args, 2*time.Hour), "nuclei", argv...)
	out := readOut(path)
	return Result{Status: "done", Output: out, Stderr: tail(r.stderr, 4000),
		Summary:  fmt.Sprintf("nuclei over %d target(s), %d finding(s)", len(tg), countLines(out)),
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
	argv := []string{"-json", "-o", path, "-silent", "-duc"}
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
