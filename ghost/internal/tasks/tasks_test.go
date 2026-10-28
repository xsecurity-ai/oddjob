package tasks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func has(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}

// The bug this guards: the quick profile appended -F unconditionally,
// so a task that also named ports produced `-p 22,80 -T4 -F`. nmap
// refuses that pair, exits 1, and still writes an XML file describing a
// finished run over zero hosts -- which imported cleanly as "scanned,
// nothing there".
func TestNmapArgvFastAndPortsAreExclusive(t *testing.T) {
	cases := []struct {
		name      string
		args      map[string]any
		wantF     bool
		wantP     bool
		wantSV    bool
		wantPorts string
	}{
		// wantSV is true on every row below. The quick profile used
		// to omit -sV, which left it reporting open ports and nothing
		// about them; see TestNmapArgvQuickStillDoesVersionDetection.
		{name: "quick with explicit ports drops -F",
			args:  map[string]any{"profile": "quick", "ports": "22,80,443"},
			wantF: false, wantP: true, wantPorts: "22,80,443",
			wantSV: true},
		{name: "quick with no ports keeps -F",
			args:  map[string]any{"profile": "quick"},
			wantF: true, wantP: false, wantSV: true},
		{name: "default profile does version detection, never -F",
			args:   map[string]any{},
			wantF:  false,
			wantSV: true},
		{name: "default profile with ports",
			args:      map[string]any{"ports": "8080"},
			wantF:     false,
			wantP:     true,
			wantSV:    true,
			wantPorts: "8080"},
		{name: "empty ports string is not an explicit port selection",
			args:  map[string]any{"profile": "quick", "ports": "   "},
			wantF: true, wantP: false, wantSV: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			argv := nmapArgv(c.args, "/tmp/o.xml", []string{"example.org"}, false)
			if got := has(argv, "-F"); got != c.wantF {
				t.Errorf("-F present = %v, want %v (argv %v)", got, c.wantF, argv)
			}
			if got := has(argv, "-p"); got != c.wantP {
				t.Errorf("-p present = %v, want %v (argv %v)", got, c.wantP, argv)
			}
			if got := has(argv, "-sV"); got != c.wantSV {
				t.Errorf("-sV present = %v, want %v (argv %v)", got, c.wantSV, argv)
			}
			if has(argv, "-F") && has(argv, "-p") {
				t.Fatalf("nmap refuses -F with -p; argv %v", argv)
			}
			if c.wantPorts != "" {
				joined := strings.Join(argv, " ")
				if !strings.Contains(joined, "-p "+c.wantPorts) {
					t.Errorf("ports not passed through: %v", argv)
				}
			}
		})
	}
}

func TestNmapArgvSYNOnlyWhenPrivileged(t *testing.T) {
	if argv := nmapArgv(map[string]any{}, "/tmp/o.xml", []string{"h"}, false); has(argv, "-sS") {
		t.Errorf("asked for -sS without raw sockets: %v", argv)
	}
	if argv := nmapArgv(map[string]any{}, "/tmp/o.xml", []string{"h"}, true); !has(argv, "-sS") {
		t.Errorf("did not use -sS despite raw sockets: %v", argv)
	}
}

func TestNmapArgvTargetsComeLast(t *testing.T) {
	argv := nmapArgv(map[string]any{"ports": "80"}, "/tmp/o.xml",
		[]string{"a.example", "b.example"}, false)
	if argv[len(argv)-2] != "a.example" || argv[len(argv)-1] != "b.example" {
		t.Errorf("targets must be the trailing operands: %v", argv)
	}
}

// Every runner takes `targets` as well as its own tool's name for the
// same thing, so an operator who learns the shape once can use it
// everywhere instead of getting a hard error from the next task kind.
func TestSubjectsAcceptsTargetsEverywhere(t *testing.T) {
	cases := []struct {
		name  string
		args  map[string]any
		names []string
		want  []string
	}{
		{"targets list", map[string]any{"targets": []any{"a", "b"}}, nil, []string{"a", "b"}},
		{"target singular", map[string]any{"target": "a"}, nil, []string{"a"}},
		{"space separated string", map[string]any{"targets": "a b"}, nil, []string{"a", "b"}},
		{"native name still works",
			map[string]any{"queries": []any{"a"}}, []string{"queries", "query"}, []string{"a"}},
		{"native singular still works",
			map[string]any{"query": "a"}, []string{"queries", "query"}, []string{"a"}},
		{"targets works for a lookup runner",
			map[string]any{"targets": []any{"a"}}, []string{"queries", "query"}, []string{"a"}},
		{"both given, native first, no duplicate",
			map[string]any{"query": "a", "targets": []any{"a", "b"}},
			[]string{"queries", "query"}, []string{"a", "b"}},
		{"blank entries dropped",
			map[string]any{"targets": []any{"a", "", "  ", "b"}}, nil, []string{"a", "b"}},
		{"nothing at all", map[string]any{}, []string{"queries"}, []string{}},
		{"wrong type is not a subject", map[string]any{"targets": 42}, nil, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := subjects(c.args, c.names...)
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestFirstLineTakesTheReasonNotTheUsage(t *testing.T) {
	in := "You cannot use -F (fast scan) with -p (explicit port selection)\n" +
		"but see --top-ports and --port-ratio\nQUITTING!\n"
	want := "You cannot use -F (fast scan) with -p (explicit port selection)"
	if got := firstLine(in); got != want {
		t.Errorf("firstLine() = %q, want %q", got, want)
	}
	if got := firstLine("  only one line  "); got != "only one line" {
		t.Errorf("single line not trimmed: %q", got)
	}
	if got := firstLine(""); got != "" {
		t.Errorf("empty should stay empty: %q", got)
	}
}

// A runner that shells out to a tool reports what the tool did. These
// are the kinds that refuse before running at all, which is the half we
// can assert on without the tool installed.
func TestRunnersRefuseAnEmptySubject(t *testing.T) {
	for _, kind := range []string{"nmap", "masscan", "amass", "gobuster",
		"katana", "nuclei", "httpx", "nslookup", "reverse_ip"} {
		run, ok := Runners[kind]
		if !ok {
			t.Fatalf("no runner registered for %q", kind)
		}
		res := run(t.Context(), map[string]any{}, t.TempDir())
		if res.Status != "failed" {
			t.Errorf("%s with no subject: status %q, want failed", kind, res.Status)
		}
		// The message has to name a key the operator can actually set.
		if !strings.Contains(res.Error, "targets") {
			t.Errorf("%s error does not mention `targets`: %q", kind, res.Error)
		}
	}
}

func TestAmassAndGobusterRefuseMoreThanOneSubject(t *testing.T) {
	for _, kind := range []string{"amass", "gobuster"} {
		res := Runners[kind](t.Context(),
			map[string]any{"targets": []any{"a.example", "b.example"}}, t.TempDir())
		if res.Status != "failed" || !strings.Contains(res.Error, "one task each") {
			t.Errorf("%s took two subjects silently: %q / %q",
				kind, res.Status, res.Error)
		}
	}
}

// An explicit technique must produce exactly that scan, because
// Oddjob records what ran and will not send the work again.
//
// The case that matters most is `connect` on a PRIVILEGED agent:
// nmap's default is -sS wherever it can, so omitting -sT would run a
// syn scan, record syn coverage, and leave the -sT owed for ever.
func TestNmapTechnique(t *testing.T) {
	cases := []struct {
		name      string
		technique string
		raw       bool
		want      string
		notWant   string
	}{
		{"syn asks for -sS", "syn", true, "-sS", "-sT"},
		{"connect asks for -sT", "connect", false, "-sT", "-sS"},
		// The trap: privileged, and still must be -sT.
		{"connect on a root agent is still -sT", "connect", true, "-sT", "-sS"},
		{"version asks for -sV", "version", false, "-sV", ""},
		{"version on a root agent is still -sV", "version", true, "-sV", ""},
		// UDP is a different protocol, not a weaker TCP scan, so it
		// must never pick up a TCP technique on the way through.
		{"udp asks for -sU", "udp", true, "-sU", "-sS"},
		{"udp does not become a connect scan unprivileged", "udp", false, "-sU", "-sT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			argv := nmapArgv(map[string]any{"technique": c.technique},
				"/tmp/o.xml", []string{"h"}, c.raw)
			if !has(argv, c.want) {
				t.Errorf("technique %q gave %v, wanted %s", c.technique, argv, c.want)
			}
			if c.notWant != "" && has(argv, c.notWant) {
				t.Errorf("technique %q also passed %s: %v",
					c.technique, c.notWant, argv)
			}
		})
	}

	// No technique named keeps the old behaviour exactly.
	if argv := nmapArgv(map[string]any{}, "/tmp/o.xml", []string{"h"}, true); !has(argv, "-sS") {
		t.Errorf("with no technique a privileged agent should still -sS: %v", argv)
	}
	if argv := nmapArgv(map[string]any{"profile": "quick"}, "/tmp/o.xml",
		[]string{"h"}, false); !has(argv, "-F") {
		t.Errorf("the quick profile still means -F: %v", argv)
	}
}

// Only -sS needs the privilege. Getting this wrong the other way
// would idle every unprivileged agent on work it can perfectly well
// do -- and which produces stronger coverage than -sS does.
func TestOnlySynNeedsRawSockets(t *testing.T) {
	for _, tc := range []struct {
		technique string
		want      bool
	}{
		{"syn", true},
		{"connect", false},
		{"version", false},
		{"", false},
	} {
		if got := needsRawSockets(map[string]any{"technique": tc.technique}); got != tc.want {
			t.Errorf("needsRawSockets(%q) = %v, want %v", tc.technique, got, tc.want)
		}
	}
}

// The `full` standing-order profile, as the server actually sends it.
//
// The pairing is the point: `--script ssl-cert` arrives in `extra`,
// and `extra` is also what `nseEnabled` watches to decide whether a
// User-Agent is worth setting. Asserting the whole argv here means a
// change to either half shows up as a failure rather than as a scan
// that quietly stops collecting certificates.
func TestNmapArgvFullProfileAsksForTheCertificate(t *testing.T) {
	// Mirrors automation.NMAP_PROFILES["full"].
	args := map[string]any{"ports": "1-65535", "extra": "--script ssl-cert"}
	argv := nmapArgv(args, "/tmp/o.xml", []string{"h.example"}, false)
	joined := strings.Join(argv, " ")

	if !strings.Contains(joined, "--script ssl-cert") {
		t.Errorf("the script was not passed to nmap: %v", argv)
	}
	if !strings.Contains(joined, "-p 1-65535") {
		t.Errorf("the full port range was lost: %v", argv)
	}
	// -F and -p together make nmap exit 1 while still writing a
	// successful-looking XML file of zero hosts.
	if has(argv, "-F") {
		t.Fatalf("nmap refuses -F with -p; argv %v", argv)
	}
	if !has(argv, "-sV") {
		t.Errorf("full profile lost version detection: %v", argv)
	}
	// A script is running, so the attribution argument is worth
	// setting and should now be present.
	if !strings.Contains(joined, "--script-args") {
		t.Errorf("NSE is on but no user agent was set: %v", argv)
	}
	if argv[len(argv)-1] != "h.example" {
		t.Errorf("targets must be the trailing operands: %v", argv)
	}
}

// Scripts ride with -sV, on every profile that does version
// detection -- which, since the quick profile gained -sV, is all of
// them.
//
// This test used to assert the opposite: `top100` was the cheap
// option and a TLS handshake per port was held to change what that
// choice meant. The trade was re-made deliberately. A port scan that
// says "995/tcp open" and nothing more is most of the cost of one
// that says "POP3S, Dovecot, these capabilities" and a fraction of
// the value -- and without the script output the service classifier
// had been calling every TLS port a web server and sending content
// discovery at mail and database ports.
//
// The cost is real and is not hidden: `vuln` in particular makes a
// scan materially slower. It is the operator's trade, taken on an
// engagement with authority to make it.
func TestNmapArgvScriptsRideWithVersionDetection(t *testing.T) {
	for _, profile := range []string{"quick", "full", ""} {
		args := map[string]any{}
		if profile != "" {
			args["profile"] = profile
		}
		argv := nmapArgv(args, "/tmp/o.xml", []string{"h.example"}, false)
		joined := strings.Join(argv, " ")
		if !has(argv, "-sV") {
			t.Fatalf("profile %q lost version detection: %v", profile, argv)
		}
		if !strings.Contains(joined, "--script "+NSEScripts) {
			t.Errorf("profile %q does not run the scripts: %v", profile, argv)
		}
		// The UA matters only because scripts are now running; a
		// scan that reaches a client's web server must say who it
		// is, and nmap's default announces the scripting engine.
		if !strings.Contains(joined, "--script-args") {
			t.Errorf("profile %q runs scripts unattributed: %v", profile, argv)
		}
	}
}

// ssl-cert must be in the set, not merely implied by `default` and
// `safe` containing it. It is the richest source of hostnames on the
// estate, the `full` profile used to ask for it by name, and that
// line was removed precisely because naming it there SUPPRESSED
// everything else. If a future edit narrows the categories, this is
// what says so.
func TestNSEScriptsKeepsTheCertificate(t *testing.T) {
	if !strings.Contains(NSEScripts, "ssl-cert") {
		t.Fatalf("ssl-cert is not in the script set: %q", NSEScripts)
	}
	argv := nmapArgv(map[string]any{"ports": "1-65535"}, "/tmp/o.xml",
		[]string{"h.example"}, false)
	if !strings.Contains(strings.Join(argv, " "), "ssl-cert") {
		t.Errorf("the full-style scan does not collect certificates: %v", argv)
	}
}

// ssl-enum-ciphers is in NEITHER `default` nor `safe` -- nmap files
// it under `discovery, intrusive` -- so it runs only while it is
// named here. Without it Oddjob can say which hosts speak TLS and
// nothing at all about whether that TLS is any good, which is the
// state it was in: no cipher list, no protocol versions, no grade.
//
// Asserted separately from ssl-cert because the two are dropped by
// different mistakes. ssl-cert survives a category narrowing by
// accident, being in both; this one does not survive anything.
func TestNSEScriptsAnalysesTheTLS(t *testing.T) {
	for _, want := range []string{
		"ssl-enum-ciphers",
		// Both are in `default` already. Named anyway, because what
		// they report -- SMB signing not required, which is what
		// makes a relay attack work -- is now read as a finding, and
		// a category edit must not be able to remove it quietly.
		"smb-security-mode", "smb2-security-mode",
	} {
		if !strings.Contains(NSEScripts, want) {
			t.Errorf("%s is not in the script set: %q", want, NSEScripts)
		}
	}
	argv := nmapArgv(map[string]any{}, "/tmp/o.xml",
		[]string{"h.example"}, false)
	if !strings.Contains(strings.Join(argv, " "), "ssl-enum-ciphers") {
		t.Errorf("an ordinary scan does not analyse TLS: %v", argv)
	}
}

// A caller who named their own scripts keeps them. nmap honours the
// LAST --script on the line, so appending ours would silently replace
// theirs -- and the `full` profile asks for `ssl-cert` by name, which
// is where every hostname in a certificate comes from.
func TestNmapArgvDoesNotOverrideAChosenScript(t *testing.T) {
	argv := nmapArgv(map[string]any{"extra": "--script ssl-cert"},
		"/tmp/o.xml", []string{"h.example"}, false)
	joined := strings.Join(argv, " ")
	if strings.Contains(joined, NSEScripts) {
		t.Errorf("the caller's script selection was overridden: %v", argv)
	}
	if !strings.Contains(joined, "--script ssl-cert") {
		t.Errorf("the caller's script was lost: %v", argv)
	}
	if strings.Count(joined, "--script ") != 1 {
		t.Errorf("more than one --script on the line: %v", argv)
	}
}

// The quick profile must still ask what is listening.
//
// It did not, and that single missing flag is why the production
// Services view held 2,033 services carrying 11 versions between
// them: half the estate was swept with -T4 -F -sS and never probed.
func TestNmapArgvQuickStillDoesVersionDetection(t *testing.T) {
	argv := nmapArgv(map[string]any{"profile": "quick"}, "/tmp/o.xml",
		[]string{"h.example"}, false)
	if !has(argv, "-sV") {
		t.Errorf("quick profile does not identify services: %v", argv)
	}
	// Still the cheap one: -F keeps it to nmap's hundred commonest
	// ports, and -sV only probes the ones that answered.
	if !has(argv, "-F") {
		t.Errorf("quick profile stopped being quick: %v", argv)
	}
	if has(argv, "-F") && has(argv, "-p") {
		t.Fatalf("nmap refuses -F with -p; argv %v", argv)
	}
}

// A scanner that could not start has not examined anything.
//
// nuclei exits 0 whether or not it matched, so a non-zero code means
// it did not run. On a live estate this surfaced as 193 completed CVE
// scans reporting "0 findings" while nuclei was exiting 1 with "no
// templates provided for scan" -- the image shipped the binary and
// not the 86MB of templates, and the task said `done`. Reporting that
// as done asserts a client's estate is clean on the strength of our
// own scanner failing to launch.
func TestNucleiFailsWhenItCouldNotRun(t *testing.T) {
	dir := t.TempDir()
	// A `nuclei` that exits non-zero and writes nothing, which is
	// exactly what the real one does with no templates.
	//
	// `false` rather than a script written here: an executable stub
	// would need a mode gosec refuses on both WriteFile (G306) and
	// Chmod (G302), and suppressing a file-permission check to get a
	// test to run is the wrong trade. `false` is already on the box
	// and already does the one thing this needs.
	falseBin, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no `false` on this box to stand in for a broken nuclei")
	}
	if err := os.Symlink(falseBin, filepath.Join(dir, "nuclei")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res := Runners["nuclei"](t.Context(),
		map[string]any{"targets": []any{"https://a.acme.example/"}}, t.TempDir())

	if res.Status != "failed" {
		t.Errorf("status %q, want failed — a scanner that did not start "+
			"must not report a clean run", res.Status)
	}
	if !strings.Contains(res.Error, "did not run") {
		t.Errorf("error does not say it did not run: %q", res.Error)
	}
	// The operator needs to know WHY, or the next step is guesswork.
	// The exit code is the part always available; nuclei's own stderr
	// rides along with it when there is any.
	if !strings.Contains(res.Error, "exit 1") {
		t.Errorf("error does not name the exit code: %q", res.Error)
	}
}

// The templates come from the image, and the path is overridable for
// an agent installed by hand that has no image.
func TestNucleiTemplateDirIsOverridable(t *testing.T) {
	if got := envOr("GHOST_NUCLEI_TEMPLATES_UNSET_FOR_TEST", "/opt/x"); got != "/opt/x" {
		t.Errorf("fallback not used: %q", got)
	}
	t.Setenv("GHOST_NUCLEI_TEMPLATES_SET_FOR_TEST", "/elsewhere")
	if got := envOr("GHOST_NUCLEI_TEMPLATES_SET_FOR_TEST", "/opt/x"); got != "/elsewhere" {
		t.Errorf("override ignored: %q", got)
	}
}

// The agent sizes nuclei against the host, and an operator who names
// a flag wins outright -- PER FLAG, so overriding one does not
// silently discard the other.
//
// Asserted on the argv rather than through a subprocess. The first
// version of this test ran a stub and looked at the Result, which
// could not tell "the operator's flag won" from "nothing was
// computed at all" -- it passed one case and failed four for the
// same reason.
func TestNucleiPacingYieldsToTheOperatorPerFlag(t *testing.T) {
	for _, c := range []struct {
		name      string
		extra     string
		wantOurC  bool
		wantOurRL bool
	}{
		{"nothing named: we size both", "", true, true},
		{"operator sets -c: we still set the rate", "-c 40", false, true},
		{"operator sets -rl: we still set concurrency", "-rl 500", true, false},
		{"operator sets both: we set neither", "-c 40 -rl 500", false, false},
		// The long spellings are the same flags. Checking only the
		// short form means an operator who wrote `-concurrency` is
		// silently overridden by the heuristic.
		{"long spellings count too", "-concurrency 40 -rate-limit 500", false, false},
	} {
		argv, paced := nucleiArgv(t.Context(), []string{"https://a.acme.example/"},
			map[string]any{"extra": c.extra}, "/tmp/out.jsonl")
		if paced == "" {
			t.Errorf("%s: no pacing was computed", c.name)
			continue
		}
		// Ours is appended AFTER the operator's, so counting
		// occurrences is what distinguishes "we deferred" from "we
		// appended a second one".
		// Counting occurrences cannot tell ours from theirs -- both
		// give one. The VALUE can: the operator's 40 and 500 are
		// both above anything this sizer will ever produce, since
		// it never exceeds nuclei's own defaults.
		assertFlag(t, c.name, argv, "-c", "40", c.wantOurC)
		assertFlag(t, c.name, argv, "-rl", "500", c.wantOurRL)
	}
}

// assertFlag checks whose value ended up on the command line.
//
// `ours` true means the sizer supplied it: the flag is present and
// its value is not the operator's. `ours` false means we deferred:
// either the flag is absent entirely (the operator used the long
// spelling) or it carries the operator's own value.
func assertFlag(t *testing.T, name string, argv []string,
	flag, operatorValue string, ours bool) {
	t.Helper()
	got, found := valueOf(argv, flag)
	switch {
	case ours && !found:
		t.Errorf("%s: %s missing — the sizer did not supply it", name, flag)
	case ours && got == operatorValue:
		t.Errorf("%s: %s is the operator's %q, not a sized value",
			name, flag, got)
	case !ours && found && got != operatorValue:
		t.Errorf("%s: %s is %q — the sizer overrode the operator",
			name, flag, got)
	}
}

func valueOf(argv []string, flag string) (string, bool) {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1], true
		}
	}
	return "", false
}

// hasFlag has to see both spellings of the same option.
func TestHasFlagMatchesEverySpelling(t *testing.T) {
	extra := []string{"-concurrency", "40"}
	if !hasFlag(extra, "-c", "-concurrency") {
		t.Error("long spelling not matched")
	}
	if hasFlag([]string{"-rl", "20"}, "-c", "-concurrency") {
		t.Error("matched an unrelated flag")
	}
	if !hasFlag([]string{"-c=40"}, "-c", "-concurrency") {
		t.Error("`-c=40` form not matched")
	}
}

func TestNmapUDPTopPortsOnlyWithoutExplicitPorts(t *testing.T) {
	// --top-ports and -p are mutually exclusive the same way -F and
	// -p are: nmap refuses the pair, exits non-zero, and still writes
	// an XML file that imports as a finished scan over nothing. That
	// bug has shipped here once already with -F.
	argv := nmapArgv(map[string]any{"technique": "udp"},
		"/tmp/o.xml", []string{"h"}, true)
	if !has(argv, "--top-ports") {
		t.Errorf("a udp scan with no ports should sweep the top list: %v", argv)
	}
	if !has(argv, "-sV") {
		t.Errorf("a udp scan should still ask what answered: %v", argv)
	}

	argv = nmapArgv(map[string]any{"technique": "udp", "ports": "161,500"},
		"/tmp/o.xml", []string{"h"}, true)
	if has(argv, "--top-ports") {
		t.Errorf("explicit ports must suppress --top-ports: %v", argv)
	}
	if !has(argv, "-p") {
		t.Errorf("explicit ports should still be passed: %v", argv)
	}
}

func TestUDPNeedsRawSockets(t *testing.T) {
	// nmap does not fall back to anything for -sU; it fails. Saying so
	// up front lets the server hand the task to an agent that can run
	// it rather than spending three attempts on one that cannot.
	if !needsRawSockets(map[string]any{"technique": "udp"}) {
		t.Error("a udp scan should be refused on an unprivileged agent")
	}
	if needsRawSockets(map[string]any{"technique": "connect"}) {
		t.Error("a connect scan needs no raw sockets")
	}
}
