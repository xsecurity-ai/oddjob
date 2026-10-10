package tasks

import (
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
		{name: "quick with explicit ports drops -F",
			args:  map[string]any{"profile": "quick", "ports": "22,80,443"},
			wantF: false, wantP: true, wantPorts: "22,80,443"},
		{name: "quick with no ports keeps -F",
			args:  map[string]any{"profile": "quick"},
			wantF: true, wantP: false},
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
			wantF: true, wantP: false},
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
		"gospider", "nuclei", "httpx", "nslookup", "reverse_ip"} {
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
