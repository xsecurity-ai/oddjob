package tasks

import (
	"strings"
	"testing"
)

// The engagement sets this so the client's own logs can answer who was
// scanning them. The cases that matter are not the happy one.
func TestUserAgent(t *testing.T) {
	for _, c := range []struct {
		name string
		in   any
		want string
	}{
		{"absent falls back to the attributable default", nil, defaultUserAgent},
		{"empty falls back too", "", defaultUserAgent},
		{"whitespace is not a user agent", "   ", defaultUserAgent},
		{"a real one is used", "Acme Security (authorised)",
			"Acme Security (authorised)"},
		{"surrounding space is trimmed", "  Acme  ", "Acme"},
	} {
		args := map[string]any{}
		if c.in != nil {
			args["user_agent"] = c.in
		}
		if got := userAgent(args); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// A CR or an LF ends the header early and begins another one. That is
// request splitting, aimed at the client's own infrastructure, from a
// field an operator types into a web form.
//
// The server validates this too. This is the agent refusing to trust
// that, because the agent is what actually writes the header.
func TestUserAgentCannotInjectAHeader(t *testing.T) {
	for _, bad := range []string{
		"Acme\r\nX-Forwarded-For: 127.0.0.1",
		"Acme\nX-Injected: yes",
		"Acme\rX-Injected: yes",
		"Acme\x00truncated",
		"Acme\x7Fdel",
	} {
		got := userAgent(map[string]any{"user_agent": bad})
		if strings.ContainsAny(got, "\r\n\x00") {
			t.Errorf("%q survived as %q — a header can be injected", bad, got)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7F {
				t.Errorf("%q left control byte %q in %q", bad, r, got)
			}
		}
	}
	// Not vacuous: the surviving text is still the attribution, not an
	// empty string. Dropping the whole value on one stray byte would
	// lose the attribution the setting exists to provide.
	got := userAgent(map[string]any{"user_agent": "Acme\nSecurity"})
	if !strings.Contains(got, "Acme") || !strings.Contains(got, "Security") {
		t.Errorf("sanitising threw away the attribution: %q", got)
	}
}

// nuclei and httpx spell it identically, which is why one function
// builds it for both.
func TestHeaderArgs(t *testing.T) {
	got := headerArgs(map[string]any{"user_agent": "Acme (authorised)"})
	if len(got) != 2 || got[0] != "-H" {
		t.Fatalf("not an -H pair: %v", got)
	}
	if got[1] != "User-Agent: Acme (authorised)" {
		t.Errorf("header value is %q", got[1])
	}
}

// nmap parses --script-args itself and splits on commas, so a real
// engagement string with a comma in it has to survive quoting.
func TestNmapUserAgentQuoting(t *testing.T) {
	got := nmapUserAgent(map[string]any{
		"user_agent": `Acme, authorised "test"\x`})
	if len(got) != 2 || got[0] != "--script-args" {
		t.Fatalf("not a --script-args pair: %v", got)
	}
	v := got[1]
	if !strings.HasPrefix(v, `http.useragent="`) || !strings.HasSuffix(v, `"`) {
		t.Errorf("value is not a quoted script-arg: %q", v)
	}
	// The comma must be inside the quotes, not splitting the argument.
	if !strings.Contains(v, "Acme, authorised") {
		t.Errorf("the comma did not survive: %q", v)
	}
	// Inner quotes escaped, or they close the string early and nmap
	// reads the rest as another argument.
	if strings.Contains(v, `"test"`) {
		t.Errorf("inner quotes were not escaped: %q", v)
	}
	if !strings.Contains(v, `\"test\"`) {
		t.Errorf("inner quotes not escaped as expected: %q", v)
	}
}

// The flag is only worth sending when something will read it.
func TestNmapOnlySetsTheAgentWhenScriptsRun(t *testing.T) {
	args := map[string]any{"user_agent": "Acme", "technique": "connect"}

	plain := nmapArgv(args, "/tmp/o.xml", []string{"h.example"}, false)
	if hasFlag(plain, "--script-args") {
		t.Errorf("script-args sent to a scan running no scripts: %v", plain)
	}

	for _, on := range []string{"-A", "-sC", "--script=http-title"} {
		withNSE := nmapArgv(map[string]any{
			"user_agent": "Acme", "technique": "connect", "extra": on,
		}, "/tmp/o.xml", []string{"h.example"}, false)
		if !hasFlag(withNSE, "--script-args") {
			t.Errorf("%s runs scripts but got no user agent: %v", on, withNSE)
		}
	}

	// An operator's own --script-args wins. nmap keeps only the last
	// occurrence, so appending ours would silently discard theirs.
	mine := nmapArgv(map[string]any{
		"user_agent": "Acme", "technique": "connect",
		"extra": "-sC --script-args http.max-cache-size=1000",
	}, "/tmp/o.xml", []string{"h.example"}, false)
	n := 0
	for _, a := range mine {
		if a == "--script-args" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected the operator's single --script-args, got %d: %v",
			n, mine)
	}
	if !strings.Contains(strings.Join(mine, " "), "http.max-cache-size") {
		t.Errorf("the operator's script-args was dropped: %v", mine)
	}
}
