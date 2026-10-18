package tasks

import "testing"

// `fork/exec /usr/bin/nmap: operation not permitted` says nothing
// about capabilities, and every obvious reading of it is wrong: the
// process is root, the file is 0755, AppArmor and seccomp are off,
// and every other binary in the image execs fine. The cause is a
// file capability the container's bounding set cannot grant.
//
// Asserted because the message is the whole fix. A correct cap list
// nobody can find their way to is not much better than a wrong one.
func TestExplainExecNamesTheCapability(t *testing.T) {
	got := explainExec("fork/exec /usr/bin/nmap: operation not permitted")
	for _, want := range []string{
		"NET_BIND_SERVICE", // the flag to add
		"capabilit",        // what kind of problem it is
		"root does not help",
	} {
		if !contains(got, want) {
			t.Errorf("the explanation does not mention %q: %s", want, got)
		}
	}
}

// Everything else is passed through. An explanation bolted onto an
// unrelated failure is noise, and the next person learns to skip
// the whole sentence.
func TestExplainExecLeavesOtherFailuresAlone(t *testing.T) {
	for _, in := range []string{
		"Failed to resolve \"nope.invalid\".",
		"You requested a scan type which requires root privileges.",
		"",
	} {
		if got := explainExec(in); got != in {
			t.Errorf("explainExec rewrote an unrelated error: %q -> %q", in, got)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
