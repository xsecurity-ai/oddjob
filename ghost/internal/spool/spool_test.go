package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The whole reason this package exists: a scan finished, the process
// died before the result was delivered, and the result must still be
// there. "Dying" is modelled by dropping the Spool and opening the
// same directory again, which is exactly what a restart does.
func TestAResultSurvivesTheProcessThatMadeIt(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Begin(7, "nmap"); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(7, "done", "<nmaprun>...</nmaprun>", "", "1 host", 0, ""); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir) // the restart
	if err != nil {
		t.Fatal(err)
	}
	pending, err := again.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("got %d pending results after a restart, want 1", len(pending))
	}
	if pending[0].Output != "<nmaprun>...</nmaprun>" {
		t.Errorf("the scan output did not survive: %q", pending[0].Output)
	}
	if pending[0].TaskID != 7 || pending[0].Status != "done" {
		t.Errorf("entry came back wrong: %+v", pending[0])
	}
}

func TestDeliveredIsWhatClearsIt(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_ = s.Begin(1, "nmap")
	_ = s.Finish(1, "done", "out", "", "", 0, "")

	// A failed send must not clear it — that is the bug this guards.
	s.Attempted(1)
	if p, _ := s.Pending(); len(p) != 1 {
		t.Fatal("a failed delivery attempt dropped the result")
	}
	if p, _ := s.Pending(); p[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1", p[0].Attempts)
	}

	if err := s.Delivered(1); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(); len(p) != 0 {
		t.Error("an acknowledged result is still pending")
	}
}

func TestDeliveringTwiceIsNotAnError(t *testing.T) {
	// The drain can race an in-flight report. Clearing something that
	// is already gone is the expected outcome, not a failure.
	s, _ := Open(t.TempDir())
	if err := s.Delivered(999); err != nil {
		t.Errorf("clearing an absent entry: %v", err)
	}
}

func TestInterruptedWorkIsVisible(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_ = s.Begin(3, "masscan")
	_ = s.Begin(4, "nmap")
	_ = s.Finish(4, "done", "x", "", "", 0, "")

	again, _ := Open(dir)
	orphans, err := again.Orphaned()
	if err != nil {
		t.Fatal(err)
	}
	// 3 was running when we stopped; 4 had finished and is merely
	// undelivered. Conflating them would either lose a result or
	// report a completed scan as interrupted.
	if len(orphans) != 1 || orphans[0].TaskID != 3 {
		t.Fatalf("orphans = %+v, want just task 3", orphans)
	}
}

func TestResultsComeBackInOrder(t *testing.T) {
	s, _ := Open(t.TempDir())
	for _, id := range []int{30, 4, 100, 2} {
		_ = s.Begin(id, "nmap")
		_ = s.Finish(id, "done", "x", "", "", 0, "")
	}
	p, _ := s.Pending()
	var got []int
	for _, e := range p {
		got = append(got, e.TaskID)
	}
	// Numeric, not lexicographic: "task-100" sorts before "task-30" as
	// a filename, and delivering results wildly out of order makes a
	// timeline harder to read than it needs to be.
	want := []int{2, 4, 30, 100}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestACorruptEntryIsSetAsideNotFatal(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_ = s.Begin(1, "nmap")
	_ = s.Finish(1, "done", "good", "", "", 0, "")
	if err := os.WriteFile(filepath.Join(dir, "task-2.json"),
		[]byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := s.Pending()
	if err != nil {
		t.Fatalf("one bad file broke the whole spool: %v", err)
	}
	if len(p) != 1 || p[0].TaskID != 1 {
		t.Fatalf("the good entry was lost: %+v", p)
	}
	// Kept, not deleted: it is evidence of something going wrong.
	names, _ := filepath.Glob(filepath.Join(dir, "*.corrupt"))
	if len(names) != 1 {
		t.Errorf("the corrupt entry was not set aside: %v", names)
	}
}

func TestTheSpoolIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_ = s.Begin(1, "nmap")
	_ = s.Finish(1, "done", "client scan output", "", "", 0, "")

	// The spool holds raw scan output for someone else's estate. Any
	// local user being able to read it is a disclosure.
	st, err := os.Stat(filepath.Join(dir, "task-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("spool entry mode = %o, want 600", perm)
	}
}

func TestNoTemporaryFilesAreLeftBehind(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	_ = s.Begin(1, "nmap")
	_ = s.Finish(1, "done", strings.Repeat("x", 4096), "", "", 0, "")
	names, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(names) != 0 {
		t.Errorf("left temporary files behind: %v", names)
	}
}
