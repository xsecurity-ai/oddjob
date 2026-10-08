package retire

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTombstoneSurvivesAndStops(t *testing.T) {
	dir := t.TempDir()

	if _, ok := Marked(dir); ok {
		t.Fatal("a fresh workdir must not look retired")
	}
	if err := Mark(dir, Tombstone{Reason: "killed from Oddjob",
		Removed: []string{"nuclei"}, Kept: []string{"nmap"}}); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	// The point of the file: a supervisor restarts the process and the
	// next start has to find this. Reading it from a different call,
	// with nothing held in memory, is that scenario.
	got, ok := Marked(dir)
	if !ok {
		t.Fatal("a retired ghost must still read as retired on the next start")
	}
	if got.Reason != "killed from Oddjob" {
		t.Errorf("reason = %q", got.Reason)
	}
	if len(got.Removed) != 1 || got.Removed[0] != "nuclei" {
		t.Errorf("removed = %v", got.Removed)
	}
	if got.At == "" {
		t.Error("a tombstone with no time cannot be reasoned about later")
	}

	if err := Unmark(dir); err != nil {
		t.Fatalf("Unmark: %v", err)
	}
	if _, ok := Marked(dir); ok {
		t.Error("revive must actually clear it")
	}
	// Unmark on a ghost that was never retired is a no-op, not an
	// error: `ghost revive` should be safe to run twice.
	if err := Unmark(dir); err != nil {
		t.Errorf("second Unmark: %v", err)
	}
}

func TestUnreadableTombstoneStillStops(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, tombstoneFile),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The file's existence is the signal; its contents are only the
	// explanation. A ghost that restarted because it could not parse
	// its own tombstone would be the worst possible failure here.
	tomb, ok := Marked(dir)
	if !ok {
		t.Fatal("an unreadable tombstone must still stop the ghost")
	}
	if tomb.Reason == "" {
		t.Error("it should still say something")
	}
}

func TestLedgerRecordsOnlyWhatWeInstalled(t *testing.T) {
	dir := t.TempDir()
	err := RecordInstalls(dir, []Entry{
		{Tool: "nuclei", Action: "installed", Via: "go", Path: "/root/go/bin/nuclei"},
		// Already on the host. Removing this on the way out would be a
		// worse trespass than leaving ours behind.
		{Tool: "nmap", Action: "present"},
		{Tool: "ffuf", Action: "failed"},
	})
	if err != nil {
		t.Fatalf("RecordInstalls: %v", err)
	}
	led, err := Ledger(dir)
	if err != nil {
		t.Fatalf("Ledger: %v", err)
	}
	if len(led) != 1 || led[0].Tool != "nuclei" {
		t.Fatalf("ledger = %+v, want only nuclei", led)
	}
	if led[0].Via != "go" || led[0].Path == "" {
		t.Errorf("how it was installed must be kept, got %+v", led[0])
	}
	if led[0].At == "" {
		t.Error("entries need a timestamp")
	}

	// A second baseline run must not duplicate it.
	if err := RecordInstalls(dir, []Entry{
		{Tool: "nuclei", Action: "installed", Via: "go"}}); err != nil {
		t.Fatal(err)
	}
	led, _ = Ledger(dir)
	if len(led) != 1 {
		t.Errorf("re-running the baseline duplicated entries: %+v", led)
	}
}

func TestLedgerOfAFreshHostIsEmptyNotAnError(t *testing.T) {
	led, err := Ledger(t.TempDir())
	if err != nil {
		t.Fatalf("a ghost that installed nothing is not an error: %v", err)
	}
	if len(led) != 0 {
		t.Errorf("led = %+v", led)
	}
}

func TestContactClockIsOnDisk(t *testing.T) {
	dir := t.TempDir()

	// Never contacted. The caller falls back to process start, so this
	// has to be distinguishable rather than "now".
	if got := LastContact(dir); !got.IsZero() {
		t.Errorf("no contact yet should be the zero time, got %v", got)
	}

	TouchContact(dir)
	got := LastContact(dir)
	if got.IsZero() {
		t.Fatal("contact was not recorded")
	}
	if d := time.Since(got); d > time.Minute || d < -time.Minute {
		t.Errorf("recorded contact is %v away from now", d)
	}

	// On disk is the whole point: a ghost crash-looping on a stranded
	// host would reset an in-memory clock on every start and never
	// time out. Reading it back with nothing in memory is that test.
	again := LastContact(dir)
	if !again.Equal(got) {
		t.Errorf("clock did not survive: %v then %v", got, again)
	}
}
