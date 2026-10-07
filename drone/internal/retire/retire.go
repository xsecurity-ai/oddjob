// Package retire holds the three pieces of state a Drone needs in
// order to take itself off a host and stay off it.
//
// All three live in the work directory, which is the one place that is
// a Docker volume, survives a container restart, and is already where
// the identity and the spool live.
//
//	installed.json  what this Drone installed, so it can undo exactly
//	                that and nothing a sysadmin put there first
//	contact.json    when the server was last reached, so the dead-man
//	                switch cannot be reset by crash-looping
//	retired.json    the tombstone: this Drone is finished
//
// The tombstone is the part that is easy to leave out and the part
// that actually matters. A Drone told to stop exits, and
// `--restart unless-stopped` starts it again four seconds later: exit
// status 0 is not "do not come back" to Docker, systemd, or anything
// else that supervises. Without a mark on disk, "kill this drone" is
// a four-second pause.
package retire

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	ledgerFile    = "installed.json"
	contactFile   = "contact.json"
	tombstoneFile = "retired.json"
)

// Entry is one tool this Drone installed, in the shape
// tools.InstallReport writes. Kept as its own type so the on-disk
// format does not move every time that struct gains a field.
type Entry struct {
	Tool    string `json:"tool"`
	Action  string `json:"action"`
	Version string `json:"version,omitempty"`
	Via     string `json:"via,omitempty"`
	Pkg     string `json:"pkg,omitempty"`
	Path    string `json:"path,omitempty"`
	At      string `json:"at,omitempty"`
}

// Tombstone is why this Drone stopped, left where its own next start
// will find it.
type Tombstone struct {
	Reason   string   `json:"reason"`
	At       string   `json:"at"`
	Removed  []string `json:"removed,omitempty"`
	Kept     []string `json:"kept,omitempty"`
	Failed   []string `json:"failed,omitempty"`
	Reported bool     `json:"reported_to_server"`
}

func path(workdir, name string) string { return filepath.Join(workdir, name) }

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// Written through a temporary file: a Drone killed mid-write
	// would otherwise leave a truncated tombstone, and a tombstone
	// that will not parse is one that does not stop the next start.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// RecordInstalls appends to the ledger. Called after the baseline run,
// with whatever that run actually installed.
func RecordInstalls(workdir string, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	existing, _ := Ledger(workdir)
	now := time.Now().UTC().Format(time.RFC3339)
	have := map[string]bool{}
	for _, e := range existing {
		have[e.Tool] = true
	}
	for _, e := range entries {
		if e.Action != "installed" || have[e.Tool] {
			continue
		}
		e.At = now
		existing = append(existing, e)
	}
	return writeJSON(path(workdir, ledgerFile), existing)
}

// Ledger is everything this Drone has installed on this host.
func Ledger(workdir string) ([]Entry, error) {
	b, err := os.ReadFile(path(workdir, ledgerFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	if err := json.Unmarshal(b, &out); err != nil {
		// A corrupt ledger must not block retirement. Better to leave
		// tools behind and say so than to refuse to leave.
		return nil, fmt.Errorf("ledger unreadable: %w", err)
	}
	return out, nil
}

// TouchContact records that the server was reached just now.
//
// On disk rather than in memory, and this is the whole point of the
// dead-man switch: a Drone that cannot reach Oddjob and keeps
// restarting would reset an in-memory clock on every start and never
// time out. The host it is stranded on is exactly the host where that
// matters.
func TouchContact(workdir string) {
	_ = writeJSON(path(workdir, contactFile),
		map[string]string{"last_contact": time.Now().UTC().Format(time.RFC3339)})
}

// LastContact is when the server was last reached, or the zero time if
// it never has been.
func LastContact(workdir string) time.Time {
	b, err := os.ReadFile(path(workdir, contactFile))
	if err != nil {
		return time.Time{}
	}
	var m map[string]string
	if json.Unmarshal(b, &m) != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, m["last_contact"])
	if err != nil {
		return time.Time{}
	}
	return t
}

// Mark writes the tombstone.
func Mark(workdir string, t Tombstone) error {
	t.At = time.Now().UTC().Format(time.RFC3339)
	return writeJSON(path(workdir, tombstoneFile), t)
}

// Marked reports whether this Drone has already retired, and why.
//
// Read before anything else at startup. A supervisor restarting a
// retired Drone is the normal case, not an edge one:
// `--restart unless-stopped` and `Restart=always` both do it, and
// both are what the documentation tells people to use.
func Marked(workdir string) (*Tombstone, bool) {
	b, err := os.ReadFile(path(workdir, tombstoneFile))
	if err != nil {
		return nil, false
	}
	var t Tombstone
	if json.Unmarshal(b, &t) != nil {
		// Present but unreadable still means retired. The file's
		// existence is the signal; its contents are only the
		// explanation.
		return &Tombstone{Reason: "retired (tombstone unreadable)"}, true
	}
	return &t, true
}

// Unmark removes the tombstone, so the operator can deliberately bring
// a retired Drone back. Deleting the file by hand does the same thing;
// this exists so `drone revive` can say what it did.
func Unmark(workdir string) error {
	err := os.Remove(path(workdir, tombstoneFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
