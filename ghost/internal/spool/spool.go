// Package spool is the agent's own record of the work it has taken on.
//
// The failure this exists for: a scan finishes, the agent is killed or
// the host reboots before the result reaches Oddjob, and the output is
// gone. That scan ran against the client's estate — the packets were
// sent, the noise was made — and there is nothing to show for it. The
// operator sees a task that never came back and cannot tell whether it
// found nothing or never reported.
//
// So this is deliberately not an in-memory database. The only property
// that matters is surviving the process that wrote it. A result is
// written to disk before it is sent, and removed only once the server
// has acknowledged it; anything still on disk at startup is re-sent.
//
// It is also deliberately not a database at all. One directory, one
// file per task, written atomically by rename. That survives a crash
// mid-write, needs no schema migration on an agent nobody will log
// into again, and can be read with `cat` by whoever is debugging it at
// two in the morning.
package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// State is where a task has got to, from this agent's point of view.
const (
	//: Taken from the server, not yet finished.
	Running = "running"
	//: Finished. The output is here and the server has not confirmed
	//: receipt, so it must be re-sent until it does.
	Pending = "pending"
)

// Entry is one task as this agent sees it.
type Entry struct {
	TaskID    int    `json:"task_id"`
	Kind      string `json:"kind"`
	State     string `json:"state"`
	StartedAt string `json:"started_at"`
	EndedAt   string `json:"ended_at,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`

	// The result, once there is one. Held here rather than in memory
	// so a crash between finishing and reporting does not lose it.
	Status   string `json:"status,omitempty"`
	Output   string `json:"output,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Summary  string `json:"summary,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Error    string `json:"error,omitempty"`
}

type Spool struct {
	dir string
	mu  sync.Mutex
}

func Open(dir string) (*Spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool %s: %w", dir, err)
	}
	return &Spool{dir: dir}, nil
}

func (s *Spool) path(id int) string {
	return filepath.Join(s.dir, fmt.Sprintf("task-%d.json", id))
}

// Begin records that this agent has taken a task on.
func (s *Spool) Begin(id int, kind string) error {
	return s.write(&Entry{TaskID: id, Kind: kind, State: Running,
		StartedAt: time.Now().UTC().Format(time.RFC3339)})
}

// Finish stores the result. After this returns the result is on disk,
// and will be delivered eventually whatever happens to the process.
func (s *Spool) Finish(id int, status, output, stderr, summary string,
	exit int, errText string) error {
	s.mu.Lock()
	e, err := s.read(id)
	s.mu.Unlock()
	if err != nil || e == nil {
		e = &Entry{TaskID: id, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	}
	e.TaskID, e.State = id, Pending
	e.EndedAt = time.Now().UTC().Format(time.RFC3339)
	e.Status, e.Output, e.Stderr = status, output, stderr
	e.Summary, e.ExitCode, e.Error = summary, exit, errText
	return s.write(e)
}

// Delivered drops a task once the server has acknowledged it. Only
// then: removing it at send time would lose the result to a response
// that never arrived.
func (s *Spool) Delivered(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Attempted notes a failed delivery, so an operator looking at the
// spool can tell "never tried" from "tried eleven times".
func (s *Spool) Attempted(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, err := s.read(id)
	if err != nil || e == nil {
		return
	}
	e.Attempts++
	_ = s.writeLocked(e)
}

// Pending is everything still owed to the server, oldest first.
func (s *Spool) Pending() ([]*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names, err := filepath.Glob(filepath.Join(s.dir, "task-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var out []*Entry
	for _, n := range names {
		raw, err := os.ReadFile(n) // #nosec G304 — our own spool dir
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(raw, &e) != nil {
			// A half-written or corrupt entry is not worth crashing
			// the agent over, but it is worth keeping: renamed aside
			// so it stops being retried and is still there to look at.
			_ = os.Rename(n, n+".corrupt")
			continue
		}
		if e.State == Pending {
			out = append(out, &e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TaskID < out[j].TaskID })
	return out, nil
}

// Orphaned are tasks this agent was running when it stopped. They
// cannot be resumed — the tool's process is gone — but the server is
// still waiting on them, so they are reported as failures rather than
// left to time out silently.
func (s *Spool) Orphaned() ([]*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names, _ := filepath.Glob(filepath.Join(s.dir, "task-*.json"))
	sort.Strings(names)
	var out []*Entry
	for _, n := range names {
		raw, err := os.ReadFile(n) // #nosec G304 — our own spool dir
		if err != nil {
			continue
		}
		var e Entry
		if json.Unmarshal(raw, &e) == nil && e.State == Running {
			out = append(out, &e)
		}
	}
	return out, nil
}

// Count is how much work the spool is holding: `running` is what this
// agent is working on now and `pending` is what it still owes the
// server. Both for the call-in API — an operator asking "is this agent
// stuck?" wants the two numbers, not a boolean.
func (s *Spool) Count() (running, pending int) {
	r, _ := s.Orphaned()
	p, _ := s.Pending()
	return len(r), len(p)
}

func (s *Spool) write(e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(e)
}

func (s *Spool) writeLocked(e *Entry) error {
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	// Written then renamed: a crash partway through leaves the old
	// file intact rather than a truncated one, which is the difference
	// between re-sending a result and losing it.
	tmp := s.path(e.TaskID) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(e.TaskID))
}

func (s *Spool) read(id int) (*Entry, error) {
	raw, err := os.ReadFile(s.path(id)) // #nosec G304 — our own spool dir
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}
