// Package debuglog keeps the agent's own log so it can be sent back.
//
// Diagnosing a ghost used to mean having an account on the box it runs
// on, and this fleet is a GCP VM reached through an IAP tunnel, a
// Windows host whose docker lives inside WSL2, and a droplet: three
// different procedures to answer one question. When the GCP host lost
// its network route there was no procedure at all, because the only
// channel still working was the one the agent itself dials out on.
//
// So the agent keeps its recent log in memory and ships it when asked.
// Off by default. While it is off nothing is retained and the cost is
// one atomic load per line.
package debuglog

import (
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Line is one entry, stamped on the agent's own clock.
type Line struct {
	At   time.Time `json:"at"`
	Line string    `json:"line"`
}

// Max lines held in memory between sends. A bound rather than a
// window: the failure this exists for is an agent that has STOPPED
// doing things, where the last lines matter and their age does not.
// At roughly 120 bytes a line this is well under a megabyte.
const Max = 1000

// Buffer is an io.Writer that keeps what it is given, when enabled.
//
// It is written to by the logger on whatever goroutine is logging and
// drained by the heartbeat on another, so every field is guarded. The
// enabled flag is atomic and checked before the mutex: when debug is
// off -- which is almost always -- a log line costs one load and no
// contention with anything.
type Buffer struct {
	on   atomic.Bool
	mu   sync.Mutex
	buf  []Line
	lost int // dropped because the buffer was full, reported once
}

// New returns a disabled buffer.
func New() *Buffer { return &Buffer{} }

// SetEnabled turns collection on or off. Turning it off discards what
// was held: the operator switching debug off is the signal that this
// engagement should stop keeping a copy of what the ghost says, and
// a buffer that outlived the switch would be sent after it.
func (b *Buffer) SetEnabled(on bool) {
	was := b.on.Swap(on)
	if was == on {
		return
	}
	b.mu.Lock()
	b.buf, b.lost = nil, 0
	b.mu.Unlock()
}

// Enabled reports whether lines are being kept.
func (b *Buffer) Enabled() bool { return b.on.Load() }

// Write implements io.Writer. It never fails and never blocks on
// anything but its own mutex: this sits in the logger's path, and a
// debug facility that can wedge the thing it is observing is worse
// than no debug facility.
func (b *Buffer) Write(p []byte) (int, error) {
	if !b.on.Load() {
		return len(p), nil
	}
	// Trimmed, and dropped if nothing is left. The server applies the
	// same rule, so a blank line sent from here is a line that travels
	// the network to be discarded on arrival.
	s := strings.TrimSpace(string(p))
	if s == "" {
		return len(p), nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) >= Max {
		// Drop the OLDEST, not this one. When an agent is failing it
		// is the most recent lines that say why, and a buffer that
		// discards new arrivals preserves the run-up to a problem
		// while losing the problem.
		copy(b.buf, b.buf[1:])
		b.buf = b.buf[:len(b.buf)-1]
		b.lost++
	}
	b.buf = append(b.buf, Line{At: time.Now().UTC(), Line: s})
	return len(p), nil
}

// Drain removes and returns what is held, plus how many were dropped
// since the last drain. The caller is sending them; if the send fails
// they are gone, which is the right trade for a diagnostic -- a retry
// queue here would be a second place for the agent to run out of
// memory while it is already in trouble.
func (b *Buffer) Drain() ([]Line, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 && b.lost == 0 {
		return nil, 0
	}
	out, lost := b.buf, b.lost
	b.buf, b.lost = nil, 0
	return out, lost
}

// Add records one line directly, without going through a logger.
//
// For the things that must reach Oddjob whatever is wrong with this
// host's own logging -- above all the line saying debug has just been
// switched on, which is the only evidence an operator has that the
// switch did anything at all.
func (b *Buffer) Add(line string) {
	if !b.on.Load() {
		return
	}
	_, _ = b.Write([]byte(line))
}

// tee writes to the buffer first and to the local writer second, and
// never lets the second one's failure affect the first.
type tee struct {
	b *Buffer
	w io.Writer
}

func (t *tee) Write(p []byte) (int, error) {
	// Buffer first, deliberately. This was `io.MultiWriter(w, b)`,
	// which stops at the first error -- so one failed write to the
	// local stderr silently stopped anything from ever being
	// COLLECTED, and the agent then had an empty buffer to drain on
	// every beat and sent nothing, for ever, while still looking
	// healthy. A ghost whose local logging has broken is the exact
	// case this feature exists for, and it was the one case where it
	// turned itself off.
	_, _ = t.b.Write(p) // never fails; see Write
	// And the local write's error is dropped rather than returned:
	// the only caller is log.Printf, which ignores it, and returning
	// it would be claiming the line was lost when it was kept.
	_, _ = t.w.Write(p)
	return len(p), nil
}

// Tee returns a writer that keeps everything and also passes it to w.
// Local logging is unchanged whether debug is on or off: a ghost that
// stopped printing to its own stderr when debug was enabled would make
// the one case you are investigating the one case you cannot watch.
func (b *Buffer) Tee(w io.Writer) io.Writer { return &tee{b: b, w: w} }
