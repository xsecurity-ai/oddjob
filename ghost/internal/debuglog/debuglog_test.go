package debuglog

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sync"
	"testing"
)

func TestDisabledKeepsNothing(t *testing.T) {
	b := New()
	for i := 0; i < 50; i++ {
		_, _ = fmt.Fprintf(b, "line %d\n", i)
	}
	got, lost := b.Drain()
	if len(got) != 0 || lost != 0 {
		t.Fatalf("a disabled buffer kept %d line(s), lost %d; it must keep "+
			"nothing, because that is the state it is in on every agent "+
			"that is not being debugged", len(got), lost)
	}
}

func TestCollectsWhenOn(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	_, _ = fmt.Fprintln(b, "first")
	_, _ = fmt.Fprintln(b, "second")
	got, lost := b.Drain()
	if len(got) != 2 || lost != 0 {
		t.Fatalf("kept %d line(s), lost %d, want 2 and 0", len(got), lost)
	}
	if got[0].Line != "first" || got[1].Line != "second" {
		t.Fatalf("order or content wrong: %+v", got)
	}
	if got[0].At.IsZero() {
		t.Fatal("no timestamp; the server orders by the agent's clock")
	}
	// Drain is destructive -- the caller is sending them.
	if again, _ := b.Drain(); len(again) != 0 {
		t.Fatalf("drain left %d line(s) behind", len(again))
	}
}

func TestTrailingNewlineStripped(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	_, _ = fmt.Fprint(b, "no trailing newline please\r\n")
	got, _ := b.Drain()
	if len(got) != 1 || got[0].Line != "no trailing newline please" {
		t.Fatalf("got %q", got)
	}
}

// The server drops a line that is empty once stripped, so sending one
// is a round trip to be discarded on arrival. Same rule both ends.
func TestBlankWritesIgnored(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	_, _ = fmt.Fprint(b, "\n")
	_, _ = fmt.Fprint(b, "   \n")
	_, _ = fmt.Fprint(b, "\t \r\n")
	if got, _ := b.Drain(); len(got) != 0 {
		t.Fatalf("kept %d blank line(s), want none: %+v", len(got), got)
	}
}

// The important one. When an agent is failing it is the LAST lines
// that say why, so a full buffer must discard the oldest.
func TestOverflowDropsOldestNotNewest(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	for i := 0; i < Max+25; i++ {
		_, _ = fmt.Fprintf(b, "line %d\n", i)
	}
	got, lost := b.Drain()
	if len(got) != Max {
		t.Fatalf("held %d, want the cap of %d", len(got), Max)
	}
	if lost != 25 {
		t.Fatalf("reported %d dropped, want 25 -- a hole in the log the "+
			"operator cannot otherwise see", lost)
	}
	want := fmt.Sprintf("line %d", Max+24)
	if got[len(got)-1].Line != want {
		t.Fatalf("newest line is %q, want %q: the buffer dropped the "+
			"arriving line instead of the oldest one, which preserves "+
			"the run-up to a failure and loses the failure",
			got[len(got)-1].Line, want)
	}
	if got[0].Line != "line 25" {
		t.Fatalf("oldest retained is %q, want \"line 25\"", got[0].Line)
	}
}

// Turning debug off must not leave a buffer to be shipped afterwards.
func TestDisablingDiscards(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	_, _ = fmt.Fprintln(b, "collected while on")
	b.SetEnabled(false)
	if got, lost := b.Drain(); len(got) != 0 || lost != 0 {
		t.Fatalf("switching debug off left %d line(s) to be sent: the "+
			"switch is what says this engagement stops keeping a copy "+
			"of what the ghost logs", len(got))
	}
}

func TestReenableStartsClean(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	_, _ = fmt.Fprintln(b, "old")
	b.SetEnabled(false)
	b.SetEnabled(true)
	_, _ = fmt.Fprintln(b, "new")
	got, _ := b.Drain()
	if len(got) != 1 || got[0].Line != "new" {
		t.Fatalf("got %+v, want only the line logged after re-enabling", got)
	}
}

func TestSetEnabledSameValueKeepsBuffer(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	_, _ = fmt.Fprintln(b, "kept")
	b.SetEnabled(true) // no transition
	if got, _ := b.Drain(); len(got) != 1 {
		t.Fatalf("re-asserting the current state threw the buffer away; "+
			"the heartbeat says `debug: true` on every beat, so that "+
			"would discard the log continuously (got %d)", len(got))
	}
}

// Tee must not swallow local output. The host's own stderr is how you
// watch an agent you are already logged in to.
func TestTeeStillWritesThrough(t *testing.T) {
	var sink bytes.Buffer
	b := New()
	w := b.Tee(&sink)
	_, _ = fmt.Fprintln(w, "visible locally")
	if sink.String() != "visible locally\n" {
		t.Fatalf("local writer got %q", sink.String())
	}
	b.SetEnabled(true)
	_, _ = fmt.Fprintln(w, "and now also kept")
	if got, _ := b.Drain(); len(got) != 1 {
		t.Fatalf("tee did not collect when enabled: %+v", got)
	}
	if sink.String() == "visible locally\n" {
		t.Fatal("enabling debug stopped local logging")
	}
}

// It sits in the logger's path and is drained from the heartbeat
// goroutine, so it is written and read concurrently by construction.
func TestConcurrentWriteAndDrain(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			lg := log.New(b, "", 0)
			for i := 0; i < 200; i++ {
				lg.Printf("writer %d line %d", w, i)
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			b.Drain()
		}
	}()
	wg.Wait()
	b.Drain()
}

// failing stands in for a stderr that has stopped accepting writes.
type failing struct{ n int }

func (f *failing) Write(p []byte) (int, error) {
	f.n++
	return 0, errors.New("broken pipe")
}

// The regression this package was briefly useless for.
//
// `Tee` was `io.MultiWriter(w, b)` with the local writer first, and
// io.MultiWriter stops at the first error. So on a host whose stderr
// had stopped accepting writes, nothing was ever COLLECTED: the
// buffer stayed empty, every heartbeat drained nothing, and the agent
// shipped nothing for ever while still looking perfectly healthy. A
// ghost whose local logging is broken is the exact case this exists
// for, and it was the one case it silently switched itself off in.
func TestLocalWriterFailureDoesNotStopCollection(t *testing.T) {
	b := New()
	b.SetEnabled(true)
	bad := &failing{}
	lg := log.New(b.Tee(bad), "", 0)

	lg.Printf("first")
	lg.Printf("second")

	if bad.n == 0 {
		t.Fatal("the local writer was never tried, so this proves nothing")
	}
	lines, _ := b.Drain()
	if len(lines) != 2 {
		t.Fatalf("a failing stderr cost us the log: kept %d of 2", len(lines))
	}
	if lines[0].Line != "first" || lines[1].Line != "second" {
		t.Fatalf("kept the wrong lines: %+v", lines)
	}
}

// Add is how the "debug is on" line reaches Oddjob even when the
// logger cannot get anywhere, so it must obey the enabled flag and
// the same trimming as everything else.
func TestAddBypassesTheLogger(t *testing.T) {
	b := New()
	b.Add("while off")
	if lines, _ := b.Drain(); len(lines) != 0 {
		t.Fatalf("Add kept a line while disabled: %+v", lines)
	}
	b.SetEnabled(true)
	b.Add("  switched on  ")
	b.Add("   ")
	lines, _ := b.Drain()
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d: %+v", len(lines), lines)
	}
	if lines[0].Line != "switched on" {
		t.Fatalf("not trimmed like the rest: %q", lines[0].Line)
	}
}
