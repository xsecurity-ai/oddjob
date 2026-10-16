package agent

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/xsecurity-ai/oddjob/ghost/internal/client"
	"github.com/xsecurity-ai/oddjob/ghost/internal/config"
	"github.com/xsecurity-ai/oddjob/ghost/internal/debuglog"
)

// The bug this exists for, reproduced with the exact two calls the
// library makes.
//
// katana runs in process, and `types.NewCrawlerOptions` reaches
// `logutil.DisableDefaultLogger()`:
//
//	log.SetFlags(0); log.SetOutput(io.Discard)
//
// on the standard logger the whole agent writes to. From the first
// katana task onward the agent logged into a hole -- no local logs,
// and nothing for the debug buffer to ever send. In the fleet, the
// last line in both stuck ghosts' container logs is the one
// announcing a katana task.
func TestReclaimLoggerAfterALibraryTakesIt(t *testing.T) {
	// The standard logger is process-wide, which is the whole
	// problem; put it back so this test cannot break its neighbours.
	defer log.SetOutput(log.Writer())
	defer log.SetFlags(log.Flags())

	b := debuglog.New()
	b.SetEnabled(true)
	a := &Agent{dbg: b}
	a.logw = b.Tee(io.Discard)
	log.SetOutput(a.logw)

	log.Printf("before katana")
	if lines, _ := b.Drain(); len(lines) != 1 {
		t.Fatalf("setup is wrong: kept %d lines before the theft", len(lines))
	}

	// What katana does.
	log.SetFlags(0)
	log.SetOutput(io.Discard)

	log.Printf("during katana")
	if lines, _ := b.Drain(); len(lines) != 0 {
		t.Fatalf("expected the line to be lost; this test proves nothing now")
	}

	a.reclaimLogger()

	log.Printf("after reclaim")
	lines, _ := b.Drain()
	// Two: the notice that the logger was taken, and the line after.
	if len(lines) != 2 {
		t.Fatalf("logging was not reclaimed: kept %d lines: %+v",
			len(lines), lines)
	}
	if !strings.Contains(lines[0].Line, "taken back") {
		t.Fatalf("the theft was not reported: %q", lines[0].Line)
	}
	if !strings.HasSuffix(lines[1].Line, "after reclaim") {
		t.Fatalf("wrong line kept: %q", lines[1].Line)
	}
	// DisableDefaultLogger clears the flags as well, so a reclaim
	// that only restored the writer would leave every later line
	// without its timestamp -- which is most of what makes an agent
	// log worth reading.
	if log.Flags() != log.Ltime {
		t.Fatalf("flags not restored: %d", log.Flags())
	}
}

// The ordinary path must stay a pointer comparison and must not
// announce anything: this runs on every heartbeat.
func TestReclaimLoggerIsQuietWhenNothingIsWrong(t *testing.T) {
	defer log.SetOutput(log.Writer())

	b := debuglog.New()
	b.SetEnabled(true)
	a := &Agent{dbg: b}
	a.logw = b.Tee(io.Discard)
	log.SetOutput(a.logw)

	for i := 0; i < 5; i++ {
		a.reclaimLogger()
	}
	if lines, _ := b.Drain(); len(lines) != 0 {
		t.Fatalf("reclaim talked when nothing was wrong: %+v", lines)
	}
}

// An agent that never installed a writer -- anything constructed
// without Run -- must not seize the process logger from whoever has
// it.
func TestReclaimLoggerDoesNothingWithoutOurWriter(t *testing.T) {
	a := &Agent{}
	a.reclaimLogger()
}

// The wiring, which is the part a unit test of `reclaimLogger` alone
// cannot speak for: deleting the call from the heartbeat path has to
// fail something. `onHeartbeat` is what the loop calls, so this goes
// through the same door the server's response does.
func TestOnHeartbeatReclaimsBeforeAdopting(t *testing.T) {
	defer log.SetOutput(log.Writer())
	defer log.SetFlags(log.Flags())

	b := debuglog.New()
	a := &Agent{dbg: b, cap_: 1, cfg: &config.Config{}, running: map[int]bool{}}
	a.logw = b.Tee(io.Discard)
	log.SetOutput(a.logw)

	// A katana task, earlier in this agent's life.
	log.SetFlags(0)
	log.SetOutput(io.Discard)

	// The server says: debug on, run two at a time.
	a.onHeartbeat(context.Background(),
		&client.HeartbeatResp{Debug: true, MaxParallel: 2})

	if log.Writer() != a.logw {
		t.Fatal("onHeartbeat did not take the process logger back")
	}
	if !b.Enabled() {
		t.Fatal("onHeartbeat did not turn debug collection on")
	}
	// The line adoptDebug adds on the transition is the operator's
	// only evidence the switch did anything, and it is written
	// AFTER the reclaim, so it is also proof of the ordering.
	lines, _ := b.Drain()
	if len(lines) == 0 {
		t.Fatal("nothing was collected, so the reclaim came too late")
	}
	var found bool
	for _, l := range lines {
		if strings.Contains(l.Line, "logging to Oddjob is on") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the debug-on line never reached the buffer: %+v", lines)
	}
}
