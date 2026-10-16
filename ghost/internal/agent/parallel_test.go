package agent

import (
	"strings"
	"testing"

	"github.com/xsecurity-ai/oddjob/ghost/internal/config"
)

// Who gets to decide how many tasks this agent runs at once.
//
// Four parties now, and the precedence is a decision rather than an
// accident, so it is written down as a test:
//
//	--parallel on the command line   the person who put the agent on
//	                                 this machine
//	the host's free memory           not an opinion; a hard ceiling
//	Oddjob, over the heartbeat       the person running the engagement
//	the agent measuring its host     a guess, and a good one
//
// The local flag still wins outright. What changed is the second line:
// the host's memory used to sit at the BOTTOM, below Oddjob, and a
// server number simply replaced it. That cost two hosts -- see
// clampCapacity -- so a measurement can now hold a server number down,
// though it can never push one up.
func newTestAgent(localFlag int) *Agent {
	return &Agent{cfg: &config.Config{Parallel: localFlag}}
}

func TestClampCapacity(t *testing.T) {
	cases := []struct {
		name     string
		want     int // what Oddjob asked for
		measured int // what the host can stand
		why      string
		expect   int
		inReason string
	}{
		{"no opinion from the server", 0, 3, "2 cores x 4", 3, "2 cores x 4"},
		{"a negative is no opinion", -1, 3, "2 cores x 4", 3, "2 cores x 4"},
		{"server asks for less than the host could do", 2, 8, "8 cores", 2, "from Oddjob"},
		{"server asks for exactly what fits", 4, 4, "4 cores", 4, "from Oddjob"},
		{"not measured yet, take the server's word", 6, 0, "", 6, "from Oddjob"},

		// The two that actually happened.
		{"the WSL2 box", 6, 2, "2 cores x 4, held by 420MB available",
			2, "held to 2 by this host"},
		{"the 1GB droplet", 6, 3, "3 from 512MB available",
			3, "held to 3 by this host"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := clampCapacity(c.want, c.measured, c.why)
			if got != c.expect {
				t.Errorf("clampCapacity(%d, %d) = %d, want %d",
					c.want, c.measured, got, c.expect)
			}
			if !strings.Contains(why, c.inReason) {
				t.Errorf("reason %q does not mention %q", why, c.inReason)
			}
		})
	}
}

// The regression, stated as the thing that went wrong rather than as
// the function that was changed.
//
// A server number larger than the host can hold must not be run. Both
// failures looked like this: the agent measured correctly, Oddjob said
// a bigger number, and the agent did as it was told until the host
// stopped responding.
func TestAServerNumberCannotExceedTheHost(t *testing.T) {
	a := newTestAgent(0)
	a.capMeasured, a.capMeasuredWhy = 2, "2 cores x 4, held by 101MB available"
	a.cap_ = 2

	a.adoptServerParallel(6)

	if a.cap_ > 2 {
		t.Fatalf("cap_=%d: the agent took a number its host cannot hold, "+
			"which is how the WSL2 VM and the droplet both died", a.cap_)
	}
	// And it has to SAY so. An operator who asked for six and silently
	// got two has no way to tell this from an agent that is just slow.
	if !strings.Contains(a.capWhy, "6") || !strings.Contains(a.capWhy, "held to 2") {
		t.Errorf("capWhy = %q, which does not tell an operator that their "+
			"6 was held down to 2", a.capWhy)
	}
	// The request is remembered, so headroom returning lifts the cap
	// without the server having to repeat itself.
	if a.capServerWant != 6 {
		t.Errorf("capServerWant = %d, want the original 6", a.capServerWant)
	}
}

// The other direction: once memory frees up, the operator's number is
// honoured without Oddjob resending it. Without this the clamp is a
// one-way ratchet and a host that recovers stays throttled forever.
func TestHeadroomReturningLiftsTheCapBack(t *testing.T) {
	a := newTestAgent(0)
	a.capMeasured, a.capMeasuredWhy = 2, "held by 101MB available"
	a.adoptServerParallel(6)
	if a.cap_ != 2 {
		t.Fatalf("precondition: cap_=%d, want it held to 2", a.cap_)
	}

	// What retune does after the box recovers.
	a.mu.Lock()
	a.capMeasured, a.capMeasuredWhy = 8, "2 cores x 4"
	a.mu.Unlock()
	a.applyCapacity()

	if a.cap_ != 6 {
		t.Errorf("cap_=%d after memory freed, want the operator's 6", a.cap_)
	}
}

func TestAdoptServerParallel(t *testing.T) {
	a := newTestAgent(0)
	a.capMeasured, a.capMeasuredWhy = 8, "2 cores x 4"
	a.cap_, a.capWhy = 8, "2 cores x 4"

	a.adoptServerParallel(8)
	if a.cap_ != 8 {
		t.Errorf("server number not adopted: cap_=%d", a.cap_)
	}
	if !a.capFromServer {
		t.Error("adopting did not record where the number came from")
	}
	if a.capWhy == "2 cores x 4" {
		t.Error("the reason still describes the host's own answer")
	}

	// Zero is "no opinion", which is also what an older server sends by
	// not sending the field at all. Reading it as "run nothing" would
	// idle the whole fleet against a server that had not been upgraded.
	a2 := newTestAgent(0)
	a2.capMeasured, a2.capMeasuredWhy = 4, "4 cores"
	a2.cap_, a2.capWhy = 4, "4 cores"
	a2.adoptServerParallel(0)
	if a2.cap_ != 4 || a2.capFromServer {
		t.Errorf("zero was treated as an instruction: cap_=%d from_server=%v",
			a2.cap_, a2.capFromServer)
	}
	a2.adoptServerParallel(-1)
	if a2.cap_ != 4 {
		t.Errorf("a negative was treated as an instruction: cap_=%d", a2.cap_)
	}
}

func TestLocalFlagBeatsTheServer(t *testing.T) {
	// The host owner's limit is not the engagement operator's to raise.
	a := newTestAgent(2)
	a.cap_, a.capWhy = 2, "set to 2 by the operator"
	a.adoptServerParallel(32)
	if a.cap_ != 2 {
		t.Fatalf("a server number overrode an explicit --parallel: cap_=%d", a.cap_)
	}
	if a.capFromServer {
		t.Error("the agent recorded a server origin for a number it refused")
	}
	if a.capServerWant != 0 {
		t.Errorf("capServerWant = %d: a refused number was still remembered, "+
			"and would be applied if the measurement ever changed",
			a.capServerWant)
	}
}

// The flicker this replaced a guard against. `retune` used to return
// early whenever Oddjob had set a number, because the two paths wrote
// different answers and the fleet table oscillated between them.
//
// They now share clampCapacity, so the fix is that both paths agree.
// Asserted directly rather than by calling retune, which would measure
// whatever machine the test runs on.
func TestBothPathsAgreeSoNothingFlickers(t *testing.T) {
	const want, measured = 8, 2
	const why = "2 cores x 4, held by 101MB available"

	// What adoptServerParallel computes on a heartbeat.
	a := newTestAgent(0)
	a.capMeasured, a.capMeasuredWhy = measured, why
	a.adoptServerParallel(want)
	fromHeartbeat := a.cap_

	// What retune computes sixty seconds later, measuring the same host.
	a.mu.Lock()
	a.capMeasured, a.capMeasuredWhy = measured, why
	a.mu.Unlock()
	a.applyCapacity()
	fromRetune := a.cap_

	if fromHeartbeat != fromRetune {
		t.Errorf("heartbeat says %d and retune says %d: the fleet table "+
			"would oscillate between them every sixty seconds",
			fromHeartbeat, fromRetune)
	}
}
