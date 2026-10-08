package agent

import (
	"testing"

	"github.com/xsecurity-ai/oddjob/ghost/internal/config"
)

// Who gets to decide how many tasks this agent runs at once.
//
// Three parties, and the precedence is a decision rather than an
// accident, so it is written down as a test:
//
//	--parallel on the command line   the person who put the agent on
//	                                 this machine
//	Oddjob, over the heartbeat       the person running the engagement
//	the agent measuring its host     nobody; it is a guess, a good one
//
// The local flag wins. It is the only way to say "this box must not be
// pushed harder than this" in a way a remote operator cannot undo, and
// a server that is wrong — or not ours — should not be able to drive
// somebody's machine into swap.
func newTestAgent(localFlag int) *Agent {
	return &Agent{cfg: &config.Config{Parallel: localFlag}}
}

func TestAdoptServerParallel(t *testing.T) {
	a := newTestAgent(0)
	a.cap_, a.capWhy = 2, "2 cores x 4"

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
}

func TestRetuneLeavesAServerNumberAlone(t *testing.T) {
	// Without this the two fight on a sixty-second cycle: Oddjob says
	// 8, the next retune measures the box and says 2, the heartbeat
	// after that says 8 again, and the fleet table flickers. `retune`
	// is not called here — it would measure this machine — so the
	// guard it consults is asserted directly.
	a := newTestAgent(0)
	a.adoptServerParallel(8)
	if !a.capFromServer {
		t.Fatal("precondition: the number should be marked as the server's")
	}

	// And the other direction: a locally-flagged agent keeps measuring,
	// because its cap is pinned by the flag anyway and the reasoning
	// shown to an operator should stay current.
	b := newTestAgent(4)
	b.adoptServerParallel(8)
	if b.capFromServer {
		t.Error("a flagged agent must not be marked as server-set")
	}
}
