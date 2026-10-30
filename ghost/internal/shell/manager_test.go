package shell

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
)

// A manager over a pipe, counting how many tunnels it dialled.
func newManager(t *testing.T) (*Manager, *pipe, *atomic.Int32) {
	t.Helper()
	p := newPipe()
	var dials atomic.Int32
	m := NewManager(func(context.Context) (Transport, error) {
		dials.Add(1)
		return p, nil
	})
	t.Cleanup(m.Close)
	return m, p, &dials
}

func TestHoldsWhatItIsAskedFor(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)

	// Real ports, not 0. Port 0 is refused here exactly as the
	// server refuses it: "whatever is free" is not something a
	// payload can be told to call back to.
	m.Reconcile(ctx, []Spec{
		{ID: 1, Protocol: "tcp", Port: freePort(t)},
		{ID: 2, Protocol: "udp", Port: freePort(t)},
	})
	got := statuses(m)
	if len(got) != 2 {
		t.Fatalf("reported %d listeners, want 2", len(got))
	}
	for _, s := range got {
		if !s.Bound {
			t.Errorf("listener %d should be bound, said %q", s.ID, s.Error)
		}
	}
}

// The one that matters most. Rebinding a port that is already held
// would drop every shell on it every few seconds -- which is the one
// thing this whole feature exists to prevent.
func TestRepeatingTheSameAskChangesNothing(t *testing.T) {
	ctx := context.Background()
	m, _, dials := newManager(t)

	port := freePort(t)
	want := []Spec{{ID: 1, Protocol: "tcp", Port: port}}
	m.Reconcile(ctx, want)
	if !statuses(m)[0].Bound {
		t.Fatalf("first bind failed: %q", statuses(m)[0].Error)
	}

	// A second ask for the same thing. If it released and rebound,
	// the port would be briefly free and the second bind could even
	// fail -- but the giveaway that works every time is the socket
	// identity, so check a shell survives it.
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	m.Reconcile(ctx, want)
	m.Reconcile(ctx, want)

	if _, err := c.Write([]byte("still alive\n")); err != nil {
		t.Fatalf("the shell was dropped by a repeated reconcile: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("dialled the tunnel %d times for one listener", n)
	}
}

// A port dropped from the list is released, and the OS agrees.
func TestReleasesWhatIsNoLongerWanted(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)

	port := freePort(t)
	m.Reconcile(ctx, []Spec{{ID: 1, Protocol: "tcp", Port: port}})
	if !statuses(m)[0].Bound {
		t.Fatalf("bind failed: %q", statuses(m)[0].Error)
	}

	m.Reconcile(ctx, nil)
	if got := statuses(m); len(got) != 0 {
		t.Errorf("still reporting %d listeners after being asked for none", len(got))
	}
	// The real check: the port is free again.
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("port %d was not released: %v", port, err)
	}
	_ = ln.Close()
}

// A bind that fails is reported WITH the reason. "address already in
// use" is the whole answer most of the time, and without it an
// operator goes and debugs their payload.
func TestAFailedBindSaysWhy(t *testing.T) {
	ctx := context.Background()
	// Bound on ALL interfaces, which is how the listener binds.
	// Holding 127.0.0.1:p while the listener asks for :p does not
	// conflict on macOS, so a test written that way skips -- and a
	// test that skips proves nothing.
	port := freePort(t)
	taken, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = taken.Close() }()

	m, _, _ := newManager(t)
	m.Reconcile(ctx, []Spec{{ID: 7, Protocol: "tcp", Port: port}})

	got := statuses(m)
	if len(got) != 1 {
		t.Fatalf("reported %d listeners, want 1", len(got))
	}
	if got[0].Bound {
		t.Fatalf("bound a port something else already holds")
	}
	if got[0].Error == "" {
		t.Error("a failed bind must carry the reason, not just a cross")
	}
}

// No route home means a bound port catching shells nobody can see,
// so it is a failure and it names the tunnel rather than the port.
func TestNoTunnelIsAFailureWithAReason(t *testing.T) { //nolint:thelper // it is a test
	m := NewManager(func(context.Context) (Transport, error) {
		return nil, errors.New("tunnel refused (401 Unauthorized)")
	})
	defer m.Close()
	m.Reconcile(context.Background(), []Spec{
		{ID: 3, Protocol: "tcp", Port: freePort(t)}})

	got := statuses(m)
	if len(got) != 1 || got[0].Bound {
		t.Fatalf("expected one failed listener, got %+v", got)
	}
	if got[0].Error == "" || !contains(got[0].Error, "401") {
		t.Errorf("the reason should reach the operator, got %q", got[0].Error)
	}
}

// A Ghost nobody has given a listener dials nothing. A websocket
// held open for no reason is a connection somebody has to explain.
func TestAsksForNothingDialsNothing(t *testing.T) {
	m, _, dials := newManager(t)
	m.Reconcile(context.Background(), nil)
	if n := dials.Load(); n != 0 {
		t.Errorf("dialled %d times with no listeners wanted", n)
	}
	if got := statuses(m); len(got) != 0 {
		t.Errorf("reported %d listeners with none wanted", len(got))
	}
}

// A port the server should never have sent is refused here too. An
// agent that binds whatever it is told is an agent that does what a
// compromised server says.
func TestRefusesAnImpossiblePort(t *testing.T) {
	m, _, dials := newManager(t)
	m.Reconcile(context.Background(), []Spec{
		{ID: 1, Protocol: "tcp", Port: 0xFFFF + 1},
		{ID: 2, Protocol: "tcp", Port: -1},
		// 0 is "any free port", which is not something a payload
		// can call back to -- refused here as well as server-side.
		{ID: 3, Protocol: "tcp", Port: 0},
	})
	if got := statuses(m); len(got) != 0 {
		t.Errorf("bound %d impossible ports", len(got))
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("dialled a tunnel for ports it refused")
	}
}

func statuses(m *Manager) []Status { return m.Report() }

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("%s is not a tcp address", l.Addr())
	}
	_ = l.Close()
	return addr.Port
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
