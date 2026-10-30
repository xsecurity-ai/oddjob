package shell

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

// A transport that keeps what the listener sent and lets a test push
// frames back down, standing in for the websocket to Oddjob.
type pipe struct {
	mu   sync.Mutex
	sent [][]byte
	in   chan []byte
}

func newPipe() *pipe { return &pipe{in: make(chan []byte, 64)} }

func (p *pipe) Send(_ context.Context, b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, append([]byte(nil), b...))
	return nil
}

func (p *pipe) Recv(ctx context.Context) ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pipe) frames() []socksrelay.Frame {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []socksrelay.Frame{}
	for _, raw := range p.sent {
		if f, err := socksrelay.Decode(raw); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func (p *pipe) of(kind byte) []socksrelay.Frame {
	out := []socksrelay.Frame{}
	for _, f := range p.frames() {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func start(t *testing.T) (*Listener, *pipe, context.CancelFunc) {
	t.Helper()
	p := newPipe()
	ctx, cancel := context.WithCancel(context.Background())
	// Port 0: the OS picks a free one. A fixed port in a test is a
	// test that fails when two of them run at once.
	l, err := Open(ctx, p, 0)
	if err != nil {
		cancel()
		t.Fatalf("open: %v", err)
	}
	go func() { _ = l.Run(ctx) }()
	t.Cleanup(func() { _ = l.Close(); cancel() })
	return l, p, cancel
}

func dial(t *testing.T, l *Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(l.Port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

// A callback lands, is announced with where it came from, and its
// output comes home.
func TestCatchesACallback(t *testing.T) {
	l, p, _ := start(t)
	c := dial(t, l)
	defer func() { _ = c.Close() }()

	waitFor(t, "the arrival", func() bool { return len(p.of(socksrelay.ARRIVED)) == 1 })
	arrived := p.of(socksrelay.ARRIVED)[0]
	// Provenance: the peer address is the only thing distinguishing
	// two callbacks on one port.
	if !strings.HasPrefix(string(arrived.Payload), "127.0.0.1:") {
		t.Errorf("arrival should carry the peer, got %q", arrived.Payload)
	}

	_, _ = c.Write([]byte("uid=0(root)\n"))
	waitFor(t, "the output", func() bool { return len(p.of(socksrelay.DATA)) > 0 })
	got := string(p.of(socksrelay.DATA)[0].Payload)
	if got != "uid=0(root)\n" {
		t.Errorf("output came back as %q", got)
	}
	if arrived.Stream != p.of(socksrelay.DATA)[0].Stream {
		t.Errorf("output arrived on a different stream than the callback")
	}
}

// The whole reason this is an Accept loop. A shell that dies at 2am
// and a payload that retries every minute must produce a second
// session, not silence.
func TestRelistensAfterACallbackEnds(t *testing.T) {
	l, p, _ := start(t)

	first := dial(t, l)
	waitFor(t, "the first arrival",
		func() bool { return len(p.of(socksrelay.ARRIVED)) == 1 })
	_ = first.Close()
	waitFor(t, "the first close",
		func() bool { return len(p.of(socksrelay.CLOSE)) == 1 })

	second := dial(t, l)
	defer func() { _ = second.Close() }()
	waitFor(t, "the second arrival",
		func() bool { return len(p.of(socksrelay.ARRIVED)) == 2 })

	a := p.of(socksrelay.ARRIVED)
	// A new stream, not the old one reused: the transcripts are
	// different sessions and must not merge.
	if a[0].Stream == a[1].Stream {
		t.Errorf("the second callback reused stream %d", a[0].Stream)
	}
	_, _ = second.Write([]byte("second\n"))
	waitFor(t, "the second output", func() bool {
		for _, f := range p.of(socksrelay.DATA) {
			if string(f.Payload) == "second\n" {
				return true
			}
		}
		return false
	})
}

// Several callbacks at once, which is ordinary when a payload is on
// a schedule across a subnet.
func TestSeveralAtOnce(t *testing.T) {
	l, p, _ := start(t)
	conns := []net.Conn{}
	for i := 0; i < 4; i++ {
		conns = append(conns, dial(t, l))
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	waitFor(t, "four arrivals",
		func() bool { return len(p.of(socksrelay.ARRIVED)) == 4 })
	seen := map[uint32]bool{}
	for _, f := range p.of(socksrelay.ARRIVED) {
		if seen[f.Stream] {
			t.Fatalf("stream %d announced twice", f.Stream)
		}
		seen[f.Stream] = true
	}
	if l.Live() != 4 {
		t.Errorf("Live() says %d, wanted 4", l.Live())
	}
}

// A command typed in the browser reaches the shell.
func TestServerDataReachesTheShell(t *testing.T) {
	l, p, _ := start(t)
	c := dial(t, l)
	defer func() { _ = c.Close() }()
	waitFor(t, "the arrival",
		func() bool { return len(p.of(socksrelay.ARRIVED)) == 1 })
	id := p.of(socksrelay.ARRIVED)[0].Stream

	b, _ := socksrelay.Encode(socksrelay.DATA, id, []byte("id\n"))
	p.in <- b

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("the shell never received it: %v", err)
	}
	if string(buf[:n]) != "id\n" {
		t.Errorf("the shell got %q", buf[:n])
	}
}

// A CLOSE from the server ends that session and no other.
func TestServerCanCloseOneSession(t *testing.T) {
	l, p, _ := start(t)
	a := dial(t, l)
	b := dial(t, l)
	defer func() { _ = b.Close() }()
	waitFor(t, "both arrivals",
		func() bool { return len(p.of(socksrelay.ARRIVED)) == 2 })
	first := p.of(socksrelay.ARRIVED)[0].Stream

	raw, _ := socksrelay.Encode(socksrelay.CLOSE, first, nil)
	p.in <- raw
	waitFor(t, "one left", func() bool { return l.Live() == 1 })

	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Errorf("the closed session is still readable")
	}
	// The other one is untouched, which is the point of a stream id.
	_, _ = b.Write([]byte("still here\n"))
	waitFor(t, "the survivor's output", func() bool {
		for _, f := range p.of(socksrelay.DATA) {
			if string(f.Payload) == "still here\n" {
				return true
			}
		}
		return false
	})
}

// A port already in use is reported to the caller, not to a
// goroutine nobody is reading.
func TestOpenReportsABusyPort(t *testing.T) {
	// All interfaces, which is what `Open` binds. Blocking only
	// 127.0.0.1 is not a conflict on every platform -- macOS let the
	// wildcard bind succeed beside it, so the first version of this
	// test asserted nothing.
	ln, err := net.Listen("tcp", ":0") //nolint:gosec // G102: matching what Open binds is the point
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("setup: %s is not a tcp address", ln.Addr())
	}
	port := addr.Port

	if _, err := Open(context.Background(), newPipe(), port); err == nil {
		t.Errorf("binding a port in use should fail, and say so here")
	} else if !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Errorf("the error should name the port: %v", err)
	}
}
