package socksrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeTunnel is a Transport backed by channels. The point of the
// Transport interface: the hard part of this file is many streams
// over one socket, and that is worth testing deterministically
// rather than against a listener.
type fakeTunnel struct {
	in   chan []byte
	out  chan []byte
	mu   sync.Mutex
	done bool
}

func newTunnel() *fakeTunnel {
	return &fakeTunnel{in: make(chan []byte, 64), out: make(chan []byte, 256)}
}

func (f *fakeTunnel) Recv(ctx context.Context) ([]byte, error) {
	select {
	case b, ok := <-f.in:
		if !ok {
			return nil, io.EOF
		}
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeTunnel) Send(ctx context.Context, b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return errors.New("tunnel closed")
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case f.out <- cp:
		return nil
	default:
		return errors.New("tunnel backed up")
	}
}

func (f *fakeTunnel) hangUp() { close(f.in) }

// next waits for a frame of one of the given kinds, ignoring others.
func (f *fakeTunnel) next(t *testing.T, kinds ...byte) Frame {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case raw := <-f.out:
			fr, err := Decode(raw)
			if err != nil {
				t.Fatalf("relay sent junk: %v", err)
			}
			for _, k := range kinds {
				if fr.Kind == k {
					return fr
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %v", kinds)
		}
	}
}

// portOf reads a listener's port with the comma-ok form. A bare
// assertion panics the whole test binary if a listener ever hands
// back something that is not a *net.TCPAddr, which is a confusing
// way to find out.
func portOf(t *testing.T, ln net.Listener) int {
	t.Helper()
	a, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, not *net.TCPAddr", ln.Addr())
	}
	return a.Port
}

// echoServer is a target: it writes back whatever it is sent.
func echoServer(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return ln, portOf(t, ln)
}

func TestOpenDialsAndEchoes(t *testing.T) {
	ln, port := echoServer(t)
	defer func() { _ = ln.Close() }()

	tun := newTunnel()
	r := New(tun, NetDialer(2*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	open, _ := EncodeOpen(1, "127.0.0.1", port)
	tun.in <- open
	if f := tun.next(t, OPENED, FAILED); f.Kind != OPENED {
		t.Fatalf("dial failed: %s", f.Payload)
	}

	data, _ := Encode(DATA, 1, []byte("hello"))
	tun.in <- data
	got := tun.next(t, DATA)
	if string(got.Payload) != "hello" {
		t.Errorf("echoed %q", got.Payload)
	}
	if got.Stream != 1 {
		t.Errorf("came back on stream %d", got.Stream)
	}
}

func TestDialFailureIsReportedNotDropped(t *testing.T) {
	tun := newTunnel()
	r := New(tun, func(context.Context, string, int) (net.Conn, error) {
		return nil, errors.New("no such host")
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	open, _ := EncodeOpen(2, "nope.invalid", 80)
	tun.in <- open
	f := tun.next(t, OPENED, FAILED)
	if f.Kind != FAILED {
		t.Fatal("a failed dial reported success")
	}
	// The reason is for the OPERATOR. A SOCKS reply has five codes
	// and none of them say "no such host", so it has to travel here
	// or it is lost.
	if string(f.Payload) == "" {
		t.Error("a failed dial carried no reason")
	}
}

func TestStreamsDoNotCrossOver(t *testing.T) {
	// The bug this exists for: two streams over one socket, and a
	// reply going back on the wrong id. It reads as corruption
	// rather than as a routing mistake, so it is worth asserting
	// rather than assuming.
	ln, port := echoServer(t)
	defer func() { _ = ln.Close() }()

	tun := newTunnel()
	r := New(tun, NetDialer(2*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	for _, id := range []uint32{10, 20} {
		open, _ := EncodeOpen(id, "127.0.0.1", port)
		tun.in <- open
		if f := tun.next(t, OPENED, FAILED); f.Kind != OPENED {
			t.Fatalf("stream %d: %s", id, f.Payload)
		}
	}
	for _, id := range []uint32{10, 20} {
		payload := fmt.Sprintf("for-%d", id)
		d, _ := Encode(DATA, id, []byte(payload))
		tun.in <- d
		got := tun.next(t, DATA)
		if got.Stream != id || string(got.Payload) != payload {
			t.Errorf("stream %d got back stream=%d %q",
				id, got.Stream, got.Payload)
		}
	}
}

func TestCloseFromServerEndsTheStream(t *testing.T) {
	ln, port := echoServer(t)
	defer func() { _ = ln.Close() }()

	tun := newTunnel()
	r := New(tun, NetDialer(2*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	open, _ := EncodeOpen(5, "127.0.0.1", port)
	tun.in <- open
	tun.next(t, OPENED)
	if r.Live() != 1 {
		t.Fatalf("expected one live stream, got %d", r.Live())
	}

	cl, _ := Encode(CLOSE, 5, nil)
	tun.in <- cl
	deadline := time.After(3 * time.Second)
	for r.Live() != 0 {
		select {
		case <-deadline:
			t.Fatal("stream stayed live after CLOSE")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestTargetHangupIsReportedUp(t *testing.T) {
	// A target that closes is the normal end of a request, not a
	// fault — but the server still has to be told, or it waits for
	// a stream that will never speak again.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close() // hang up immediately
	}()

	tun := newTunnel()
	r := New(tun, NetDialer(2*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = r.Run(ctx) }()

	open, _ := EncodeOpen(9, "127.0.0.1", portOf(t, ln))
	tun.in <- open
	tun.next(t, OPENED)
	if f := tun.next(t, CLOSE); f.Stream != 9 {
		t.Errorf("CLOSE came back on stream %d", f.Stream)
	}
}

func TestLostFramingEndsTheTunnel(t *testing.T) {
	// Not just the frame. A multiplexer that cannot find the next
	// frame boundary would start feeding one stream's bytes to
	// another, which is worse than dropping the connection.
	tun := newTunnel()
	r := New(tun, NetDialer(time.Second))
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()

	tun.in <- []byte{0x7F, 0, 0, 0, 1} // unknown type
	select {
	case err := <-done:
		if err == nil {
			t.Error("Run returned nil on lost framing")
		}
	case <-time.After(3 * time.Second):
		t.Error("Run kept going after lost framing")
	}
}

func TestShutdownClosesLiveStreams(t *testing.T) {
	// A dropped tunnel must not leave sockets open against the
	// client's estate. That is both a leak and a thing somebody
	// would have to explain.
	ln, port := echoServer(t)
	defer func() { _ = ln.Close() }()

	tun := newTunnel()
	r := New(tun, NetDialer(2*time.Second))
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()

	open, _ := EncodeOpen(3, "127.0.0.1", port)
	tun.in <- open
	tun.next(t, OPENED)
	if r.Live() != 1 {
		t.Fatalf("expected one live stream, got %d", r.Live())
	}

	tun.hangUp()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return when the tunnel ended")
	}
	if r.Live() != 0 {
		t.Errorf("%d stream(s) left open after shutdown", r.Live())
	}
}

func TestDataForAnUnknownStreamIsIgnored(t *testing.T) {
	// Late data for a stream that has already gone is normal on a
	// multiplexed tunnel — both sides can close at once. It must not
	// take the tunnel down.
	tun := newTunnel()
	r := New(tun, NetDialer(time.Second))
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()

	d, _ := Encode(DATA, 999, []byte("orphan"))
	tun.in <- d
	select {
	case err := <-done:
		t.Fatalf("tunnel died on orphan data: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
}
