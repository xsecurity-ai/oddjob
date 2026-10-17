package socksrelay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Transport is the tunnel, as this file needs it: a pair of framed
// message channels and nothing else.
//
// An interface rather than a WebSocket because the hard part here is
// the concurrency -- many streams over one socket, each closing at a
// time of its own choosing -- and that is worth testing in memory,
// deterministically, without a listener. The socket is a thin layer
// above this and has its own, much smaller, set of ways to be wrong.
type Transport interface {
	// Recv returns the next frame, or an error once the tunnel is done.
	Recv(ctx context.Context) ([]byte, error)
	// Send writes one frame. It MUST be safe to call from several
	// goroutines: one per live stream does exactly that.
	Send(ctx context.Context, b []byte) error
}

// Dialer opens a connection to a target. Injected so a test can
// answer without touching the network, and so the real one can carry
// a timeout and a resolver without this file knowing about either.
type Dialer func(ctx context.Context, host string, port int) (net.Conn, error)

// NetDialer is the production dialer: resolve and connect HERE, on
// the agent, because that is the whole point of proxying through it.
func NetDialer(timeout time.Duration) Dialer {
	d := &net.Dialer{Timeout: timeout}
	return func(ctx context.Context, host string, port int) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(host,
			fmt.Sprint(port)))
	}
}

// Relay runs one tunnel until it ends.
//
// It owns the stream table and is the only thing that writes to it.
// Per-stream work happens in goroutines that talk back through the
// transport, never through the map -- a mutex around a map that four
// goroutines touch is a deadlock waiting for the first slow dial.
type Relay struct {
	t    Transport
	dial Dialer

	mu      sync.Mutex
	streams map[uint32]net.Conn
	closed  bool
}

func New(t Transport, dial Dialer) *Relay {
	return &Relay{t: t, dial: dial, streams: map[uint32]net.Conn{}}
}

// Run reads frames until the transport ends or the context is done.
//
// Returns the transport's error, including io.EOF for an orderly
// close. A caller reconnecting on error should treat EOF as "the
// server hung up" and back off like any other failure: a tunnel that
// reconnects instantly on a server that is refusing it is a loop.
func (r *Relay) Run(ctx context.Context) error {
	defer r.shutdown()
	for {
		raw, err := r.t.Recv(ctx)
		if err != nil {
			return err
		}
		f, err := Decode(raw)
		if err != nil {
			// Framing is lost: there is no way to know where the
			// next frame starts, so carrying on would feed one
			// stream's bytes to another. The tunnel ends.
			return fmt.Errorf("tunnel framing lost: %w", err)
		}
		r.handle(ctx, f)
	}
}

func (r *Relay) handle(ctx context.Context, f Frame) {
	switch f.Kind {
	case OPEN:
		host, port, err := DecodeOpen(f)
		if err != nil {
			r.fail(ctx, f.Stream, "malformed OPEN")
			return
		}
		go r.open(ctx, f.Stream, host, port)
	case DATA:
		if c := r.conn(f.Stream); c != nil {
			// Blocking on purpose. A target that is not reading is
			// backpressure, and dropping the bytes instead would
			// corrupt the stream silently -- which on a proxied TLS
			// session is a handshake failure nobody can explain.
			if _, err := c.Write(f.Payload); err != nil {
				r.endStream(ctx, f.Stream, true)
			}
		}
	case CLOSE:
		r.endStream(ctx, f.Stream, false)
	case OPENED, FAILED:
		// These travel the other way. A server sending one is either
		// confused or not the server; either way this agent has
		// nothing to do with it.
	}
}

// open dials and, on success, pumps the target back up the tunnel.
func (r *Relay) open(ctx context.Context, id uint32, host string, port int) {
	c, err := r.dial(ctx, host, port)
	if err != nil {
		// The reason goes to the operator, not to the client: a
		// SOCKS reply has five codes and none of them say "no such
		// host". Truncated because it is a remote-controlled string.
		r.fail(ctx, id, trunc(err.Error(), 200))
		return
	}
	if !r.add(id, c) {
		// The relay shut down between the dial starting and landing.
		_ = c.Close()
		return
	}
	if err := r.send(ctx, OPENED, id, nil); err != nil {
		r.endStream(ctx, id, true)
		return
	}
	r.pump(ctx, id, c)
}

// pump copies target -> tunnel until either end stops.
func (r *Relay) pump(ctx context.Context, id uint32, c net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if serr := r.send(ctx, DATA, id, buf[:n]); serr != nil {
				r.endStream(ctx, id, true)
				return
			}
		}
		if err != nil {
			// ALWAYS tell the server, EOF or not. EOF is the normal
			// end of a request rather than a fault, but the far side
			// does not care which it was -- it cares that the stream
			// is over, and a server never told is a server waiting
			// on a stream that will not speak again.
			//
			// The first version passed `!errors.Is(err, io.EOF)`
			// here, which suppressed the CLOSE on precisely the
			// common case. TestTargetHangupIsReportedUp is that bug.
			r.endStream(ctx, id, true)
			return
		}
	}
}

func (r *Relay) send(ctx context.Context, kind byte, id uint32, p []byte) error {
	raw, err := Encode(kind, id, p)
	if err != nil {
		return err
	}
	return r.t.Send(ctx, raw)
}

func (r *Relay) fail(ctx context.Context, id uint32, why string) {
	_ = r.send(ctx, FAILED, id, []byte(why))
}

// add registers a live stream. False means the relay is shutting
// down and the caller should close what it just opened.
func (r *Relay) add(id uint32, c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if old, ok := r.streams[id]; ok {
		// The server allocates ids; a reused one means the two sides
		// disagree about what is live. Close the old rather than
		// leak it, and let the new one stand.
		_ = old.Close()
	}
	r.streams[id] = c
	return true
}

func (r *Relay) conn(id uint32) net.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[id]
}

// endStream closes the target and, when `tell` is set, says so up the
// tunnel. `tell` is false when the CLOSE came FROM the server, which
// already knows.
func (r *Relay) endStream(ctx context.Context, id uint32, tell bool) {
	r.mu.Lock()
	c, ok := r.streams[id]
	delete(r.streams, id)
	r.mu.Unlock()
	if ok && c != nil {
		_ = c.Close()
	}
	if tell && ok {
		_ = r.send(ctx, CLOSE, id, nil)
	}
}

// shutdown closes every live stream. Called when Run returns, so a
// dropped tunnel does not leave sockets open against the client's
// estate -- which is both a resource leak and a thing somebody would
// have to explain.
func (r *Relay) shutdown() {
	r.mu.Lock()
	live := r.streams
	r.streams = map[uint32]net.Conn{}
	r.closed = true
	r.mu.Unlock()
	for _, c := range live {
		_ = c.Close()
	}
}

// Live reports how many streams are open. For the status the agent
// already reports; also what a test asserts on.
func (r *Relay) Live() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.streams)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
