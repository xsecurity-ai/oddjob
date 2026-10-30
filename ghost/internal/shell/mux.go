package shell

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

// sink is one live callback, whatever kind of socket it arrived on.
//
// An interface rather than a net.Conn because a UDP "session" is not
// a connection: it is a peer address on a shared PacketConn, and
// writing to it means sending a datagram rather than writing to a
// stream. Both are the same thing to the mux -- somewhere bytes go.
type sink interface {
	write(b []byte) error
	close() error
}

// Mux is one shell tunnel carrying every listener this Ghost holds.
//
// It exists because a Ghost can hold several ports and there is only
// one websocket home. Two listeners each reading the transport would
// steal each other's frames, and two allocating their own stream ids
// would both call their first callback 1 -- so the server would file
// a shell caught on 443 into the session of a shell caught on 8080.
// Neither failure announces itself: the bytes simply land in the
// wrong transcript.
//
// So the mux owns the transport, the read loop and the id space, and
// a listener owns nothing but its socket.
type Mux struct {
	t Transport

	mu     sync.Mutex
	sinks  map[uint32]sink
	nextID atomic.Uint32
	sendMu sync.Mutex
}

func NewMux(t Transport) *Mux {
	return &Mux{t: t, sinks: map[uint32]sink{}}
}

// add registers a callback and returns the stream id it owns.
func (m *Mux) add(s sink) uint32 {
	id := m.nextID.Add(1)
	m.mu.Lock()
	m.sinks[id] = s
	m.mu.Unlock()
	return id
}

// drop ends one stream and tells the server. Safe to call twice: the
// second call finds nothing and says nothing, which matters because
// both ends of a socket closing is the ordinary way a shell ends.
func (m *Mux) drop(ctx context.Context, id uint32) {
	m.mu.Lock()
	s := m.sinks[id]
	delete(m.sinks, id)
	m.mu.Unlock()
	if s == nil {
		return
	}
	_ = s.close()
	_ = m.send(ctx, socksrelay.CLOSE, id, nil)
}

// send serialises writes. A websocket is one connection and two
// goroutines writing to it interleave into something neither end can
// decode -- the failure this mutex exists for is silent corruption
// rather than an error.
func (m *Mux) send(ctx context.Context, kind byte, id uint32,
	payload []byte) error {
	b, err := socksrelay.Encode(kind, id, payload)
	if err != nil {
		return err
	}
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	return m.t.Send(ctx, b)
}

// Run carries what the server sends down to the right socket, until
// the transport ends.
//
// One pump for every listener. Returning closes nothing by itself --
// Close does that -- because the caller redials and the sockets on
// this side may still be perfectly alive.
func (m *Mux) Run(ctx context.Context) error {
	for {
		raw, err := m.t.Recv(ctx)
		if err != nil {
			return err
		}
		f, err := socksrelay.Decode(raw)
		if err != nil {
			// Framing is lost, not one frame: carrying on would feed
			// one session's bytes to another. The tunnel is dropped
			// and redialled, which is what the proxy relay does for
			// the same reason.
			return err
		}
		m.mu.Lock()
		s := m.sinks[f.Stream]
		m.mu.Unlock()
		if s == nil {
			continue
		}
		switch f.Kind {
		case socksrelay.DATA:
			if err := s.write(f.Payload); err != nil {
				m.drop(ctx, f.Stream)
			}
		case socksrelay.CLOSE:
			m.drop(ctx, f.Stream)
		}
	}
}

// Close ends every live callback on this tunnel.
func (m *Mux) Close() {
	m.mu.Lock()
	all := make([]sink, 0, len(m.sinks))
	for id, s := range m.sinks {
		all = append(all, s)
		delete(m.sinks, id)
	}
	m.mu.Unlock()
	for _, s := range all {
		_ = s.close()
	}
}

// live is how many callbacks are open across every listener.
func (m *Mux) live() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sinks)
}

// sinkFor is how the UDP listener reaches its own peer records.
// Unexported and only used inside the package: a sink is an
// implementation detail of whoever registered it.
func (m *Mux) sinkFor(id uint32) sink {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sinks[id]
}
