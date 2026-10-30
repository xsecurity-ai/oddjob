package shell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

// UDPIdle ends a peer's session when it has said nothing for this
// long.
//
// UDP has no FIN, so this is the ONLY way a udp session ever ends.
// Two hours matches the TCP idle timeout: a shell an operator is
// thinking at must not be reaped, and a peer that has genuinely gone
// must not hold a stream and a row that both claim to be live.
const UDPIdle = 2 * time.Hour

// datagram is one peer talking to a UDP listener.
//
// "One peer" is the whole session concept here. A PacketConn has no
// accept and no connection, so the only thing distinguishing two
// callers on one port is the address they send from -- which is
// exactly what the server files a session against.
type datagram struct {
	pc   net.PacketConn
	addr net.Addr
	last time.Time
}

func (d *datagram) write(b []byte) error {
	_, err := d.pc.WriteTo(b, d.addr)
	return err
}

// close is a no-op, and has to be: the socket is SHARED by every
// peer on this port. Closing it because one shell ended would take
// every other session on the listener with it.
func (d *datagram) close() error { return nil }

// PacketListener holds one UDP port and relays every peer that sends
// to it.
type PacketListener struct {
	Port int

	m  *Mux
	pc net.PacketConn

	mu    sync.Mutex
	peers map[string]uint32
}

// OpenPacket binds a UDP port.
func OpenPacket(ctx context.Context, m *Mux, port int) (*PacketListener, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("shell: cannot listen on udp %d: %w", port, err)
	}
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("shell: %s is not a udp address", pc.LocalAddr())
	}
	return &PacketListener{Port: addr.Port, m: m, pc: pc,
		peers: map[string]uint32{}}, nil
}

// Run reads datagrams until the context ends or the socket closes.
//
// One goroutine, not one per peer: there is one socket and reading
// it from two places would deal alternate datagrams to each, which
// splits one shell's output across two readers in an order neither
// can restore.
func (p *PacketListener) Run(ctx context.Context) error {
	buf := make([]byte, ReadChunk)
	for {
		// A select rather than `ctx.Err() != nil`: ending because
		// the caller asked is not an error, and this says so in a
		// shape that reads as one.
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		// A deadline rather than a blocking read, so a cancelled
		// context is noticed. ReadFrom on a PacketConn does not take
		// a context and nothing else interrupts it.
		_ = p.pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, addr, err := p.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				p.reap(ctx)
				continue
			}
			if ctx.Err() != nil {
				// nil, deliberately: a cancelled context or a
				// closed socket is this shutting down on purpose,
				// and returning the error would make every clean
				// stop look like a failure in the agent's log.
				return nil //nolint:nilerr // a clean shutdown is not an error
			}
			return err
		}
		if n == 0 {
			continue
		}
		id, fresh := p.stream(addr)
		if fresh {
			// Announced before any bytes move, exactly as the TCP
			// side does: a DATA frame for a stream the server has
			// never heard of has nowhere to go.
			_ = p.m.send(ctx, socksrelay.ARRIVED, id,
				announce(addr.String(), "udp", p.Port))
		}
		_ = p.m.send(ctx, socksrelay.DATA, id, buf[:n])
	}
}

// stream finds or makes the session for a peer. -> (id, is new).
func (p *PacketListener) stream(addr net.Addr) (uint32, bool) {
	key := addr.String()
	p.mu.Lock()
	id, known := p.peers[key]
	p.mu.Unlock()
	if known {
		p.touch(id)
		return id, false
	}
	d := &datagram{pc: p.pc, addr: addr, last: time.Now()}
	id = p.m.add(d)
	p.mu.Lock()
	p.peers[key] = id
	p.mu.Unlock()
	return id, true
}

func (p *PacketListener) touch(id uint32) {
	if d, ok := p.m.sinkFor(id).(*datagram); ok {
		d.last = time.Now()
	}
}

// reap ends peers that have gone quiet. Called on every read
// timeout, which is the only clock this listener has.
func (p *PacketListener) reap(ctx context.Context) {
	cut := time.Now().Add(-UDPIdle)
	var stale []string
	p.mu.Lock()
	for key, id := range p.peers {
		if d, ok := p.m.sinkFor(id).(*datagram); !ok || d.last.Before(cut) {
			stale = append(stale, key)
		}
	}
	ids := make([]uint32, 0, len(stale))
	for _, key := range stale {
		ids = append(ids, p.peers[key])
		delete(p.peers, key)
	}
	p.mu.Unlock()
	for _, id := range ids {
		p.m.drop(ctx, id)
	}
}

// Close stops listening. Like the TCP side, the sessions belong to
// the Mux -- but here closing the socket does end them, because they
// share it. Said out loud because it is the one place the two
// protocols genuinely differ.
func (p *PacketListener) Close() error { return p.pc.Close() }

// Live is how many peers are talking to this tunnel.
func (p *PacketListener) Live() int { return p.m.live() }
