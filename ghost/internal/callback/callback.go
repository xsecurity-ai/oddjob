// Package callback holds a port open while a test runs, and says what
// arrived on it.
//
// A great many web findings are only observable out of band. An SSRF
// that returns nothing, an XXE that renders no entity, a blind command
// injection, a DNS-less log4j payload: the request succeeds, the
// response says nothing, and the only evidence the thing worked is a
// connection arriving somewhere you control. Until now a Ghost could
// send that payload and had nowhere to catch the answer, so the whole
// class of finding came back "no".
//
// # Why this is on the Ghost and not on Oddjob
//
// Because the Ghost is already where the engagement's traffic comes
// from. A callback caught on Oddjob would be a callback to the
// operator's server from the client's estate, which is a different
// path through a different firewall than the one being tested, and on
// most engagements is not reachable at all. The Ghost is on the
// infrastructure chosen for this job and is already attributable.
//
// # The three answers
//
// Binding a port and hearing nothing is NOT evidence of absence. A
// cloud security group drops inbound 443 by default, and a listener
// nothing can reach produces exactly the same silence as a target that
// is not vulnerable. So the listener is probed from outside before the
// payload goes anywhere, and the result says which of three things
// happened:
//
//	found     something connected. The payload worked.
//	absent    the port was proved reachable and nothing came.
//	unknown   the port could not be proved reachable, so this test
//	          measured nothing and must not be reported as a pass.
//
// Reaching for the third rather than collapsing it into the second is
// the whole reason this package is careful.
package callback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
	"unicode"
)

// Preferred is the bind order, and it is about what a target is
// allowed to talk to rather than what is convenient here.
//
// Egress from a client's estate is routinely filtered to the ports a
// browser uses, so a callback on 47000 is refused by the client's own
// firewall and the test reports "not vulnerable" about the firewall.
// 443 first because it is the one port that is almost always allowed
// out, then 80, then the common alternates.
//
// Binding 443 and 80 needs CAP_NET_BIND_SERVICE, which the Ghost's
// compose file grants and the README explains. Without it those two
// fail and the walk simply continues -- a Ghost that cannot bind 443
// still works, it just catches fewer callbacks.
var Preferred = []int{443, 80, 8443, 8080, 8000, 10000}

// MaxPreview is how much of a callback's first datagram or segment is
// kept. Enough to recognise an HTTP request line and a Host header,
// which is what identifies WHICH payload fired; not so much that a
// target echoing a megabyte fills the result.
const MaxPreview = 512

// Hit is one connection that arrived.
type Hit struct {
	At      time.Time `json:"at"`
	From    string    `json:"from"`
	Bytes   int       `json:"bytes"`
	Preview string    `json:"preview,omitempty"`
}

// Listener holds one port for the life of one task.
type Listener struct {
	Proto string // tcp | udp
	Port  int
	// Where a target should be told to connect. The Ghost's outbound
	// address, which is the only one that means anything from the
	// other side of a NAT -- see recon.OutboundAddress.
	Advertised string

	tcp  net.Listener
	udp  net.PacketConn
	mu   sync.Mutex
	hits []Hit
	done chan struct{}
	once sync.Once
}

// Open binds the first port of `Preferred` that is free, falling back
// to an ephemeral one.
//
// **An ephemeral port is a worse test, not a failed one.** A target
// whose egress is filtered will not reach it, so the run is more
// likely to come back `unknown` -- which is the honest outcome and is
// why the fallback exists rather than the whole thing refusing.
func Open(ctx context.Context, proto, advertiseHost string) (*Listener, error) {
	proto = normaliseProto(proto)
	if proto == "" {
		return nil, fmt.Errorf("callback: proto must be tcp or udp")
	}
	var last error
	for _, p := range append(append([]int{}, Preferred...), 0) {
		l, err := bind(ctx, proto, p)
		if err != nil {
			last = err
			continue
		}
		l.Advertised = advertiseHost
		go l.accept()
		return l, nil
	}
	return nil, fmt.Errorf("callback: no port could be bound: %w", last)
}

func normaliseProto(p string) string {
	switch p {
	case "tcp", "TCP", "":
		return "tcp"
	case "udp", "UDP":
		return "udp"
	}
	return ""
}

func bind(ctx context.Context, proto string, port int) (*Listener, error) {
	addr := ":" + strconv.Itoa(port)
	l := &Listener{Proto: proto, done: make(chan struct{})}
	var lc net.ListenConfig
	if proto == "udp" {
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		ua, ok := pc.LocalAddr().(*net.UDPAddr)
		if !ok {
			_ = pc.Close()
			return nil, fmt.Errorf("callback: %s is not a udp address",
				pc.LocalAddr())
		}
		l.udp, l.Port = pc, ua.Port
		return l, nil
	}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("callback: %s is not a tcp address", ln.Addr())
	}
	l.tcp, l.Port = ln, ta.Port
	return l, nil
}

// Address is what a payload should be pointed at.
func (l *Listener) Address() string {
	return net.JoinHostPort(l.Advertised, strconv.Itoa(l.Port))
}

func (l *Listener) accept() {
	if l.udp != nil {
		buf := make([]byte, 4096)
		for {
			n, from, err := l.udp.ReadFrom(buf)
			if n > 0 {
				l.record(from.String(), buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	for {
		c, err := l.tcp.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			// A deadline, because a target that connects and says
			// nothing would otherwise hold the goroutine for the life
			// of the task. The connection ITSELF is the evidence; the
			// bytes are a bonus that identifies which payload fired.
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			n, _ := c.Read(buf)
			l.record(c.RemoteAddr().String(), buf[:n])
		}(c)
	}
}

func (l *Listener) record(from string, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits = append(l.hits, Hit{
		At: time.Now().UTC(), From: from, Bytes: len(body),
		Preview: preview(body),
	})
}

// preview keeps the readable head of what arrived.
//
// Escaped rather than truncated-and-shipped: this lands in a JSON
// result, goes into the database and is rendered in a browser, and a
// target is free to send whatever bytes it likes. A control character
// surviving that path is somebody else choosing what our UI renders.
func preview(b []byte) string {
	if len(b) > MaxPreview {
		b = b[:MaxPreview]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r):
			out = append(out, r)
		default:
			out = append(out, '.')
		}
	}
	return string(out)
}

// Hits returns what has arrived so far.
func (l *Listener) Hits() []Hit {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Hit(nil), l.hits...)
}

// Take removes and returns the first hit whose preview contains
// `nonce`. Used to pull the reachability probe back out of the list:
// it is our own traffic and reporting it as a callback would be the
// tool finding itself.
func (l *Listener) Take(nonce string) bool {
	if nonce == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, h := range l.hits {
		if contains(h.Preview, nonce) {
			l.hits = append(l.hits[:i], l.hits[i+1:]...)
			return true
		}
	}
	return false
}

func contains(hay, needle string) bool {
	return len(needle) > 0 && len(hay) >= len(needle) &&
		indexOf(hay, needle) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// Close stops listening and returns everything that arrived.
func (l *Listener) Close() []Hit {
	l.once.Do(func() {
		close(l.done)
		if l.tcp != nil {
			_ = l.tcp.Close()
		}
		if l.udp != nil {
			_ = l.udp.Close()
		}
	})
	return l.Hits()
}

// WaitFor blocks until a hit arrives or the window closes.
//
// Returns as soon as the FIRST one lands rather than always waiting
// out the window: one callback is the finding, and the remaining
// seconds would only be spent proving it twice. The window is still
// honoured when nothing comes, because an out-of-band callback is
// routinely seconds to minutes behind the request that caused it --
// a queued job, a retry, a crawler picking the URL up later.
func (l *Listener) WaitFor(ctx context.Context, window time.Duration) []Hit {
	deadline := time.After(window)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if h := l.Hits(); len(h) > 0 {
			return h
		}
		select {
		case <-ctx.Done():
			return l.Hits()
		case <-deadline:
			return l.Hits()
		case <-tick.C:
		}
	}
}

// ErrNoPort is returned when nothing could be bound at all.
var ErrNoPort = errors.New("callback: no port could be bound")
