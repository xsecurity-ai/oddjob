package shell

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

func startUDP(t *testing.T) (*PacketListener, *pipe) {
	t.Helper()
	p := newPipe()
	ctx, cancel := context.WithCancel(context.Background())
	m := NewMux(p)
	go func() { _ = m.Run(ctx) }()
	l, err := OpenPacket(ctx, m, 0)
	if err != nil {
		cancel()
		t.Fatalf("open udp: %v", err)
	}
	go func() { _ = l.Run(ctx) }()
	t.Cleanup(func() { _ = l.Close(); m.Close(); cancel() })
	return l, p
}

func sendTo(t *testing.T, port int, msg string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write udp: %v", err)
	}
	return c
}

// A datagram is a session. There is no accept and no connection, so
// the peer address is the only thing that distinguishes two callers
// on one port.
func TestUDPFirstDatagramOpensASession(t *testing.T) {
	l, p := startUDP(t)
	c := sendTo(t, l.Port, "uid=0(root)\n")
	defer func() { _ = c.Close() }()

	waitFor(t, "the arrival", func() bool {
		return len(p.of(socksrelay.ARRIVED)) == 1
	})
	var got announcement
	if err := json.Unmarshal(p.of(socksrelay.ARRIVED)[0].Payload, &got); err != nil {
		t.Fatalf("arrival is not an announcement: %v", err)
	}
	if got.Protocol != "udp" {
		t.Errorf("a udp callback should say udp, said %q", got.Protocol)
	}
	if got.Port != l.Port {
		t.Errorf("arrival names port %d, listener is on %d", got.Port, l.Port)
	}

	waitFor(t, "the output", func() bool { return len(p.of(socksrelay.DATA)) == 1 })
	if s := string(p.of(socksrelay.DATA)[0].Payload); s != "uid=0(root)\n" {
		t.Errorf("output came back as %q", s)
	}
}

// The silent one. A second datagram from the SAME peer is the same
// shell: announcing it again would file one session's output as a
// second session, and the transcript of the first would stop dead
// after one line.
func TestUDPSamePeerIsOneSession(t *testing.T) {
	l, p := startUDP(t)
	c := sendTo(t, l.Port, "one\n")
	defer func() { _ = c.Close() }()
	waitFor(t, "the first", func() bool { return len(p.of(socksrelay.DATA)) == 1 })

	if _, err := c.Write([]byte("two\n")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	waitFor(t, "the second", func() bool { return len(p.of(socksrelay.DATA)) == 2 })

	if n := len(p.of(socksrelay.ARRIVED)); n != 1 {
		t.Errorf("the same peer announced %d times, want 1", n)
	}
	a := p.of(socksrelay.DATA)
	if a[0].Stream != a[1].Stream {
		t.Errorf("one peer's output split across streams %d and %d",
			a[0].Stream, a[1].Stream)
	}
}

// Two peers on one port are two shells.
func TestUDPTwoPeersAreTwoSessions(t *testing.T) {
	l, p := startUDP(t)
	c1 := sendTo(t, l.Port, "first\n")
	defer func() { _ = c1.Close() }()
	waitFor(t, "the first peer", func() bool {
		return len(p.of(socksrelay.ARRIVED)) == 1
	})
	c2 := sendTo(t, l.Port, "second\n")
	defer func() { _ = c2.Close() }()
	waitFor(t, "the second peer", func() bool {
		return len(p.of(socksrelay.ARRIVED)) == 2
	})

	a := p.of(socksrelay.ARRIVED)
	if a[0].Stream == a[1].Stream {
		t.Fatalf("two peers share stream %d", a[0].Stream)
	}
	var one, two announcement
	_ = json.Unmarshal(a[0].Payload, &one)
	_ = json.Unmarshal(a[1].Payload, &two)
	if one.Peer == two.Peer {
		t.Errorf("both sessions claim peer %q", one.Peer)
	}
}

// What the operator types has to reach the right peer. With one
// shared socket, sending to the wrong address is a command typed at
// one host arriving at another -- which on an engagement is a
// serious thing to get wrong.
func TestUDPServerDataReachesThatPeer(t *testing.T) {
	l, p := startUDP(t)
	c := sendTo(t, l.Port, "hello\n")
	defer func() { _ = c.Close() }()
	waitFor(t, "the arrival", func() bool {
		return len(p.of(socksrelay.ARRIVED)) == 1
	})
	stream := p.of(socksrelay.ARRIVED)[0].Stream

	frame, err := socksrelay.Encode(socksrelay.DATA, stream, []byte("id\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	p.in <- frame

	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("the peer never got it: %v", err)
	}
	if string(buf[:n]) != "id\n" {
		t.Errorf("peer got %q", buf[:n])
	}
}

// Closing the listener must not be reported as a failure: it is this
// shutting down on purpose, and an error there makes every clean
// stop look like a fault in the agent's log.
func TestUDPCloseIsNotAnError(t *testing.T) {
	p := newPipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMux(p)
	l, err := OpenPacket(ctx, m, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Errorf("a cancelled listener returned %v", err)
	}
}
