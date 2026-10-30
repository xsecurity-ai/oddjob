package shell

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

// The reason the Mux exists. Two listeners allocating their own
// stream ids would both call their first callback 1, and the server
// would file a shell caught on one port into the session of a shell
// caught on the other. Nothing errors; the bytes land in the wrong
// transcript.
func TestTwoListenersDoNotShareStreamIDs(t *testing.T) {
	p := newPipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMux(p)
	go func() { _ = m.Run(ctx) }()
	defer m.Close()

	a, err := Open(ctx, m, 0)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	b, err := Open(ctx, m, 0)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() { _ = a.Run(ctx) }()
	go func() { _ = b.Run(ctx) }()

	ca := dialPort(t, a.Port)
	defer func() { _ = ca.Close() }()
	waitFor(t, "the first arrival", func() bool { return len(p.of(socksrelay.ARRIVED)) == 1 })
	cb := dialPort(t, b.Port)
	defer func() { _ = cb.Close() }()
	waitFor(t, "the second arrival", func() bool { return len(p.of(socksrelay.ARRIVED)) == 2 })

	arrivals := p.of(socksrelay.ARRIVED)
	if arrivals[0].Stream == arrivals[1].Stream {
		t.Fatalf("both callbacks got stream %d", arrivals[0].Stream)
	}

	// And each says which port caught it, so the server can tell
	// them apart even when the peer address is the same host.
	var first, second announcement
	_ = json.Unmarshal(arrivals[0].Payload, &first)
	_ = json.Unmarshal(arrivals[1].Payload, &second)
	if first.Port == second.Port {
		t.Errorf("both arrivals claim port %d", first.Port)
	}
	if first.Port != a.Port || second.Port != b.Port {
		t.Errorf("arrivals name the wrong ports: %d, %d (want %d, %d)",
			first.Port, second.Port, a.Port, b.Port)
	}
}

// Closing one listener must not end a shell on another. An operator
// removing a port from the configuration has said nothing about the
// session somebody is typing at on a different one.
func TestClosingOneListenerKeepsTheOther(t *testing.T) {
	p := newPipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMux(p)
	go func() { _ = m.Run(ctx) }()
	defer m.Close()

	a, _ := Open(ctx, m, 0)
	b, _ := Open(ctx, m, 0)
	go func() { _ = a.Run(ctx) }()
	go func() { _ = b.Run(ctx) }()
	defer func() { _ = b.Close() }()

	ca := dialPort(t, a.Port)
	defer func() { _ = ca.Close() }()
	cb := dialPort(t, b.Port)
	defer func() { _ = cb.Close() }()
	waitFor(t, "both arrivals", func() bool { return len(p.of(socksrelay.ARRIVED)) == 2 })

	_ = a.Close()

	// The surviving listener's shell still carries output home.
	_, _ = cb.Write([]byte("still here\n"))
	waitFor(t, "output from the survivor", func() bool {
		for _, f := range p.of(socksrelay.DATA) {
			if string(f.Payload) == "still here\n" {
				return true
			}
		}
		return false
	})
}

func dialPort(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	return c
}
