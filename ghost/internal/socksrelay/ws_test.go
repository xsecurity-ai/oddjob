package socksrelay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeSigner stands in for an enrolled identity. The dial only needs
// headers, which is why Signer is one method.
type fakeSigner struct{ seen map[string]string }

func (f *fakeSigner) Sign(method, path string, _ []byte) map[string]string {
	f.seen = map[string]string{"method": method, "path": path}
	return map[string]string{
		"X-Ghost-Agent":     "7",
		"X-Ghost-Signature": "sig",
		"X-Ghost-Timestamp": "1",
		"X-Ghost-Nonce":     "n",
	}
}

// wsEcho accepts a tunnel and hands the raw conn to `use`.
func wsEcho(t *testing.T, use func(ctx context.Context, c *websocket.Conn)) (
	*httptest.Server, *[]*http.Request) {
	t.Helper()
	var got []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			got = append(got, r.Clone(context.Background()))
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = c.CloseNow() }()
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			use(ctx, c)
		}))
	return srv, &got
}

func TestDialSignsTheTunnelPath(t *testing.T) {
	srv, reqs := wsEcho(t, func(ctx context.Context, c *websocket.Conn) {
		<-ctx.Done()
	})
	defer srv.Close()

	s := &fakeSigner{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, err := Dial(ctx, srv.URL, s)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	// The signature covers the path, so the two sides must agree on
	// the exact string or every tunnel is a 401.
	if s.seen["path"] != TunnelPath {
		t.Errorf("signed %q, wanted %q", s.seen["path"], TunnelPath)
	}
	if s.seen["method"] != http.MethodGet {
		t.Errorf("signed method %q", s.seen["method"])
	}
	if len(*reqs) == 0 {
		t.Fatal("server saw no request")
	}
	if (*reqs)[0].Header.Get("X-Ghost-Agent") != "7" {
		t.Error("the agent header did not reach the server")
	}
	if (*reqs)[0].URL.Path != TunnelPath {
		t.Errorf("dialled %q", (*reqs)[0].URL.Path)
	}
}

func TestDialRefusesAnUrlWithNoScheme(t *testing.T) {
	// A bare host would otherwise be dialled as whatever the library
	// guesses, and a tunnel downgraded to cleartext is the one
	// failure mode worth refusing outright.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Dial(ctx, "oddjob.example:8443", &fakeSigner{}); err == nil {
		t.Error("dialled a url with no scheme")
	}
}

func TestTextFramesAreRefused(t *testing.T) {
	// A text frame here is a proxy injecting something, or a server
	// that is not Oddjob. Neither is stream bytes.
	srv, _ := wsEcho(t, func(ctx context.Context, c *websocket.Conn) {
		_ = c.Write(ctx, websocket.MessageText, []byte("hello"))
		<-ctx.Done()
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, err := Dial(ctx, srv.URL, &fakeSigner{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()
	if _, err := ws.Recv(ctx); err == nil {
		t.Error("a text frame was accepted as stream bytes")
	}
}

// The whole path: a real WebSocket, the real relay, a real target.
func TestEndToEndOverAWebSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	port := portOf(t, ln)

	type result struct {
		opened bool
		echo   string
	}
	out := make(chan result, 1)

	srv, _ := wsEcho(t, func(ctx context.Context, c *websocket.Conn) {
		// The SERVER side of the tunnel: ask the agent to dial, then
		// push a byte and read it back.
		open, _ := EncodeOpen(1, "127.0.0.1", port)
		if err := c.Write(ctx, websocket.MessageBinary, open); err != nil {
			return
		}
		var r result
		for {
			_, raw, err := c.Read(ctx)
			if err != nil {
				out <- r
				return
			}
			f, err := Decode(raw)
			if err != nil {
				out <- r
				return
			}
			switch f.Kind {
			case OPENED:
				r.opened = true
				d, _ := Encode(DATA, 1, []byte("ping"))
				_ = c.Write(ctx, websocket.MessageBinary, d)
			case DATA:
				r.echo = string(f.Payload)
				out <- r
				return
			case FAILED:
				out <- r
				return
			}
		}
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, err := Dial(ctx, srv.URL, &fakeSigner{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	r := New(ws, NetDialer(3*time.Second))
	go func() { _ = r.Run(ctx) }()

	select {
	case got := <-out:
		if !got.opened {
			t.Fatal("the agent never reported the dial succeeded")
		}
		if got.echo != "ping" {
			t.Errorf("echoed %q through the tunnel, wanted \"ping\"", got.echo)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("nothing came back through the tunnel")
	}
}

func TestBackoffIsCappedAndClimbs(t *testing.T) {
	// A fleet that all lost a tunnel at once -- which is what a
	// server restart looks like -- must not reconnect in lockstep
	// for ever.
	if Backoff(0) >= Backoff(3) {
		t.Error("backoff does not climb")
	}
	for _, n := range []int{10, 100, 1 << 20} {
		if Backoff(n) > time.Minute {
			t.Errorf("backoff(%d) = %v, over the cap", n, Backoff(n))
		}
	}
	if Backoff(-5) <= 0 {
		t.Error("a negative attempt produced a non-positive wait")
	}
}
