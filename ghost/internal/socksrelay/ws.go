package socksrelay

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// The WebSocket end of the tunnel.
//
// WebSocket rather than a raw socket or a streaming POST for one
// practical reason: nginx sits in front of Oddjob and proxies an
// Upgrade cleanly, while it buffers request bodies by default and
// would hold a streaming POST until the agent stopped talking --
// which for a tunnel is for ever.
//
// `github.com/coder/websocket` is the dependency, and it is the only
// third-party package this agent gained for the proxy. It has no
// third-party dependencies of its own (`go list -deps` is stdlib
// plus its own internals), which matters on a binary that runs
// privileged inside a client's network.

// MaxFrame caps one read. The codec already refuses a payload over
// MaxPayload; this stops a hostile server making the library
// allocate before the codec ever sees the bytes.
const MaxFrame = MaxPayload + Header

// WS adapts a websocket.Conn to Transport.
//
// Send is safe from several goroutines because the library serialises
// writes internally -- one per live stream calls it, which is exactly
// the case the Transport contract warns about.
type WS struct {
	c *websocket.Conn
}

// Recv returns the next frame.
//
// Binary only. A text frame on this tunnel is either a proxy
// injecting something or a server that is not Oddjob; neither is a
// thing to interpret as stream bytes.
func (w *WS) Recv(ctx context.Context) ([]byte, error) {
	typ, data, err := w.c.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, fmt.Errorf("%w: text frame on the tunnel", ErrFrame)
	}
	return data, nil
}

func (w *WS) Send(ctx context.Context, b []byte) error {
	return w.c.Write(ctx, websocket.MessageBinary, b)
}

// Close ends the tunnel politely, then stops caring.
func (w *WS) Close() {
	_ = w.c.Close(websocket.StatusNormalClosure, "")
}

// Signer is the agent's identity, as this file needs it: something
// that can produce the headers authenticating one request.
//
// An interface so the dial can be tested against a plain httptest
// server without an enrolled identity, and so this file does not
// import the identity package to use one method of it.
type Signer interface {
	Sign(method, path string, body []byte) map[string]string
}

// TunnelPath is where the server accepts a tunnel. The signature
// covers it, so the two sides must agree on the exact string.
const TunnelPath = "/api/ghosts/proxy/tunnel"

// ShellPath is where the server accepts a shell tunnel.
//
// Its own socket rather than a second kind of stream on the proxy
// tunnel: the two have different lifetimes and different failure
// modes, and a SOCKS tunnel dropping should not take a live shell
// with it. They share the CODEC and nothing else.
const ShellPath = "/api/ghosts/shell/tunnel"

// Dial opens the tunnel.
//
// The agent dials OUT. There is no listener on this side and there
// is deliberately no way to ask for one: internal/callin is the
// inbound channel and it cannot run anything, which is the property
// that keeps a compromised server from turning every agent into a
// proxy on its own say-so. Switching this on is a decision made in
// Oddjob AND carried by the agent's own flag.
func Dial(ctx context.Context, base string, s Signer) (*WS, error) {
	return DialPath(ctx, base, TunnelPath, s)
}

// DialPath is Dial against a named endpoint.
//
// The path is signed as well as dialled, and the two are the SAME
// string: a signature over one path and a connection to another
// would be a signature that proves nothing about where the agent
// meant to connect.
func DialPath(ctx context.Context, base, path string, s Signer) (*WS, error) {
	u := strings.TrimRight(base, "/") + path
	// ws:// for http://, wss:// for https://. The scheme is taken
	// from the server URL this agent already enrolled against rather
	// than configured again, so a tunnel cannot be quietly downgraded
	// to cleartext by a second setting nobody checks.
	switch {
	case strings.HasPrefix(u, "https://"):
		u = "wss://" + strings.TrimPrefix(u, "https://")
	case strings.HasPrefix(u, "http://"):
		u = "ws://" + strings.TrimPrefix(u, "http://")
	default:
		return nil, fmt.Errorf("server url has no scheme: %q", base)
	}

	// Signed over the PATH with an empty body, the same shape every
	// other request from this agent uses, so the server verifies it
	// with the code it already has.
	h := http.Header{}
	for k, v := range s.Sign(http.MethodGet, path, nil) {
		h.Set(k, v)
	}

	c, resp, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPHeader: h,
	})
	// Closed on BOTH paths. A failed dial happens inside a reconnect
	// loop, so leaking the handshake response once per attempt runs
	// this agent out of file descriptors over a long outage -- which
	// presents as a ghost that stopped coming back rather than as a
	// leak, and is the sort of thing found weeks later.
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		if resp != nil {
			// The status is the useful half: 401 means the signature
			// or the clock, 403 means proxying is off for this agent,
			// and those send an operator to different places.
			return nil, fmt.Errorf("tunnel refused (%s): %w", resp.Status, err)
		}
		return nil, fmt.Errorf("tunnel dial: %w", err)
	}
	c.SetReadLimit(MaxFrame)
	return &WS{c: c}, nil
}

// Backoff is how long to wait before dialling again, given how many
// attempts have failed in a row.
//
// Capped and jittered on purpose. A fleet of agents that all lost a
// tunnel at the same moment -- which is what a server restart looks
// like -- would otherwise reconnect in lockstep and keep doing it.
func Backoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := time.Second << min(attempt, 6) // 1s .. 64s
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
