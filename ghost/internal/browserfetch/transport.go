package browserfetch

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ChromeUA is the User-Agent the handshake below is pretending to
// belong to.
//
// It has to MATCH. A Chrome ClientHello carrying a curl User-Agent
// is a sharper signal than either on its own -- the mismatch is
// itself what several products score on -- so a caller that
// overrides one must override the other, and `Transport` refuses to
// guess.
const ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) " +
	"Chrome/155.0.0.0 Safari/537.36"

// Transport is an http.RoundTripper whose TLS handshake is Chrome's.
//
// **HTTP/1.1 only, deliberately.** utls gives us Chrome's
// ClientHello, which advertises h2 -- but the HTTP/2 connection
// Go would then open has its own fingerprint (SETTINGS values,
// window size, header-table size, pseudo-header order) and Go's
// does not look like Chrome's either. Advertising h2 and then
// speaking Go's dialect of it is a worse tell than not advertising
// it, so the ALPN list is narrowed to http/1.1 after the preset is
// applied.
//
// That narrowing does not change the JA3: JA3 hashes the extension
// IDs, not their contents, and the ALPN extension is present
// either way.
//
// **What this does not fix.** Header ORDER is Go's, because
// net/http writes headers sorted and controlling that means writing
// requests by hand. JA4_H and the more thorough HTTP fingerprints
// look at it. And nothing here solves an active JavaScript
// challenge -- a page that requires running JS to get a clearance
// cookie still needs a real browser. This handles the passive
// check, which is the one that silently turns a live site into a
// 403 in an inventory.
type Transport struct {
	// Dialer for the underlying TCP connection. Zero value is fine.
	Dialer net.Dialer
	// Handshake deadline. Zero means 15s.
	HandshakeTimeout time.Duration
	// Skip certificate verification. An engagement frequently meets
	// an expired or mismatched certificate on a staging host, and
	// refusing to read the page over it would lose the evidence --
	// the certificate is recorded as a finding in its own right
	// elsewhere, not enforced here.
	InsecureSkipVerify bool

	inner *http.Transport
	once  bool
}

func (t *Transport) timeout() time.Duration {
	if t.HandshakeTimeout > 0 {
		return t.HandshakeTimeout
	}
	return 15 * time.Second
}

// dialTLS performs Chrome's handshake and hands back the connection.
func (t *Transport) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := t.Dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}
	c := utls.UClient(raw, cfg, utls.HelloChrome_Auto)

	// The handshake state has to be built before the extensions can
	// be reached: HelloChrome_Auto is a recipe, and until it is
	// applied there is no ALPN extension to narrow.
	if err := c.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("build chrome hello: %w", err)
	}
	for _, ext := range c.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	// Rebuilt, because the extension was edited after the first
	// build serialised it. Without this the connection negotiates
	// h2 anyway and the whole narrowing above is decorative.
	if err := c.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("rebuild chrome hello: %w", err)
	}

	deadline := time.Now().Add(t.timeout())
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if err := c.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	// Cleared: the deadline above is for the handshake, and leaving
	// it set would kill the connection partway through a slow body.
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func (t *Transport) build() {
	if t.once {
		return
	}
	t.once = true
	t.inner = &http.Transport{
		DialContext:    t.Dialer.DialContext,
		DialTLSContext: t.dialTLS,
		// Off, because DialTLSContext hands back a *utls.UConn and
		// Go's h2 upgrade path cannot drive it. See the type
		// comment: h2 is not wanted here anyway.
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: t.timeout(),
		MaxIdleConns:        8,
		IdleConnTimeout:     30 * time.Second,
		// Plain http:// still goes out as itself. There is no TLS
		// fingerprint to copy on port 80 and pretending otherwise
		// would just be a lie in a comment.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: t.InsecureSkipVerify}, //nolint:gosec // see InsecureSkipVerify
	}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.build()
	return t.inner.RoundTrip(r)
}

// CloseIdleConnections implements the optional interface http.Client
// uses, so a caller that finishes with this does not leave sockets
// open to a client's estate.
func (t *Transport) CloseIdleConnections() {
	if t.inner != nil {
		t.inner.CloseIdleConnections()
	}
}

// Client is an http.Client whose handshake is Chrome's.
//
// `ua` must be the Chrome User-Agent -- pass `ChromeUA` -- because a
// browser handshake under a tool's User-Agent scores worse than
// either alone. It is a parameter rather than a constant so a
// caller can pass a newer Chrome string without editing this file,
// and empty means `ChromeUA`.
func Client(timeout time.Duration, insecure bool) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &Transport{InsecureSkipVerify: insecure},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// Headers puts the rest of a browser's request on `h`.
//
// A Chrome handshake followed by three headers is still obviously
// not Chrome. These are the ones a real request always carries and
// a Go one never does; the Client Hints are sent only because
// Chrome sends them unconditionally on https.
//
// Existing values are not overwritten: the project's own
// attributable User-Agent, where one is configured, is the whole
// point of having it and this must not quietly replace it.
func Headers(h http.Header, ua string) {
	if ua == "" {
		ua = ChromeUA
	}
	for k, v := range map[string]string{
		"User-Agent": ua,
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9," +
			"image/avif,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language":           "en-US,en;q=0.9",
		"Accept-Encoding":           "gzip, deflate",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Sec-Ch-Ua": `"Chromium";v="155", "Not;A=Brand";v="24", ` +
			`"Google Chrome";v="155"`,
		"Sec-Ch-Ua-Mobile":   "?0",
		"Sec-Ch-Ua-Platform": `"Windows"`,
	} {
		if h.Get(k) == "" {
			h.Set(k, v)
		}
	}
}
