package shell

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// One listener takes both plain and TLS callbacks.
//
// The alternative was asking the operator to declare which when the
// listener is made, and that is a question they often cannot answer:
// the payload is written later, by somebody else, or changed after
// the first attempt failed. A listener that only speaks one of the
// two is a listener that silently eats half the callbacks aimed at
// it -- the connection lands, the handshake goes nowhere, and the
// session reads as a peer that connected and said nothing.
//
// So the protocol is decided per CONNECTION, from the first bytes.

// HandshakeWait bounds how long we wait for a peer to say which it
// is.
//
// **A TLS client always speaks first** -- the ClientHello follows
// the TCP handshake immediately, because that is the protocol. A
// reverse shell never speaks first: `nc -e /bin/sh` connects and
// waits to be typed at. So silence for this long means plain, and
// the window only has to cover the round trip of a hello that has
// already been sent.
//
// One second, not three. This delay is paid by every PLAIN shell,
// which is the common case, and it is time the operator spends
// looking at a session that has not appeared yet. A second is
// generous for a hello in flight and barely visible to a person.
//
// A var rather than a const so the tests can shorten it; a suite
// that pays a second per silent dial is a suite people stop
// running.
var HandshakeWait = 1 * time.Second

// peeked is a net.Conn whose first bytes have already been read.
//
// Needed because deciding costs a read, and a plain shell must not
// lose the bytes that decision consumed. `tls.Server` gets this and
// replays the ClientHello out of the buffer.
type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

// looksTLS reports whether these bytes open a TLS handshake.
//
// Content type 22 (handshake) then a major version of 3 -- the same
// structural test the server uses to tell a scanner from a shell,
// and for the same reason: a ClientHello carries an SNI and plenty
// of other ASCII, so anything based on printability reads it as
// text.
func looksTLS(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03
}

// accept decides what one connection is and returns it ready to
// read. -> (conn, isTLS, error).
//
// A failed TLS handshake is an error and the connection is dropped:
// something that opened a ClientHello and could not finish is not a
// shell, and handing the raw socket on would feed handshake bytes
// into a transcript as though somebody had typed them.
func acceptMaybe(ctx context.Context, c net.Conn,
	cfg *tls.Config) (net.Conn, bool, error) {
	br := bufio.NewReader(c)

	// A deadline only for the decision. Cleared before handing the
	// connection on, or a shell that sits quiet for an hour -- which
	// is what shells do -- would be killed by it.
	_ = c.SetReadDeadline(time.Now().Add(HandshakeWait))
	head, err := br.Peek(3)
	_ = c.SetReadDeadline(time.Time{})

	// `err` is deliberately not returned. A peek that timed out is
	// a peer that connected and said nothing, which is the ordinary
	// reverse shell waiting to be typed at -- `nc -e /bin/sh` does
	// exactly this. Plain is the right answer and the probe will
	// ask it. Treating the timeout as a failure would refuse every
	// shell that behaves normally.
	if cfg == nil || err != nil || !looksTLS(head) {
		return &peeked{Conn: c, r: br}, false, nil
	}

	tc := tls.Server(&peeked{Conn: c, r: br}, cfg)
	// HandshakeContext, not Handshake: a Ghost shutting down should
	// not wait on a peer that opened a ClientHello and stopped.
	hctx, cancel := context.WithTimeout(ctx, HandshakeWait)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		return nil, true, fmt.Errorf("tls handshake: %w", err)
	}
	return tc, true, nil
}

var (
	certOnce sync.Once
	certVal  *tls.Config
	certErr  error
)

// serverTLS is the certificate a listener presents, made once per
// process.
//
// Self-signed, and that is not a shortcut: the caller is a payload
// run with `verify=0`, because there is no CA either end agrees on
// and getting one onto a compromised host is not a thing an
// engagement does. What the certificate buys is the ENCRYPTION --
// a shell that does not cross the client's network in cleartext,
// where their own monitoring, and anybody else's, can read every
// command.
//
// Deliberately anonymous. A certificate is served to anyone who
// connects, scanners included, and a CN naming the engagement or
// the tool would fingerprint the operation to anybody sweeping the
// port. `localhost` says nothing.
func serverTLS() (*tls.Config, error) {
	certOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			certErr = err
			return
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			certErr = err
			return
		}
		tmpl := x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "localhost"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(1, 0, 0),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
		}
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl,
			&key.PublicKey, key)
		if err != nil {
			certErr = err
			return
		}
		certVal = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{der},
				PrivateKey:  key,
			}},
			// 1.2 and up. Nothing that calls back here needs less,
			// and offering less would be offering it to whoever is
			// scanning the port as well.
			MinVersion: tls.VersionTLS12,
		}
	})
	return certVal, certErr
}
