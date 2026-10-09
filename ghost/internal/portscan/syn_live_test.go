//go:build linux

package portscan

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// The only test that can catch a silently-broken SYN scanner: give it
// a listener it must find. A wrong checksum, a wrong flag or a wrong
// reply match all produce "no open ports", which is also what a
// correct scan of a firewalled host produces.
func TestSynFindsARealListener(t *testing.T) {
	if os.Getenv("PORTSCAN_SYN_LIVE") == "" {
		t.Skip("set PORTSCAN_SYN_LIVE=1 (needs CAP_NET_RAW)")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, not TCP", ln.Addr())
	}
	if ta.Port < 1 || ta.Port > 65535 {
		t.Fatalf("listener got port %d", ta.Port)
	}
	// #nosec G115 -- range checked immediately above
	open := uint16(ta.Port)
	shut := open + 1
	if shut == 0 {
		shut = open - 1
	}

	res, err := Run(context.Background(), Config{
		Targets: []string{"127.0.0.1"},
		Ports:   itoa(open) + "," + itoa(shut),
		Rate:    200, SYN: true, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mode=%s fallback=%q open=%v", res.Mode, res.Fallback, res.Open)
	if res.Mode != "syn" {
		t.Fatalf("fell back to %s: %s", res.Mode, res.Fallback)
	}
	found := false
	for _, o := range res.Open {
		if o.Port == open {
			found = true
		}
		if o.Port == shut {
			t.Errorf("reported closed port %d as open", shut)
		}
	}
	if !found {
		t.Fatalf("SYN scan did not find the listener on %d — this is the "+
			"silent failure the whole file is written against", open)
	}
}

func itoa(p uint16) string {
	const d = "0123456789"
	if p == 0 {
		return "0"
	}
	var b []byte
	for p > 0 {
		b = append([]byte{d[p%10]}, b...)
		p /= 10
	}
	return string(b)
}
