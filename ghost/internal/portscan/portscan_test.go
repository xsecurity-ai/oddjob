package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []uint16
		bad  bool
	}{
		{in: "80", want: []uint16{80}},
		{in: "80,443", want: []uint16{80, 443}},
		{in: "1-5", want: []uint16{1, 2, 3, 4, 5}},
		{in: "443,80", want: []uint16{80, 443}},          // sorted
		{in: "80,80,80", want: []uint16{80}},             // de-duplicated
		{in: "22,80-82", want: []uint16{22, 80, 81, 82}}, // mixed
		{in: " 80 , 443 ", want: []uint16{80, 443}},      // whitespace
		{in: "65535", want: []uint16{65535}},

		// Strict on purpose. "Scanned 0 ports and found nothing" and
		// "your port list had a typo" look identical in a report.
		{in: "", bad: true},
		{in: "0", bad: true},     // nothing listens on 0; a wasted probe per host
		{in: "65536", bad: true}, // past the end
		{in: "-1", bad: true},
		{in: "http", bad: true},
		{in: "100-50", bad: true}, // backwards
		{in: ",", bad: true},
	}
	for _, c := range cases {
		got, err := ParsePorts(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("ParsePorts(%q) = %v, wanted an error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePorts(%q): %v", c.in, err)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("ParsePorts(%q) = %v want %v", c.in, got, c.want)
		}
	}
}

func TestExpandTargets(t *testing.T) {
	got, err := ExpandTargets(context.Background(), []string{"198.51.100.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	// Every address in the prefix, network and broadcast included:
	// masscan scans them and a host that answers on .0 is a host.
	if len(got) != 4 || got[0].String() != "198.51.100.0" ||
		got[3].String() != "198.51.100.3" {
		t.Fatalf("/30 expanded to %v", got)
	}

	// De-duplicated across sources, and sorted so two runs of the
	// same task probe in the same order.
	got, err = ExpandTargets(context.Background(), []string{"198.51.100.2", "198.51.100.0/30",
		"198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Errorf("overlapping inputs gave %d addresses: %v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if !got[i-1].Less(got[i]) {
			t.Errorf("not sorted: %v", got)
			break
		}
	}

	if _, err := ExpandTargets(context.Background(), []string{"not an address"}); err == nil {
		t.Error("a bare word was accepted as a target")
	}
	// A /8 is sixteen million addresses. Somebody will type one, and
	// the answer should be a refusal with the number in it.
	if _, err := ExpandTargets(context.Background(), []string{"10.0.0.0/8"}); err == nil {
		t.Error("a /8 was accepted")
	}
	if got, err := ExpandTargets(context.Background(), []string{"", "  "}); err != nil || len(got) != 0 {
		t.Errorf("blank input gave %v, %v", got, err)
	}
}

// The rate limiter is the reason this package exists rather than a
// dependency: the engagement is capped at 11,600 packets per second,
// and a scanner that cannot be throttled cannot respect that.
func TestLimiterPacesProbes(t *testing.T) {
	const rate = 200
	l := newLimiter(rate)
	defer l.close()

	ctx := context.Background()
	start := time.Now()
	const n = 100
	for i := 0; i < n; i++ {
		if err := l.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)

	// 100 probes at 200/s cannot be instant. The burst is a tenth of
	// a second's worth (20), so the remaining 80 need at least 0.4s.
	min := 300 * time.Millisecond
	if elapsed < min {
		t.Errorf("100 probes at %d/s took %s — faster than the rate allows "+
			"(expected at least %s)", rate, elapsed, min)
	}
	// And it must not be absurdly slow either, or the cap becomes a
	// scan that never finishes.
	if elapsed > 3*time.Second {
		t.Errorf("100 probes at %d/s took %s — far slower than the rate",
			rate, elapsed)
	}
}

func TestLimiterBurstIsBounded(t *testing.T) {
	// A large burst would let a scan open with a spike many times the
	// agreed rate while still averaging compliant over a minute. That
	// spike is what somebody watching the client's side complains
	// about.
	for _, rate := range []int{1, 10, 1000, 11600, 1000000} {
		b := burstFor(rate)
		if b < 1 {
			t.Errorf("burstFor(%d) = %d, must be at least 1", rate, b)
		}
		if b > 256 {
			t.Errorf("burstFor(%d) = %d, larger than the cap", rate, b)
		}
		if b > rate && rate > 1 {
			t.Errorf("burstFor(%d) = %d, more than a second's worth", rate, b)
		}
	}
}

func TestLimiterRespectsCancellation(t *testing.T) {
	// Returning nil on a cancelled context would let a probe go after
	// the task was told to stop.
	l := newLimiter(1)
	defer l.close()
	ctx, cancel := context.WithCancel(context.Background())
	_ = l.wait(ctx) // the burst token
	cancel()
	if err := l.wait(ctx); err == nil {
		t.Error("wait returned nil after the context was cancelled")
	}
}

func TestRunFindsAListeningPort(t *testing.T) {
	// A real listener on loopback: the only honest way to check that
	// "open" means a completed handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot listen on loopback here:", err)
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
	// Narrowed once, with the check, rather than at each use: a port
	// is a uint16 everywhere else in this package and carrying it as
	// an int just moves the conversion somewhere less obvious.
	if ta.Port < 1 || ta.Port > 65535 {
		t.Fatalf("listener got port %d", ta.Port)
	}
	// #nosec G115 -- the range is checked immediately above; gosec
	// does not follow the guard.
	port := uint16(ta.Port)

	// One port that is open and one that almost certainly is not.
	closed := port + 1
	if closed == 0 { // wrapped off the top
		closed = port - 1
	}
	res, err := Run(context.Background(), Config{
		Targets:     []string{"127.0.0.1"},
		Ports:       fmt.Sprintf("%d,%d", port, closed),
		Rate:        500,
		Timeout:     500 * time.Millisecond,
		Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Probes != 2 {
		t.Errorf("probed %d, expected 2", res.Probes)
	}
	found := map[uint16]bool{}
	for _, o := range res.Open {
		found[o.Port] = true
	}
	if !found[port] {
		t.Errorf("did not find the listener on %d: %+v", port, res.Open)
	}
	// Reported alongside the findings so "0 open of 2 probed" cannot
	// be mistaken for "0 open of 64,000 probed".
	if res.Addrs != 1 || res.Ports != 2 {
		t.Errorf("counts wrong: %d addrs, %d ports", res.Addrs, res.Ports)
	}
}

func TestRunRefusesNonsense(t *testing.T) {
	ctx := context.Background()
	if _, err := Run(ctx, Config{Targets: nil, Ports: "80"}); err == nil {
		t.Error("no targets was accepted")
	}
	if _, err := Run(ctx, Config{Targets: []string{"127.0.0.1"}, Ports: ""}); err == nil {
		t.Error("no ports was accepted")
	}
}

func TestRunStopsOnCancellation(t *testing.T) {
	// A cancelled scan must stop sending, not run to completion and
	// then report. 254 addresses x 20 ports is enough that finishing
	// would take far longer than this allows.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := Run(ctx, Config{
		Targets: []string{"198.51.100.0/24"}, Ports: "1-20",
		Rate: 100, Timeout: 2 * time.Second, Concurrency: 16,
	})
	if err != nil {
		return // refusing outright is also an acceptable answer
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("a cancelled scan ran for %s", time.Since(start))
	}
	if res.Probes >= res.Addrs*res.Ports {
		t.Errorf("cancellation did not stop it: %d of %d probes sent",
			res.Probes, res.Addrs*res.Ports)
	}
}

func TestExpandTargetsUnmapsV4(t *testing.T) {
	// ::ffff:198.51.100.1 and 198.51.100.1 are the same host, and
	// counting them twice doubles the probes sent at it.
	got, err := ExpandTargets(context.Background(), []string{"198.51.100.1", "::ffff:198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("v4-mapped v6 was not folded together: %v", got)
	}
	if got[0] != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("kept the mapped form: %v", got[0])
	}
}
