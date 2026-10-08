package recon

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// answering builds a probe whose every outside dependency is fixed, so
// a test can put this process in a container on a WSL2 host without
// being in one.
func answering(public func(context.Context) (string, error), route string,
	iface string, f fakeFS) probe {
	return probe{
		public:  public,
		route:   func() string { return route },
		ifaces:  func() []string { return nil },
		ifaceOf: func(string) string { return iface },
		fs:      f,
		getenv:  noEnv,
	}
}

func publicAnswers(ip string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return ip, nil }
}

func publicFails(msg string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return "", errors.New(msg) }
}

// The whole point of asking outside: it is the only answer that
// survives NAT, a tunnel or a container.
func TestThePublicAnswerWins(t *testing.T) {
	p := answering(publicAnswers("198.51.100.7"), "172.17.0.3", "eth0",
		fakeFS{"/.dockerenv": ""})
	a := outboundAddress(context.Background(), p)
	if a.IP != "198.51.100.7" || a.Source != SourcePublic {
		t.Errorf("got %s, want the public address", a)
	}
}

// An air-gapped or egress-filtered engagement host is the normal case.
// The fallback has to work, and the failure has to be recorded —
// otherwise a local address and a public one are indistinguishable in
// the fleet list, which is the bug.
func TestAFailedPublicLookupFallsBackAndSaysSo(t *testing.T) {
	p := answering(publicFails("dial tcp: i/o timeout"), "10.1.2.3", "ens5",
		fakeFS{})
	a := outboundAddress(context.Background(), p)
	if a.IP != "10.1.2.3" || a.Source != SourceHostRoute {
		t.Errorf("got %s, want the local route answer", a)
	}
	if !strings.Contains(a.Note, "i/o timeout") {
		t.Errorf("the failure was not recorded: %q", a.Note)
	}
}

func TestTheLookupCanBeTurnedOff(t *testing.T) {
	p := answering(nil, "10.1.2.3", "ens5", fakeFS{})
	a := outboundAddress(context.Background(), p)
	if a.IP != "10.1.2.3" || !strings.Contains(a.Note, "disabled") {
		t.Errorf("got %s, want the local answer noted as the only one asked for", a)
	}
}

// The original complaint. A 172.17.0.3 is not where traffic comes
// from and is not the host, so it must not arrive looking like an
// answer. It is still reported — something is better than nothing —
// but labelled so nobody acts on it.
func TestAContainerAddressIsLabelledAsOne(t *testing.T) {
	f := fakeFS{
		"/.dockerenv": "",
		// veth: iflink points at the peer's index on the host side.
		"/sys/class/net/eth0/ifindex": "11",
		"/sys/class/net/eth0/iflink":  "12",
		"/proc/net/route": "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
			"eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
			"eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n",
	}
	a := outboundAddress(context.Background(),
		answering(publicFails("no route to host"), "172.17.0.3", "eth0", f))
	if a.IP != "172.17.0.3" {
		t.Errorf("IP = %q, want the container address reported rather than dropped", a.IP)
	}
	if a.Source != SourceContainerInternal {
		t.Errorf("source = %q, want %q", a.Source, SourceContainerInternal)
	}
	if !strings.Contains(a.Note, "NOT the host") {
		t.Errorf("note does not warn the operator off it: %q", a.Note)
	}
	// The gateway is the host's address on the bridge. Context, not an
	// answer: it belongs in the note and never in the IP field.
	if !strings.Contains(a.Note, "172.17.0.1") {
		t.Errorf("note does not mention the gateway: %q", a.Note)
	}
}

// --network=host puts the container in the host's network namespace,
// so the routing table answer really is the host's address. Told apart
// by the interface not being a veth.
func TestAHostNetworkContainerReportsTheHostAddress(t *testing.T) {
	f := fakeFS{
		"/.dockerenv":                 "",
		"/sys/class/net/ens5/ifindex": "2",
		"/sys/class/net/ens5/iflink":  "2",
	}
	a := outboundAddress(context.Background(),
		answering(publicFails("blocked"), "10.4.0.21", "ens5", f))
	if a.Source != SourceHostNetns {
		t.Errorf("source = %q, want %q (%s)", a.Source, SourceHostNetns, a.Note)
	}
	if a.IP != "10.4.0.21" {
		t.Errorf("IP = %q, want the host's address", a.IP)
	}
}

// Without sysfs we cannot tell a veth from a NIC. That must read as
// "unknown", which falls through to the cautious label — not as "not
// a veth", which would promote a container address to a host address
// on exactly the systems where we can see least.
func TestNoSysfsMeansUnknownNotHost(t *testing.T) {
	a := outboundAddress(context.Background(),
		answering(publicFails("blocked"), "172.18.0.9", "eth0",
			fakeFS{"/.dockerenv": ""}))
	if a.Source != SourceContainerInternal {
		t.Errorf("source = %q, want the cautious %q (%s)",
			a.Source, SourceContainerInternal, a.Note)
	}
}

// A routed pod network or a macvlan can hand a container an address
// the outside world can actually reach. Labelling that one as
// worthless would be the same mistake in reverse.
func TestARoutableContainerAddressIsKept(t *testing.T) {
	f := fakeFS{
		"/.dockerenv":                 "",
		"/sys/class/net/eth0/ifindex": "11",
		"/sys/class/net/eth0/iflink":  "12",
	}
	a := outboundAddress(context.Background(),
		answering(publicFails("blocked"), "203.0.113.9", "eth0", f))
	if a.Source != SourceHostRoute || a.IP != "203.0.113.9" {
		t.Errorf("got %s, want the routable address kept", a)
	}
}

// Three outcomes, not two: found, absent, could not determine. An
// empty string in an IP column is the third pretending to be the
// second.
func TestNoAddressAtAllIsSaidOutLoud(t *testing.T) {
	p := probe{
		public:  publicFails("blocked"),
		route:   func() string { return "" },
		ifaces:  func() []string { return nil },
		ifaceOf: func(string) string { return "" },
		fs:      fakeFS{},
		getenv:  noEnv,
	}
	a := outboundAddress(context.Background(), p)
	if a.Source != SourceUnknown || a.IP != "" {
		t.Errorf("got %s, want an explicit unknown", a)
	}
	if !strings.Contains(a.Note, "no non-loopback address") {
		t.Errorf("note does not say what was missing: %q", a.Note)
	}
}

func TestFallsBackToAnInterfaceWhenThereIsNoRoute(t *testing.T) {
	p := probe{
		public:  publicFails("blocked"),
		route:   func() string { return "" },
		ifaces:  func() []string { return []string{"192.0.2.44"} },
		ifaceOf: func(string) string { return "" },
		fs:      fakeFS{},
		getenv:  noEnv,
	}
	a := outboundAddress(context.Background(), p)
	if a.IP != "192.0.2.44" || a.Source != SourceInterface {
		t.Errorf("got %s, want the interface fallback", a)
	}
}

func TestPublicLookupReadsAPlainAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("198.51.100.7\n"))
		}))
	defer srv.Close()
	got, err := publicIP(context.Background(), srv.Client(), srv.URL)
	if err != nil || got != "198.51.100.7" {
		t.Errorf("got %q, %v; want 198.51.100.7", got, err)
	}
}

// The trap that has already cost this engagement time twice: an
// intercepting proxy that cannot reach upstream answers 200 with its
// own error page. A body that is not an address is a failed lookup,
// never an address.
func TestAnErrorPageIsNotAnAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><title>Burp Suite</title>..."))
		}))
	defer srv.Close()
	if got, err := publicIP(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Errorf("accepted %q as an address", got)
	}
}

// A captive portal, or a proxy reporting our own side of the
// connection back at us. A private address is not an answer to "what
// does the internet see".
func TestAPrivateAnswerIsRejected(t *testing.T) {
	for _, body := range []string{"10.0.0.5", "127.0.0.1", "100.64.3.9"} {
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
		if got, err := publicIP(context.Background(), srv.Client(), srv.URL); err == nil {
			t.Errorf("accepted %q as a public address", got)
		}
		srv.Close()
	}
}

func TestANonOKStatusIsAFailedLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		}))
	defer srv.Close()
	if _, err := publicIP(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("a 429 was read as an answer")
	}
}

// The body comes from somewhere we do not control, so it is read with
// a bound rather than in full.
func TestTheAnswerIsReadWithABound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("9", 1<<20)))
		}))
	defer srv.Close()
	if _, err := publicIP(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("a megabyte of digits was accepted")
	}
}

func TestTheDefaultGatewayIsDecodedLittleEndian(t *testing.T) {
	f := fakeFS{"/proc/net/route": "Iface\tDestination\tGateway\tFlags\n" +
		"eth0\t000011AC\t00000000\t0001\n" +
		"eth0\t00000000\t010011AC\t0003\n"}
	if got := defaultGateway(f); got != "172.17.0.1" {
		t.Errorf("gateway = %q, want 172.17.0.1", got)
	}
	if got := defaultGateway(fakeFS{}); got != "" {
		t.Errorf("gateway = %q with no routing table to read, want empty", got)
	}
}
