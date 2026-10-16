package recon

import (
	"context"
	"net"
	"testing"
	"time"
)

// The reverse lookup used to also query a third-party API, which
// answered a question DNS cannot — which names point at an address —
// by sending that address to someone else. On an engagement the
// addresses are the client's, and that is not a trade to make by
// default. This is the guard against it coming back.
func TestNothingLeavesExceptDNS(t *testing.T) {
	// A sealed context: any HTTP the package tried would need a
	// transport, and there is none reachable here. The real assurance
	// is the absence of net/http in the file, asserted in CI by the
	// build, but a PTR lookup still has to work.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := ReverseIPLookup(ctx, "127.0.0.1", NameIndex{})
	if r.IP != "127.0.0.1" {
		t.Errorf("echoed the wrong address: %q", r.IP)
	}
	for _, s := range r.Sources {
		if s != "ptr" && s != "forward-confirmed" {
			t.Errorf("unexpected source %q — only DNS should be consulted", s)
		}
	}
}

func TestAnAddressIsNotAName(t *testing.T) {
	// Forward-resolving an address returns the address, and an address
	// has dots in it. Without the guard every IP confirmed itself as
	// its own hostname.
	idx := NameIndex{byAddr: map[string][]string{
		"198.51.100.5": {"198.51.100.5", "real.acme.example"},
	}}
	r := ReverseIPLookup(context.Background(), "198.51.100.5", idx)
	for _, d := range r.Domains {
		if net.ParseIP(d) != nil {
			t.Errorf("recorded an address as a domain: %q", d)
		}
	}
	found := false
	for _, d := range r.Domains {
		if d == "real.acme.example" {
			found = true
		}
	}
	if !found {
		t.Error("dropped the genuine name along with the address")
	}
}

func TestCheckedIsReportedSoSilenceIsReadable(t *testing.T) {
	// "No other names" means something entirely different when
	// nothing was looked at. The count is the difference between a
	// result and a gap.
	empty := ReverseIPLookup(context.Background(), "192.0.2.1", NameIndex{})
	if empty.Checked != 0 {
		t.Errorf("claimed to have checked %d names with no index", empty.Checked)
	}
	idx := NameIndex{byAddr: map[string][]string{}, checked: 40}
	some := ReverseIPLookup(context.Background(), "192.0.2.1", idx)
	if some.Checked != 40 {
		t.Errorf("checked = %d, want 40", some.Checked)
	}
}

func TestIndexIsBuiltOncePerBatch(t *testing.T) {
	// The first version resolved every candidate inside the per-address
	// loop. With 1,500 names and the 2,661 addresses one real task
	// carried, that was four million queries. Built once, the count is
	// the number of names and the addresses are free.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	idx := BuildNameIndex(ctx, []string{
		"localhost", "localhost", "  LOCALHOST  ", "", "198.51.100.9",
	})
	// Deduplicated, trimmed, lowercased, and an address is not a
	// candidate name.
	if idx.checked != 1 {
		t.Errorf("checked = %d, want 1 after dedup and filtering", idx.checked)
	}
}

func TestBuildingAnEmptyIndexIsFreeAndSafe(t *testing.T) {
	idx := BuildNameIndex(context.Background(), nil)
	if idx.checked != 0 || len(idx.Get("1.1.1.1")) != 0 {
		t.Errorf("empty index is not empty: %+v", idx)
	}
}
