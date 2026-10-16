package capacity

import (
	"slices"
	"testing"
)

// The case this exists for, measured on real hosts.
//
// nuclei peaks at 185 MB merely compiling its CVE template set --
// before a request is sent -- and that cost is fixed: `-c 1` is the
// gentlest pacing there is and does not move it. A 458 MB droplet
// reporting 143 MB available cannot run nuclei however politely it
// is asked, while a 4.9 GB host in the same pool can.
func TestUnaffordableKeepsNucleiOffATinyHost(t *testing.T) {
	tiny := Unaffordable(143)
	if !slices.Contains(tiny, "nuclei") || !slices.Contains(tiny, "nuclei_tech") {
		t.Errorf("143 MB host was offered nuclei: %v", tiny)
	}
	// It is not useless -- the light tools are unconstrained and it
	// must still take them. Reporting a host as unable to do
	// anything is how a small agent ends up idle instead of useful.
	for _, light := range []string{"nmap", "httpx", "gobuster", "katana"} {
		if slices.Contains(tiny, light) {
			t.Errorf("%s was refused on a 143 MB host; it runs in tens of MB", light)
		}
	}

	if big := Unaffordable(4900); len(big) != 0 {
		t.Errorf("a 4.9 GB host was refused work: %v", big)
	}
}

// The reserve is subtracted first. Spending the last megabyte is the
// condition this package exists to avoid, and the OOM killer takes
// the agent rather than the scanner.
func TestUnaffordableCountsTheReserve(t *testing.T) {
	// Just above nuclei's requirement before the reserve, just under
	// it after -- the window where forgetting the reserve is the
	// difference between a scan and a dead agent.
	avail := kindMemMB["nuclei"] + reserveMemMB - 1
	if got := Unaffordable(avail); !slices.Contains(got, "nuclei") {
		t.Errorf("%d MB passed nuclei (needs %d + %d reserved): %v",
			avail, kindMemMB["nuclei"], reserveMemMB, got)
	}
	if got := Unaffordable(avail + 2); slices.Contains(got, "nuclei") {
		t.Errorf("%d MB refused nuclei with room to spare: %v", avail+2, got)
	}
}

// An unreadable figure must not refuse everything. A measurement gap
// should not become an outage -- the same rule `assess` and `pace`
// already follow.
func TestUnaffordableSaysNothingWhenMemoryIsUnknown(t *testing.T) {
	if got := Unaffordable(0); got != nil {
		t.Errorf("unknown memory refused work: %v", got)
	}
	if got := Unaffordable(-1); got != nil {
		t.Errorf("unreadable memory refused work: %v", got)
	}
}
