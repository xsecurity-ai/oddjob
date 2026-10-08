package capacity

import (
	"context"
	"strings"
	"testing"
)

func TestParseMasscanRate(t *testing.T) {
	cases := []struct {
		name, out string
		want      int
	}{
		{"kpps", "rate: 12.34-kpps, 45.67% done,", 12340},
		{"plain pps", "rate:  950.00-pps, 1.00% done", 950},
		{"highest wins", "rate: 1.00-kpps, x\nrate: 9.50-kpps, y", 9500},
		{"nothing to read", "masscan: permission denied", 0},
		{"prose is not a rate", "rate: fast, 10% done", 0},
	}
	for _, c := range cases {
		if got := parseMasscanRate(c.out); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestMeasureIsAlwaysUsable(t *testing.T) {
	// Never zero and never absurd, whatever the host says: an agent
	// that assessed itself as able to run no tasks would sit idle for
	// the whole engagement.
	a := Measure(context.Background(), false, 0)
	if a.Parallel < floor || a.Parallel > ceiling {
		t.Fatalf("parallel %d out of bounds [%d,%d]", a.Parallel, floor, ceiling)
	}
	if a.Reason == "" {
		t.Fatal("an assessment with no reasoning is not reviewable")
	}
	if a.Cores < 1 {
		t.Fatalf("cores %d", a.Cores)
	}
}

func TestThousands(t *testing.T) {
	for in, want := range map[int]string{
		0: "0", 950: "950", 1000: "1,000", 12340: "12,340", 1000000: "1,000,000",
	} {
		if got := thousands(in); got != want {
			t.Errorf("thousands(%d) = %q want %q", in, got, want)
		}
	}
}

func TestSize(t *testing.T) {
	// The three numbers the live fleet actually reported before this
	// changed, so the case names are not hypothetical. Each ran one or
	// two tasks on a host that was doing nothing.
	cases := []struct {
		name             string
		cores, mem, over int
		want             int
	}{
		// Was 2, "2 cores". Nothing about two cores stops a box
		// holding eight sockets open.
		{"two cores, memory to spare", 2, 4096, 0, 8},
		// Was 1, "136 MB available (256 MB per task)". Still low, and
		// correctly so -- 136 MB is genuinely not much -- but the old
		// model also charged amass prices for an nmap.
		{"a genuinely small host is still small", 2, 136, 0, 1},
		// Was 1, "235 MB available". 235-64 = 171, /128 = 1.
		{"not quite enough for two", 2, 235, 0, 1},
		{"enough for two", 2, 320, 0, 2},

		// Memory unreadable is not memory absent.
		{"memory unknown falls back to cores", 4, 0, 0, 16},

		// The operator wins, in both directions, including past what
		// the memory estimate would allow.
		{"an override beats a roomy estimate", 32, 65536, 6, 6},
		{"an override beats a tight one", 2, 136, 8, 8},
		{"an override can also go down", 16, 65536, 1, 1},

		// Bounds.
		{"never zero", 1, 1, 0, 1},
		{"never above the ceiling", 256, 1 << 20, 0, ceiling},
		{"an override is held to the ceiling too", 2, 4096, 9999, ceiling},
		{"a nonsense core count does not divide by nothing", 0, 4096, 0, 4},
	}
	for _, c := range cases {
		got, why := size(c.cores, c.mem, c.over)
		if got != c.want {
			t.Errorf("%s: size(%d cores, %d MB, override %d) = %d, want %d (%s)",
				c.name, c.cores, c.mem, c.over, got, c.want, why)
		}
		if why == "" {
			t.Errorf("%s: no reasoning", c.name)
		}
	}
}

func TestSizeExplainsItself(t *testing.T) {
	// The reason is the only thing standing between a surprising
	// number and somebody assuming the feature is broken, so each
	// branch has to name the input that bound it.
	if _, why := size(2, 4096, 0); !strings.Contains(why, "cores") {
		t.Errorf("core-bound reason does not mention cores: %q", why)
	}
	if _, why := size(8, 200, 0); !strings.Contains(why, "MB") {
		t.Errorf("memory-bound reason does not mention memory: %q", why)
	}
	if _, why := size(8, 65536, 4); !strings.Contains(why, "operator") {
		t.Errorf("an operator's number must say so: %q", why)
	}
	// An override the host disagrees with still goes through, and the
	// disagreement is recorded rather than swallowed.
	_, why := size(2, 136, 8)
	if !strings.Contains(why, "operator") || !strings.Contains(why, "136 MB") {
		t.Errorf("an override past the estimate must carry both: %q", why)
	}
}

func TestOverrideReachesTheAssessment(t *testing.T) {
	// Measure reads the real host, so this asserts only the part that
	// does not depend on it: an operator's number survives the trip.
	a := Measure(context.Background(), false, 7)
	if a.Parallel != 7 {
		t.Fatalf("override 7 became %d (%s)", a.Parallel, a.Reason)
	}
	if b := Measure(context.Background(), false, 0); b.Parallel < floor {
		t.Fatalf("autosized to %d", b.Parallel)
	}
}
