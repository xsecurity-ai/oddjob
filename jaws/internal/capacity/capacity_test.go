package capacity

import (
	"context"
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
	a := Measure(context.Background(), false)
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
