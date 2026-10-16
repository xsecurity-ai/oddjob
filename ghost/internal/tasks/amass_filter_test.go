package tasks

import "testing"

func TestHostnamesUnder(t *testing.T) {
	in := []string{
		"No assets were discovered",
		"www.example.com",
		"WWW.EXAMPLE.COM",
		"api.example.com (FQDN) --> a_record --> 1.2.3.4",
		"evil.example.org",
		"  mail.example.com.  ",
		"-bad.example.com",
		"example.com",
		"querying 12 sources",
	}
	got := hostnamesUnder(in, "example.com")
	// One www, not two: the same name in two cases is one name, and the
	// summary count is what an operator reads.
	want := []string{"www.example.com", "api.example.com",
		"mail.example.com", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d got %q want %q (%v)", i, got[i], want[i], got)
		}
	}
}
