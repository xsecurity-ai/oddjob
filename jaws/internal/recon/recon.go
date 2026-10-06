// Package recon does the lookups that need no external tool.
//
// Resolution is done with the Go resolver rather than by shelling out
// to nslookup or dig: those are not installed everywhere (Windows
// ships nslookup but not dig; minimal containers ship neither), their
// output formats differ between implementations, and parsing a
// human-readable report back into structure is how subtle mistakes get
// in. The answers here are already structured.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Lookup struct {
	Query string   `json:"query"`
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
	Error string   `json:"error,omitempty"`
}

// NSLookup resolves a name, or reverse-resolves an address.
//
// A failed lookup is reported as an error, never as an empty result.
// "no such name" and "the resolver did not answer" are different
// claims, and collapsing them records a gap in our coverage as a fact
// about the target.
func NSLookup(ctx context.Context, query string) *Lookup {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	out := &Lookup{Query: query}
	r := &net.Resolver{}

	if ip := net.ParseIP(query); ip != nil {
		names, err := r.LookupAddr(ctx, query)
		if err != nil {
			out.Error = err.Error()
			return out
		}
		for _, n := range names {
			out.PTR = append(out.PTR, strings.TrimSuffix(n, "."))
		}
		return out
	}

	addrs, err := r.LookupIPAddr(ctx, query)
	if err != nil {
		out.Error = err.Error()
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			out.A = append(out.A, a.IP.String())
		} else {
			out.AAAA = append(out.AAAA, a.IP.String())
		}
	}
	if c, err := r.LookupCNAME(ctx, query); err == nil {
		if c = strings.TrimSuffix(c, "."); !strings.EqualFold(c, query) {
			out.CNAME = c
		}
	}
	if mx, err := r.LookupMX(ctx, query); err == nil {
		for _, m := range mx {
			out.MX = append(out.MX, strings.TrimSuffix(m.Host, "."))
		}
	}
	if ns, err := r.LookupNS(ctx, query); err == nil {
		for _, n := range ns {
			out.NS = append(out.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if txt, err := r.LookupTXT(ctx, query); err == nil {
		out.TXT = txt
	}
	return out
}

type ReverseIP struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
	Sources []string `json:"sources"`
	Partial bool     `json:"partial"`
	Note    string   `json:"note,omitempty"`
}

// ReverseIPLookup finds the domains hosted on an address.
//
// This is not the same question as a PTR record. PTR gives the one
// name the address owner chose; shared hosting, a CDN or a reverse
// proxy can serve hundreds of unrelated domains from the same IP, and
// those are what an enumeration pass is after.
//
// There is no authoritative source for it, so several are consulted
// and the union returned, with `partial` set when one failed. Saying
// "47 domains" when a source timed out would present a floor as a
// total.
func ReverseIPLookup(ctx context.Context, ip string) *ReverseIP {
	out := &ReverseIP{IP: ip}
	if net.ParseIP(ip) == nil {
		out.Note = "not an IP address"
		out.Partial = true
		return out
	}

	seen := map[string]bool{}
	add := func(d string) {
		d = strings.ToLower(strings.Trim(strings.TrimSuffix(d, "."), " \t\r"))
		d = strings.TrimPrefix(d, "*.")
		if d == "" || !strings.Contains(d, ".") {
			return
		}
		seen[d] = true
	}

	// PTR first: free, local, and sometimes the only answer available.
	if names, err := (&net.Resolver{}).LookupAddr(ctx, ip); err == nil {
		for _, n := range names {
			add(n)
		}
		if len(names) > 0 {
			out.Sources = append(out.Sources, "ptr")
		}
	}

	for _, s := range reverseSources {
		names, err := s.fetch(ctx, ip)
		if err != nil {
			out.Partial = true
			continue
		}
		for _, n := range names {
			add(n)
		}
		out.Sources = append(out.Sources, s.name)
	}

	for d := range seen {
		out.Domains = append(out.Domains, d)
	}
	sort.Strings(out.Domains)
	if out.Partial {
		out.Note = "at least one source did not answer; this is a floor, not a total"
	}
	return out
}

type reverseSource struct {
	name  string
	fetch func(ctx context.Context, ip string) ([]string, error)
}

var reverseSources = []reverseSource{
	{name: "hackertarget", fetch: hackertarget},
}

var httpClient = &http.Client{Timeout: 25 * time.Second}

func get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Jaws (authorised security assessment)")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}

func hackertarget(ctx context.Context, ip string) ([]string, error) {
	b, err := get(ctx, "https://api.hackertarget.com/reverseiplookup/?q="+ip)
	if err != nil {
		return nil, err
	}
	s := string(b)
	// It answers 200 with a prose error when rate-limited. Treating
	// that as a result would record "api count exceeded" as a domain.
	if strings.Contains(s, "API count exceeded") || strings.Contains(s, "error") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(trunc(s, 120)))
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// JSON renders a result for shipping home.
func JSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return string(b)
}
