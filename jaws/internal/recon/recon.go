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
	"net"
	"sort"
	"strings"
	"sync"
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
	//: How many known names were resolved forward to see whether they
	//: land here. Reported because "no other names" means something
	//: very different when nothing was checked.
	Checked int    `json:"checked"`
	Partial bool   `json:"partial"`
	Note    string `json:"note,omitempty"`
}

// This is not the same question as a PTR record. PTR gives the one
// name the address owner chose; shared hosting, a CDN or a reverse
// proxy can serve hundreds of unrelated domains from the same IP, and
// those are what an enumeration pass is after.
//
// There is no authoritative source for it, so several are consulted
// and the union returned, with `partial` set when one failed. Saying
// "47 domains" when a source timed out would present a floor as a
// total.
// ReverseIPLookup finds names associated with an address, using DNS
// and nothing else.
//
// It used to also query a third-party reverse-IP API. That answered a
// question DNS cannot -- which names point here -- but it did so by
// sending the address to someone else, and on an engagement the
// addresses are the client's. A list of a customer's infrastructure
// arriving at a third party is not a trade worth making silently, and
// it was the default.
//
// So: PTR, plus forward confirmation of `candidates`. The caller
// supplies the candidates; the server fills them from names the
// project already holds.
// NameIndex maps an address to the known names that resolve to it.
//
// Built once for a whole batch. The first version resolved every
// candidate inside the per-address loop, which is O(names x
// addresses): a project with 1,500 names and the 2,661 addresses one
// real task carried would have been four million DNS queries. Built
// once it is O(names), and the addresses are then free.
type NameIndex struct {
	byAddr  map[string][]string
	checked int
}

func (n NameIndex) Get(ip string) []string { return n.byAddr[ip] }

// BuildNameIndex resolves each candidate once, concurrently.
//
// Bounded: an agent sits on someone else's network and a thousand
// simultaneous DNS queries is itself a noticeable event, quite apart
// from what the local resolver does with it.
func BuildNameIndex(ctx context.Context, candidates []string) NameIndex {
	idx := NameIndex{byAddr: map[string][]string{}}
	uniq := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, c := range candidates {
		c = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(c, ".")))
		if c == "" || seen[c] || net.ParseIP(c) != nil {
			continue
		}
		seen[c] = true
		uniq = append(uniq, c)
	}
	idx.checked = len(uniq)
	if len(uniq) == 0 {
		return idx
	}

	const workers = 24
	//: Short on purpose; see the comment in the worker.
	const perLookup = 2 * time.Second
	type hit struct {
		name  string
		addrs []string
	}
	in := make(chan string)
	outc := make(chan hit)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := &net.Resolver{}
			for name := range in {
				// Bounded per name. Most candidates in a real project
				// do not resolve from where the agent sits, and the
				// system default waits seconds and retries for each
				// one — 453 names took two minutes almost entirely in
				// timeouts. A name that cannot answer quickly is not
				// going to answer.
				c, cancel := context.WithTimeout(ctx, perLookup)
				addrs, err := r.LookupHost(c, name)
				cancel()
				if err != nil {
					// A name that does not resolve says nothing
					// either way about any address.
					continue
				}
				select {
				case outc <- hit{name, addrs}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(in)
		for _, n := range uniq {
			select {
			case in <- n:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(outc) }()

	for h := range outc {
		for _, a := range h.addrs {
			idx.byAddr[a] = append(idx.byAddr[a], h.name)
		}
	}
	return idx
}

func ReverseIPLookup(ctx context.Context, ip string, index NameIndex) *ReverseIP {
	out := &ReverseIP{IP: ip}
	confirmed := 0
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
		// An address is not a name. "contains a dot" is true of
		// 198.51.100.5, and a forward lookup of an address returns
		// the address, so without this an IP confirms itself.
		if net.ParseIP(d) != nil {
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

	// Forward confirmation. PTR answers "what did the owner of this
	// address put in their reverse zone", which is at most a couple of
	// names and is frequently absent or generic. The question actually
	// being asked -- which names resolve HERE -- cannot be answered by
	// the DNS in that direction at all.
	//
	// What can be done with nothing but DNS is to take names already
	// known and resolve them forward, keeping the ones that land on
	// this address. On an engagement that is a strong source: the
	// project usually holds hundreds of names from certificates,
	// crawls and earlier scans, and any of them pointing here is a
	// fact rather than a third party's opinion.
	for _, n := range index.Get(ip) {
		add(n)
		confirmed++
	}
	if confirmed > 0 {
		out.Sources = append(out.Sources, "forward-confirmed")
	}
	out.Checked = index.checked

	for d := range seen {
		out.Domains = append(out.Domains, d)
	}
	sort.Strings(out.Domains)
	if out.Partial {
		out.Note = "at least one source did not answer; this is a floor, not a total"
	}
	return out
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
