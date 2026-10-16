// Package portscan is the Ghost's own port scanner.
//
// # Why there is one at all
//
// masscan is a C program that dlopen()s libpcap, and the Ghost image
// carries both so that one task kind works. Everything else the agent
// runs is either Go or genuinely irreplaceable (nmap's service and OS
// detection has no Go equivalent). Port discovery does not need a C
// program — it needs to open a lot of sockets carefully.
//
// # Why not an existing library
//
// `JustinTimperio/gomap` is pure Go, has no dependencies and cross
// compiles everywhere, which is more than can be said for the
// alternatives: naabu drags in gopacket/pcap and does not build for
// windows/arm64 at all. Its scanning approach informed this package
// and it is MIT licensed, which this repository's Apache 2.0 can
// incorporate with the notice kept — see LICENSE-THIRD-PARTY.
//
// What it does not have is **rate limiting**, and that is not a
// detail. This engagement is capped at 11,600 packets per second and
// masscan's `--rate` is how that cap was honoured. A scanner that
// fans out goroutines as fast as the host allows cannot respect an
// agreed packet rate, and on a client's production network that is
// the difference between an authorised scan and an incident. So the
// rate limiter is the reason this package exists rather than a
// dependency, and every probe takes a token before it is sent.
package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxTargets bounds what one task may expand to.
//
// A /8 is sixteen million addresses. Someone will type one, and the
// failure should be a refusal with the number in it rather than an
// agent that allocates until the kernel stops it.
const MaxTargets = 65536

// ExpandTargets turns what the task asked for into addresses to probe.
//
// Accepts bare addresses, CIDRs and hostnames. A hostname is resolved
// here, once, rather than per port: the alternative is one DNS lookup
// per probe, which is both slow and a far louder thing to do to
// somebody's resolver than the scan itself.
//
// Order is deterministic — sorted — so two runs of the same task
// probe in the same order and a partial result can be compared with a
// complete one.
func ExpandTargets(ctx context.Context, in []string) ([]netip.Addr, error) {
	seen := map[netip.Addr]struct{}{}
	var out []netip.Addr

	add := func(a netip.Addr) error {
		if !a.IsValid() {
			return nil
		}
		a = a.Unmap()
		if _, dup := seen[a]; dup {
			return nil
		}
		if len(out) >= MaxTargets {
			return fmt.Errorf("more than %d addresses: narrow the range "+
				"or split the task", MaxTargets)
		}
		seen[a] = struct{}{}
		out = append(out, a)
		return nil
	}

	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			// Every address in the prefix, including network and
			// broadcast: masscan scans them and so do we. A host that
			// answers on .0 is a host, whatever the textbook says.
			p = p.Masked()
			for a := p.Addr(); p.Contains(a); a = a.Next() {
				if err := add(a); err != nil {
					return nil, err
				}
				if !a.Next().IsValid() {
					break
				}
			}
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			if err := add(a); err != nil {
				return nil, err
			}
			continue
		}
		// A name. Resolved once, here, and through the context: a
		// lookup that cannot be cancelled outlives the task that
		// asked for it, and on a stranded host that means a scan
		// still running long after its deadline.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s, err)
		}
		for _, ip := range ips {
			a, ok := netip.AddrFromSlice(ip.IP)
			if !ok {
				continue
			}
			if err := add(a); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

// ParsePorts reads a masscan/nmap-style port specification.
//
//	"80"            one
//	"80,443"        several
//	"1-1024"        a range
//	"22,80,8000-8100"  both
//
// Deliberately strict. A specification that cannot be read is an
// error rather than a quiet empty list: "scanned 0 ports and found
// nothing" and "your port list had a typo" look identical in a report
// and mean completely different things.
func ParsePorts(spec string) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("no ports given")
	}
	seen := map[uint16]struct{}{}
	var out []uint16
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := port(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = port(hi); err != nil {
				return nil, err
			}
		}
		if b < a {
			return nil, fmt.Errorf("port range %q runs backwards", part)
		}
		// Counted in uint16 rather than int-and-convert: `b` can be
		// 65535, and `p++` on an int that is then narrowed is the
		// shape every integer-overflow lint is looking for. The
		// break is at the end so 65535 itself is included without
		// the counter wrapping to zero first.
		for p := a; ; p++ {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
			if p == b {
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports in %q", spec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func port(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a port", s)
	}
	// 0 is not a port anyone can listen on, and accepting it silently
	// wastes a probe on every host in the range.
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is outside 1-65535", n)
	}
	return uint16(n), nil
}
