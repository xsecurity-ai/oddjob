package recon

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

// PublicResolver is the nameserver a Ghost's own PTR is asked of.
//
// 8.8.8.8 explicitly, NOT the host's resolver, and that is the whole
// point of this file. A Ghost on a corporate network, in a cloud VPC
// or behind a split-horizon setup gets an internal answer from its
// own resolver -- `ghost-01.internal`, or an AWS `ip-10-0-1-7` name
// -- and the question being asked here is "what does the CLIENT see
// when our traffic reaches them", which only a public resolver can
// answer.
//
// It is also why this is done on the agent rather than on Oddjob:
// Oddjob's own resolver is somewhere else entirely and its answer
// would be about nothing.
const PublicResolver = "8.8.8.8:53"

// ptrTimeout bounds the lookup. Registration waits on it, and a Ghost
// on an egress-filtered host will never win this -- so it fails fast
// and reports that it could not determine the name, which is a
// different answer from "there is no name".
const ptrTimeout = 3 * time.Second

// Name is a reverse-resolution answer, with how it was reached.
//
// Three outcomes, not two, for the same reason the callback feature
// has three: "it is called this", "it has no name" and "we could not
// find out" are different facts, and collapsing the third into the
// second is how an operator concludes an address is unnamed when the
// truth is that the lookup never completed.
type Name struct {
	//: The PTR, trailing dot stripped. Empty when there is none or
	//: when the lookup failed -- `Note` says which.
	Name string `json:"name,omitempty"`
	Note string `json:"note,omitempty"`
}

// publicResolver dials 8.8.8.8 whatever the host's resolv.conf says.
func publicResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			// UDP for the query; the stdlib retries over TCP itself
			// when an answer comes back truncated.
			if network == "tcp" || network == "tcp4" || network == "tcp6" {
				return d.DialContext(ctx, "tcp", PublicResolver)
			}
			return d.DialContext(ctx, "udp", PublicResolver)
		},
	}
}

// PublicName asks a public resolver what this address is called.
//
// `ip` is the agent's own outbound address. An empty or unroutable
// one is not looked up at all: a PTR for 172.17.0.3 would be asked of
// Google, answered with nothing, and recorded as "no name" about an
// address that was never public in the first place.
func PublicName(ctx context.Context, ip string) Name {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return Name{Note: "no outbound address to look up"}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Name{Note: "not an address: " + ip}
	}
	if !isGloballyRoutable(parsed) {
		// Said plainly. This is the case that would otherwise read as
		// "this host has no public name", which is a claim about the
		// world rather than about our own networking.
		return Name{Note: ip + " is not a public address, so it has no " +
			"public name to look up"}
	}

	ctx, cancel := context.WithTimeout(ctx, ptrTimeout)
	defer cancel()
	names, err := publicResolver().LookupAddr(ctx, ip)
	if err != nil {
		var dnsErr *net.DNSError
		if ok := asDNSError(err, &dnsErr); ok && dnsErr.IsNotFound {
			// A real answer: the resolver was reached and said there
			// is no PTR. Distinct from the branch below.
			return Name{Note: "no PTR record"}
		}
		return Name{Note: "could not reach " + PublicResolver + ": " +
			errText(err)}
	}
	for _, n := range names {
		if n = strings.TrimSuffix(strings.TrimSpace(n), "."); n != "" {
			// The first, and only the first. Several PTRs on one
			// address is legal and uncommon; picking one and saying
			// how many there were beats inventing a list nothing
			// else here can hold.
			note := ""
			if len(names) > 1 {
				note = "one of " + strconv.Itoa(len(names)) + " PTR records"
			}
			return Name{Name: n, Note: note}
		}
	}
	return Name{Note: "no PTR record"}
}

func asDNSError(err error, target **net.DNSError) bool {
	e, ok := err.(*net.DNSError) //nolint:errorlint // the resolver returns it bare
	if ok {
		*target = e
	}
	return ok
}
