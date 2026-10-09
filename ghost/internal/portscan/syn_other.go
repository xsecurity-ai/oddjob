//go:build !linux

package portscan

import (
	"context"
	"net/netip"
	"time"
)

// SYN scanning is Linux-only here, and the refusal is explicit.
//
// Raw TCP sockets on Windows are restricted to the point of
// uselessness — which is why masscan needs Npcap there — and darwin
// wants a BPF device with its own permissions story. Neither is a
// thing to half-implement for a tool that fires packets at a
// client's estate.
//
// The caller falls back to a connect scan and SAYS so. The failure
// this guards against is quietly doing something different from what
// was asked: a connect scan completes the handshake and appears in
// the target's application logs, and reporting that as a SYN sweep is
// a wrong claim about how much noise was made.

// runSYN refuses, and the caller falls back to connect loudly.
//
// There is deliberately no synScan here to call: a stub that can only
// return an error makes every `if err != nil` beside it an always-true
// comparison, which is a lint finding on these platforms and a real
// branch on Linux. Keeping the dispatch in the platform files means
// neither has to be silenced.
func runSYN(_ context.Context, _ []netip.Addr, _ []uint16,
	_ *limiter, _ time.Duration) (*Result, string) {
	return nil, "SYN scanning is not supported on this platform"
}
