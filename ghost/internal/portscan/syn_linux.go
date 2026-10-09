//go:build linux

package portscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// SYN scanning: send a SYN, call the port open if a SYN-ACK comes
// back, and never complete the handshake.
//
// Linux only, and that is not laziness. Raw TCP sockets on Windows
// are restricted to the point of uselessness — this is why masscan
// needs Npcap there — and darwin needs a BPF device with its own
// permissions story. On everything else `synSupported` is false and
// the caller falls back to a connect scan, loudly, rather than
// silently doing something different from what was asked.
//
// # The failure mode this code is written against
//
// A wrong checksum does not error. The kernel sends the packet, the
// far end discards it, nothing answers, and the scan reports a quiet
// estate. Every bug in here looks exactly like "no open ports", which
// is also what a correct scan of a firewalled range looks like. So
// the test does not check that it runs; it checks that it FINDS a
// listener it was told is there, and the checksum has its own test
// against a known-good vector.
// synScan probes one address's ports with SYNs.
//
// Returns the open ports it saw. An error here means the scan could
// not be attempted — no raw socket, usually — and is distinct from a
// scan that attempted everything and found nothing.
func synScan(ctx context.Context, a netip.Addr, ports []uint16,
	lim *limiter, timeout time.Duration) ([]uint16, error) {
	if !a.Is4() {
		return nil, fmt.Errorf("SYN scanning is IPv4 only here; %s is not", a)
	}

	// One raw socket for the whole address, not one per port: a
	// socket per port is a file descriptor per port and 65,535 of
	// them is a different kind of outage.
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("raw socket: %w (CAP_NET_RAW is needed "+
			"for a SYN scan)", err)
	}
	defer func() { _ = conn.Close() }()

	src, err := localAddrFor(ctx, a)
	if err != nil {
		return nil, err
	}

	// The source port is ours and is how replies are matched back.
	// Randomised so two scans from the same host do not collide, and
	// held constant across the address so one listener catches
	// everything.
	// The ephemeral range, 49152-65535, so the sum cannot exceed a
	// uint16 by construction.
	// #nosec G404,G115 -- not a secret, and the range is bounded above
	sport := uint16(rand.IntN(16384) + 49152)

	var (
		mu    sync.Mutex
		open  = map[uint16]struct{}{}
		want  = map[uint16]struct{}{}
		done  = make(chan struct{})
		dstIP = a.As4()
		srcIP = src.As4()
	)
	for _, p := range ports {
		want[p] = struct{}{}
	}

	// Closed to tell the reader to stop. The reader cannot rely on
	// the context alone: when the scan ends normally the context is
	// still live, and it cannot rely on the socket closing either,
	// because a read on a closed socket returns an error immediately
	// and the loop would spin on it for ever. The first version of
	// this did exactly that and the live test hung for ten minutes.
	stopRead := make(chan struct{})

	// Reader first, so nothing sent can arrive before there is
	// something listening for it.
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopRead:
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// A deadline is expected and means "nothing arrived
				// in the last 200ms". Anything else is the socket
				// going away, and spinning on it is the hang.
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				return
			}
			fa, ok := netip.AddrFromSlice(net.ParseIP(from.String()).To4())
			if !ok || fa.Unmap() != a {
				continue
			}
			p, isSynAck := parseSynAck(buf[:n], sport)
			if !isSynAck {
				continue
			}
			mu.Lock()
			if _, asked := want[p]; asked {
				open[p] = struct{}{}
			}
			mu.Unlock()
		}
	}()

	for _, p := range ports {
		if err := lim.wait(ctx); err != nil {
			break
		}
		pkt := synPacket(srcIP, dstIP, sport, p)
		if _, err := conn.WriteTo(pkt, &net.IPAddr{IP: net.IP(dstIP[:])}); err != nil {
			// One port failing to send is not the scan failing. It is
			// also not a closed port, and must not be recorded as one.
			continue
		}
	}

	// Give the last SYNs time to be answered. Without this the scan
	// ends the instant the final packet leaves and the slowest hosts
	// — the interesting ones — are reported as silent.
	select {
	case <-ctx.Done():
	case <-time.After(timeout):
	}
	// Stop the reader, then wait for it before reading the map.
	// Signalled rather than inferred from the socket closing: see
	// the note on stopRead.
	close(stopRead)
	_ = conn.Close()
	<-done

	mu.Lock()
	defer mu.Unlock()
	out := make([]uint16, 0, len(open))
	for p := range open {
		out = append(out, p)
	}
	return out, nil
}

// localAddrFor asks the kernel which source address it would use.
//
// A UDP dial sends nothing — it only consults the routing table — so
// this is free and does not touch the target.
func localAddrFor(ctx context.Context, dst netip.Addr) (netip.Addr, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", net.JoinHostPort(dst.String(), "1"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no route to %s: %w", dst, err)
	}
	defer func() { _ = c.Close() }()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("unexpected local address %T", c.LocalAddr())
	}
	a, ok := netip.AddrFromSlice(ua.IP.To4())
	if !ok {
		return netip.Addr{}, fmt.Errorf("local address %s is not IPv4", ua.IP)
	}
	return a.Unmap(), nil
}

// synPacket builds a bare TCP SYN. No IP header: the kernel writes
// that for an `ip4:tcp` socket.
func synPacket(src, dst [4]byte, sport, dport uint16) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	// A random sequence number. Zero works and is a signature.
	binary.BigEndian.PutUint32(h[4:8], rand.Uint32()) // #nosec G404
	// 8:12 acknowledgement, zero on a SYN.
	h[12] = 5 << 4 // data offset: five 32-bit words, no options
	h[13] = 0x02   // SYN
	// A window somebody might plausibly use. Zero would be refused by
	// some stacks and is another signature.
	binary.BigEndian.PutUint16(h[14:16], 1024)
	// 16:18 checksum, filled below. 18:20 urgent pointer, zero.
	binary.BigEndian.PutUint16(h[16:18], tcpChecksum(h, src, dst))
	return h
}

// parseSynAck reports the port, if this is a SYN-ACK addressed to us.
//
// Both flags, not just SYN: a SYN on its own is a simultaneous open
// attempt, and an ACK on its own is a RST-less close. Only SYN+ACK
// means "something is listening here". A RST-ACK is a CLOSED port
// and must never count.
//
// # Where the TCP header starts
//
// It depends, and getting it wrong is silent. Go's `ip4:tcp` reads on
// Linux hand back the TCP header at offset zero — the kernel has
// already stripped the IP header — while a raw `ip4:ip` socket, and
// some other platforms, include it. The first version of this
// assumed an IP header was always present, parsed the TCP header as
// IP options, matched nothing, and reported an empty network. The
// live test is what caught it; nothing else could have.
//
// So both layouts are tried and whichever addresses our source port
// wins. A packet that matches neither is somebody else's.
func parseSynAck(b []byte, ourPort uint16) (uint16, bool) {
	if p, ok := asSynAck(b, ourPort); ok {
		return p, true
	}
	// Possibly prefixed with an IPv4 header: version 4 in the high
	// nibble, length in the low one.
	if len(b) >= 20 && b[0]>>4 == 4 {
		ihl := int(b[0]&0x0f) * 4
		if ihl >= 20 && len(b) >= ihl+20 {
			return asSynAck(b[ihl:], ourPort)
		}
	}
	return 0, false
}

// asSynAck reads a buffer that starts at the TCP header.
func asSynAck(t []byte, ourPort uint16) (uint16, bool) {
	if len(t) < 20 {
		return 0, false
	}
	if binary.BigEndian.Uint16(t[2:4]) != ourPort {
		return 0, false // not a reply to us
	}
	const synAck = 0x12
	// Masked against SYN|ACK|RST so a RST-ACK, which has the ACK bit
	// set, cannot pass as an offer of service.
	if t[13]&0x16 != synAck {
		return 0, false
	}
	return binary.BigEndian.Uint16(t[0:2]), true
}

// tcpChecksum is the ones-complement sum over the pseudo-header and
// the segment, per RFC 793.
//
// Separated out and tested against a known vector because this is the
// function whose failure is invisible: get it wrong and every packet
// is silently discarded by the far end, and the scan reports a quiet
// network rather than an error.
func tcpChecksum(tcp []byte, src, dst [4]byte) uint16 {
	var sum uint32
	// Pseudo-header: source, destination, zero, protocol, length.
	for _, b := range [][]byte{src[:], dst[:]} {
		for i := 0; i < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
	}
	sum += uint32(6) // TCP
	// Bounded before narrowing: a TCP segment longer than 65535 is
	// not a TCP segment, and the length field in the pseudo-header
	// cannot represent it.
	if len(tcp) > 0xffff {
		return 0
	}
	// #nosec G115 -- bounded immediately above
	sum += uint32(len(tcp))

	for i := 0; i+1 < len(tcp); i += 2 {
		if i == 16 {
			continue // the checksum field itself reads as zero
		}
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// runSYN scans every address with SYNs.
//
// Lives in the platform file, not beside runConnect, so that the
// stub platforms have no call to a function that can only fail --
// staticcheck reads such a call as an always-true error comparison,
// and silencing it with a nolint then upsets nolintlint on the one
// platform where the branch is real. Splitting the dispatch is the
// structural answer to a problem that was only ever structural.
//
// The string is non-empty when SYN could not be used at all, and
// carries the reason for the caller to report.
func runSYN(ctx context.Context, addrs []netip.Addr, ports []uint16,
	lim *limiter, timeout time.Duration) (*Result, string) {
	res := &Result{}
	for _, a := range addrs {
		if ctx.Err() != nil {
			break
		}
		found, err := synScan(ctx, a, ports, lim, timeout)
		if err != nil {
			// The first address deciding it cannot do this at all —
			// no raw socket — means none of them can, so say so once
			// and let the caller fall back rather than failing every
			// address with the same message.
			if res.Probes == 0 {
				return nil, err.Error()
			}
			continue
		}
		res.Probes += len(ports)
		for _, p := range found {
			res.Open = append(res.Open, Open{Addr: a, Port: p})
		}
	}
	sort.Slice(res.Open, func(i, j int) bool {
		if res.Open[i].Addr != res.Open[j].Addr {
			return res.Open[i].Addr.Less(res.Open[j].Addr)
		}
		return res.Open[i].Port < res.Open[j].Port
	})
	return res, ""
}
