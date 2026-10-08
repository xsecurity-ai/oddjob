package recon

import (
	"net"
	"sort"
)

// OutboundIP is the address on the interface this host would use to
// reach the internet.
//
// The server cannot work this out. All it sees is where the TCP
// connection arrived from, which is the last hop: behind NAT that is
// the gateway, through a reverse tunnel it is 127.0.0.1, and through a
// proxy it is the proxy. For an engagement that matters — the address
// the client's logs will show against our traffic is an attribution
// question, and "127.0.0.1" is not an answer anyone can act on.
//
// Found by asking the routing table, not by sending anything. A UDP
// "connection" is not a connection: no packet leaves the host, the
// kernel just resolves which interface and source address it would
// use. So this costs nothing, touches no third party, and is silent on
// the wire — which matters when the agent is sitting inside someone
// else's network.
//
// The address dialled is from TEST-NET-3 (RFC 5737, reserved for
// documentation and guaranteed never to be routed to a real host), so
// even if something did escape, it is addressed nowhere.
func OutboundIP() string {
	for _, probe := range []string{"203.0.113.1:80", "[2001:db8::1]:80"} {
		// There is nothing here for a context to cancel. A UDP "dial"
		// to a literal IP sends no packet and resolves no name: the
		// kernel picks a route and a source address and returns, in
		// microseconds, with no network operation to block on.
		// Threading a context through OutboundIP to satisfy the rule
		// would change the signature of a function called from four
		// places and buy a cancellation that can never fire.
		c, err := net.Dial("udp", probe) //nolint:noctx // sends no packet; resolves no name; cannot block — see above
		if err != nil {
			continue
		}
		addr, ok := c.LocalAddr().(*net.UDPAddr)
		_ = c.Close()
		if ok && addr.IP != nil && !addr.IP.IsUnspecified() &&
			!addr.IP.IsLoopback() {
			return addr.IP.String()
		}
	}
	// No default route, or a host with none of this configured. Fall
	// back to whatever global address exists.
	if addrs := InterfaceIPs(); len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// InterfaceIPs is every usable address on this host, best first.
//
// Reported alongside the outbound one because a single address is
// often the wrong picture: an agent on a jump box typically has one
// address facing us and another facing the target network, and which
// of those shows up in the client's logs depends on what is being
// scanned.
func InterfaceIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var global, private []string
	for _, i := range ifaces {
		// Down or loopback interfaces say nothing about reachability.
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			if ip.IsPrivate() {
				private = append(private, ip.String())
			} else {
				global = append(global, ip.String())
			}
		}
	}
	// Routable addresses first: on a host with both, the public one is
	// what the client will see.
	sort.Strings(global)
	sort.Strings(private)
	return append(global, private...)
}
