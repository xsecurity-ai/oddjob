package recon

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// How an address was arrived at. Carried with the value because the
// same field now holds claims of very different strength, and an
// operator who cannot tell them apart will act on the wrong one —
// which is the actual bug here. A 172.17.0.3 was reported in the same
// place, and with the same apparent authority, as a real egress
// address.
const (
	// SourcePublic: an external service told us what our traffic looks
	// like from outside. The strongest answer, and the only one that
	// survives NAT.
	SourcePublic = "public-service"
	// SourceHostRoute: the host's own routing table, asked which
	// source address it would use. True of this machine.
	SourceHostRoute = "host-route"
	// SourceHostNetns: we are in a container, but one sharing the
	// host's network namespace, so the routing table answer is the
	// host's address.
	SourceHostNetns = "container-host-netns"
	// SourceContainerInternal: the container's own address on a
	// container-private network. Reported because it is what there is,
	// labelled because it means nothing outside this machine.
	SourceContainerInternal = "container-internal"
	// SourceInterface: no usable route, so the first global address on
	// any interface.
	SourceInterface = "interface"
	// SourceUnknown: no address could be determined. A real answer,
	// and not the same as an empty string in a column.
	SourceUnknown = "unknown"
)

// DefaultPublicIPURL is the service asked what our public address is.
//
// The /ip path, not the bare host: ifconfig.me serves a full HTML page
// to anything that looks like a browser and plain text to curl, and a
// result that depends on our User-Agent is a result waiting to become
// an HTML document parsed as an address.
const DefaultPublicIPURL = "https://ifconfig.me/ip"

// publicIPTimeout bounds the one outbound request. Registration waits
// on it, so it is small on purpose: an egress-filtered or air-gapped
// engagement host is the normal case, not the exception, and a ghost
// that takes thirty seconds to come up because of a lookup it was
// never going to win is worse than one with no public address.
const publicIPTimeout = 3 * time.Second

// Address is an answer to "what address is this agent at", with how it
// was reached attached.
type Address struct {
	IP     string `json:"ip,omitempty"`
	Source string `json:"source"`
	//: Anything that qualifies the value: which lookup failed, why a
	//: fallback was used, what the address is NOT. An operator reading
	//: a container address needs to know that is what it is.
	Note string `json:"note,omitempty"`
}

func (a Address) String() string {
	ip := a.IP
	if ip == "" {
		ip = "(none)"
	}
	if a.Note == "" {
		return fmt.Sprintf("%s [%s]", ip, a.Source)
	}
	return fmt.Sprintf("%s [%s] — %s", ip, a.Source, a.Note)
}

// probe is everything outside this process that OutboundAddress
// consults, in one place so a test can supply all of it. Detection
// that reaches straight for the real network and the real /proc can
// only be tested on a host that already has the condition being
// detected, which is no test at all.
type probe struct {
	// public asks an external service; nil when that is switched off.
	public func(context.Context) (string, error)
	// route is the source address the kernel would use to leave here.
	route func() string
	// ifaces is every usable address, best first.
	ifaces func() []string
	// ifaceOf names the interface carrying an address.
	ifaceOf func(ip string) string
	fs      rootFS
	getenv  func(string) string
}

// OutboundAddress works out the address worth reporting for this
// agent, and says where the number came from.
//
// publicURL empty disables the external lookup, which is the right
// setting when even one request to a third party is more exposure than
// the answer is worth.
func OutboundAddress(ctx context.Context, publicURL string) Address {
	p := probe{
		route:   OutboundIP,
		ifaces:  InterfaceIPs,
		ifaceOf: interfaceFor,
		fs:      osFS{},
		getenv:  os.Getenv,
	}
	if publicURL != "" {
		hc := &http.Client{Timeout: publicIPTimeout}
		p.public = func(ctx context.Context) (string, error) {
			return publicIP(ctx, hc, publicURL)
		}
	}
	return outboundAddress(ctx, p)
}

// outboundAddress is the order, and the reasoning for it:
//
//  1. Ask outside. Only an external observer can answer "where does
//     our traffic appear to come from", because that is a question
//     about every NAT and proxy between here and there, none of which
//     is visible from this side.
//  2. Fall back to the local routing table. Correct for a host that
//     is a host, and the best that can be done with no egress.
//  3. Inside a container, be honest about which of those the routing
//     table actually answered.
func outboundAddress(ctx context.Context, p probe) Address {
	var notes []string

	if p.public != nil {
		ip, err := p.public(ctx)
		if err == nil && ip != "" {
			return Address{IP: ip, Source: SourcePublic}
		}
		// A failed lookup is a fact about our egress, not about this
		// host's address. It is recorded so the value below reads as
		// the fallback it is.
		notes = append(notes, "public lookup failed: "+trunc(errText(err), 160))
	} else {
		notes = append(notes, "public lookup disabled")
	}

	local, source := p.route(), SourceHostRoute
	if local == "" {
		if addrs := p.ifaces(); len(addrs) > 0 {
			local, source = addrs[0], SourceInterface
		}
	}
	if local == "" {
		notes = append(notes, "no non-loopback address on any interface")
		return Address{Source: SourceUnknown, Note: joinNotes(notes)}
	}

	c := detectContainer(p.fs, p.getenv)
	if c.Runtime == "" {
		return Address{IP: local, Source: source, Note: joinNotes(notes)}
	}

	// From here down we are in a container, where the routing table
	// answers a smaller question than it appears to. What is actually
	// knowable about the host from in here:
	//
	//   * Host networking. Then this namespace IS the host's and the
	//     address is genuinely the host's. Told apart below by the
	//     interface not being a veth.
	//   * A routable address. A routed pod network, a macvlan or
	//     --network=host can leave us holding an address the outside
	//     world can reach, and that is worth reporting as-is.
	//   * Nothing else. In the default bridge case the host's useful
	//     address is simply not visible from inside the container. The
	//     default gateway is an address OF the host, but only on the
	//     container bridge — a 172.17.0.1 that exists nowhere else —
	//     so it goes in the note as context and never in the IP field,
	//     where it would read as an answer and be acted on.
	if name := p.ifaceOf(local); name != "" {
		if veth, known := isVeth(p.fs, name); known && !veth {
			notes = append(notes, "in a "+c.Runtime+" container sharing the "+
				"host network namespace ("+name+" is not a veth), so this is "+
				"the host's own address")
			return Address{IP: local, Source: SourceHostNetns,
				Note: joinNotes(notes)}
		}
	}
	if ip := net.ParseIP(local); ip != nil && isGloballyRoutable(ip) {
		notes = append(notes, "in a "+c.Runtime+" container, but the address "+
			"is globally routable rather than container-private")
		return Address{IP: local, Source: source, Note: joinNotes(notes)}
	}

	n := "this is the " + c.Runtime + " container's own address, NOT the " +
		"host's; the host's address is not knowable from inside a " +
		"bridged container"
	if gw := defaultGateway(p.fs); gw != "" {
		n += " (its default gateway " + gw + " is the host on the container " +
			"network, which is also local-only)"
	}
	notes = append(notes, n)
	return Address{IP: local, Source: SourceContainerInternal,
		Note: joinNotes(notes)}
}

// publicIP asks an external service what our traffic looks like from
// outside.
//
// This is the only thing in this package that talks to anything but
// the DNS, and the trade is worth stating because the reverse-IP
// lookup that used to live here was removed for failing it. That one
// sent the CLIENT's addresses to a third party. This sends nothing but
// the bare request, and what the service learns — that this host
// exists and has egress — it learns from any outbound connection at
// all. It is still a connection to somewhere that is not the
// engagement, so it is one request, short, and switchable off.
func publicIP(ctx context.Context, hc *http.Client, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, publicIPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	// Bounded. The answer is at most 45 bytes and the body is from
	// someone we do not control; a captive portal or an intercepting
	// proxy would otherwise have its whole error page read and then
	// parsed as an address.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	ip := net.ParseIP(s)
	if ip == nil {
		// Covers the whole family of 200-with-an-error-page traps,
		// including a local intercepting proxy answering for the
		// upstream it could not reach.
		return "", fmt.Errorf("%s answered %q, which is not an address",
			url, trunc(s, 40))
	}
	if ip.IsLoopback() || ip.IsUnspecified() || !isGloballyRoutable(ip) {
		return "", fmt.Errorf("%s answered %s, which is not a public address "+
			"(captive portal, or a proxy reporting our own side back?)", url, ip)
	}
	return ip.String(), nil
}

// isGloballyRoutable is "would the internet route to this", not "is
// this an RFC 1918 address". The difference that matters in practice
// is carrier-grade NAT and the 100.64/10 space Tailscale hands out:
// those are not private by net.IP's definition, and reporting one as
// a public address would be wrong in the same way 172.17.0.3 is.
func isGloballyRoutable(ip net.IP) bool {
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10, CGNAT.
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return false
		}
		// 169.254/16 is covered by IsLinkLocalUnicast; 0.0.0.0/8 and
		// 240/4 are not addresses a host legitimately holds here.
		if v4[0] == 0 || v4[0] >= 240 {
			return false
		}
	}
	return true
}

// isVeth reports whether an interface is one half of a veth pair,
// which is what a container gets when it has its own network
// namespace.
//
// The trick is that a veth's iflink is the ifindex of its peer on the
// other side of the namespace boundary, so the two differ. A real NIC
// has them equal. The second return is whether we could tell at all:
// on a host without sysfs the answer is "unknown", which must not be
// read as "not a veth" — that would promote a container address to a
// host address on exactly the systems where we can see least.
func isVeth(fs rootFS, name string) (veth, known bool) {
	if name == "" || strings.ContainsAny(name, "/.") {
		return false, false
	}
	idx, ok1 := readString(fs, "/sys/class/net/"+name+"/ifindex")
	link, ok2 := readString(fs, "/sys/class/net/"+name+"/iflink")
	if !ok1 || !ok2 {
		return false, false
	}
	idx, link = strings.TrimSpace(idx), strings.TrimSpace(link)
	if idx == "" || link == "" {
		return false, false
	}
	return idx != link, true
}

// defaultGateway is the next hop for 0.0.0.0/0, read from the routing
// table rather than probed.
//
// Reported only as context: inside a bridged container this is the
// host's address on that bridge, which is the closest thing to "the
// host" that is visible from in here and still not an address anyone
// outside the machine can use.
func defaultGateway(fs rootFS) string {
	b, err := fs.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		// Little-endian hex, as the kernel stores it: 010011AC is
		// 172.17.0.1.
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		if ip.IsUnspecified() {
			continue
		}
		return ip.String()
	}
	return ""
}

// interfaceFor names the interface holding an address, so the veth
// check knows what to look at.
func interfaceFor(addr string) string {
	want := net.ParseIP(addr)
	if want == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
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
			if ip != nil && ip.Equal(want) {
				return i.Name
			}
		}
	}
	return ""
}

func errText(err error) string {
	if err == nil {
		return "empty answer"
	}
	return err.Error()
}

func joinNotes(n []string) string { return strings.Join(n, "; ") }
