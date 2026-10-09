package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/portscan"
)

// runPortscan is port discovery in process, with no binary.
//
// # What this is and is not
//
// It is a CONNECT scan. It completes the TCP handshake, which means
// it is louder than masscan's SYN sweep and shows up in the target's
// application logs rather than only at the network layer. That is
// said in the result and in the summary, every time, because a
// connect scan presented as a SYN scan is a wrong claim about how
// much noise was made at a client.
//
// It is therefore NOT a drop-in replacement for masscan, and masscan
// stays. What it removes is the binary dependency for the cases where
// a connect scan is what was wanted anyway, or where raw sockets are
// not available and masscan would refuse outright.
//
// # The output is masscan's
//
// `-oJ` shape, so the server's importer is untouched and a result is
// a result whoever produced it. The `reason` is `syn-ack` for masscan
// and `conn-established` here, which is the honest difference.
func runPortscan(ctx context.Context, args map[string]any, _ string) Result {
	tg := targets(args)
	if len(tg) == 0 {
		return failed("portscan needs `targets`")
	}
	ports := str(args, "ports")
	if ports == "" {
		// The same four masscan defaults to here, so a task written
		// for one means the same thing against the other.
		ports = "80,443,8080,8443"
	}

	// Rate is the engagement's business, not this function's. It is
	// taken from the task when given and defaulted conservatively
	// when not: a scanner whose default is "as fast as possible" is
	// one forgotten argument away from an incident.
	rate := intArg(args, "rate", 0)
	if s := str(args, "rate"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			rate = n
		}
	}

	started := time.Now()
	res, err := portscan.Run(ctx, portscan.Config{
		Targets:     tg,
		Ports:       ports,
		Rate:        rate,
		Timeout:     time.Duration(intArg(args, "port_timeout_ms", 2000)) * time.Millisecond,
		Concurrency: intArg(args, "concurrency", 0),
	})
	if err != nil {
		return failed("portscan: %v", err)
	}

	// masscan's `-oJ` shape: one object per address, ports inside.
	// Typed rather than map[string]any — the sort and the count
	// otherwise need type assertions on every element, which is both
	// noisier and a panic waiting for the day the shape changes.
	type jsonPort struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	type jsonHost struct {
		IP    string     `json:"ip"`
		Ports []jsonPort `json:"ports"`
	}

	byAddr := map[string][]jsonPort{}
	for _, o := range res.Open {
		ip := o.Addr.String()
		byAddr[ip] = append(byAddr[ip], jsonPort{
			Port: int(o.Port), Proto: "tcp", Status: "open",
			// Not "syn-ack". The handshake completed, which is a
			// different observation and a louder one.
			Reason: "conn-established",
		})
	}
	ips := make([]string, 0, len(byAddr))
	for ip := range byAddr {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	out := make([]jsonHost, 0, len(byAddr))
	openPorts := 0
	for _, ip := range ips {
		ps := byAddr[ip]
		sort.Slice(ps, func(i, j int) bool { return ps[i].Port < ps[j].Port })
		out = append(out, jsonHost{IP: ip, Ports: ps})
		openPorts += len(ps)
	}

	body, err := json.Marshal(out)
	if err != nil {
		return failed("encoding results: %v", err)
	}

	note := "connect scan: the handshake completes, so this is louder " +
		"than a SYN sweep and appears in the target's application logs"
	return Result{
		Status: "done",
		Output: string(body),
		Stderr: note,
		// The denominator matters. "0 open of 12 probed" and "0 open
		// of 64,000 probed" are different claims about coverage, and
		// only one of them means the estate is quiet.
		Summary: fmt.Sprintf(
			"%d open port(s) across %d host(s) — %d probe(s) over %d address(es) "+
				"and %d port(s) in %ds [%s]",
			openPorts, len(out), res.Probes, res.Addrs, res.Ports,
			int(time.Since(started).Seconds()), note),
	}
}
