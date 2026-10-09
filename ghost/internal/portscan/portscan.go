package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Config is one scan.
type Config struct {
	// Targets are addresses, CIDRs or names. Expanded once.
	Targets []string
	// Ports is a masscan/nmap-style specification: "80,443,8000-8100".
	Ports string
	// Rate is probes per second across the whole scan. Zero means
	// unlimited, which the caller has to choose explicitly — see the
	// note on the limiter.
	Rate int
	// Timeout is how long one probe waits for an answer.
	Timeout time.Duration
	// Concurrency is how many probes may be in flight. The rate
	// limiter governs how fast they START; this governs how many can
	// be waiting at once, which is a different resource (file
	// descriptors) and needs its own bound.
	Concurrency int
}

// Open is one port that answered.
type Open struct {
	Addr netip.Addr
	Port uint16
}

// Result is what the scan found, plus what it could not do.
type Result struct {
	Open []Open
	// Probes actually sent. Reported so a run that was cut short is
	// distinguishable from one that found nothing: "0 open of 64,000
	// probed" and "0 open of 12 probed" are different claims.
	Probes int
	// Addrs and Ports as expanded, for the same reason.
	Addrs int
	Ports int
}

const (
	defaultTimeout     = 2 * time.Second
	defaultConcurrency = 512
	// A deliberately modest default. The task normally sets this, and
	// a scanner whose default is "as fast as possible" is one bad
	// argument away from an incident.
	defaultRate = 1000
)

// Run performs the scan.
//
// Connect scans only. A SYN scan needs raw sockets and hand-built
// packets, and shipping a half-tested one would be worse than
// shipping none: this returns what it actually observed, which is a
// completed TCP handshake. That is louder than SYN and the caller is
// expected to say so — see the note where this is called.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	addrs, err := ExpandTargets(ctx, cfg.Targets)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses to scan")
	}
	ports, err := ParsePorts(cfg.Ports)
	if err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	conc := cfg.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}
	rate := cfg.Rate
	if rate == 0 {
		rate = defaultRate
	}

	lim := newLimiter(rate)
	defer lim.close()

	var (
		mu     sync.Mutex
		open   []Open
		probes int
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, conc)

	// Ports outer, addresses inner. Probing every host on one port
	// before moving to the next spreads the load across the estate
	// rather than hammering one host with every port in turn, which
	// is both politer and far less likely to trip a per-host rate
	// limit on the client's side.
	for _, p := range ports {
		for _, a := range addrs {
			if ctx.Err() != nil {
				break
			}
			if err := lim.wait(ctx); err != nil {
				break
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(a netip.Addr, p uint16) {
				defer wg.Done()
				defer func() { <-sem }()
				ok := probe(ctx, a, p, timeout)
				mu.Lock()
				probes++
				if ok {
					open = append(open, Open{Addr: a, Port: p})
				}
				mu.Unlock()
			}(a, p)
		}
	}
	wg.Wait()

	sort.Slice(open, func(i, j int) bool {
		if open[i].Addr != open[j].Addr {
			return open[i].Addr.Less(open[j].Addr)
		}
		return open[i].Port < open[j].Port
	})
	return &Result{Open: open, Probes: probes,
		Addrs: len(addrs), Ports: len(ports)}, nil
}

// probe is one connect attempt.
//
// Only a completed connection counts as open. A refusal is a closed
// port and a timeout is no answer, and neither is evidence of a
// service — conflating them is how a scan reports a firewall as an
// estate.
func probe(ctx context.Context, a netip.Addr, p uint16, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp",
		net.JoinHostPort(a.String(), fmt.Sprint(p)))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
