package portscan

import (
	"context"
	"time"
)

// limiter paces outbound probes.
//
// This is the reason this package exists rather than a dependency.
// The engagement is capped at 11,600 packets per second; masscan's
// `--rate` is how that cap was honoured, and a scanner that fans out
// goroutines as fast as the host allows cannot honour it at all.
//
// A token bucket rather than a sleep between probes. Sleeping serialises
// the scan to one probe per interval, which at 11,600 pps means a
// 86-microsecond sleep per packet and a scheduler that cannot keep up;
// a bucket lets probes go concurrently while still averaging the rate
// over any window longer than the burst.
//
// The burst is deliberately small. A large one lets a scan open with a
// spike many times the agreed rate, which is exactly what somebody
// watching the client's side would complain about, and the average
// over a minute would still look compliant.
type limiter struct {
	tokens chan struct{}
	stop   chan struct{}
}

// burstFor keeps the opening spike proportional to the rate.
//
// A tenth of a second's worth, floored at one and capped so a very
// high rate cannot buy a large head start.
func burstFor(rate int) int {
	b := rate / 10
	if b < 1 {
		b = 1
	}
	if b > 256 {
		b = 256
	}
	return b
}

// newLimiter starts a limiter at `rate` probes per second.
//
// A rate of zero or less means unlimited, and the caller is expected
// to have decided that deliberately: `Config.Rate` defaults to a real
// number precisely so "unlimited" cannot happen by forgetting.
func newLimiter(rate int) *limiter {
	if rate <= 0 {
		return nil
	}
	l := &limiter{
		tokens: make(chan struct{}, burstFor(rate)),
		stop:   make(chan struct{}),
	}
	// Refill in batches rather than one token per tick. At 11,600 pps
	// a per-token ticker fires every 86µs, which costs more in timer
	// wakeups than the scan costs in packets; ten refills a second of
	// rate/10 tokens averages identically and is nearly free.
	per := rate / 10
	if per < 1 {
		per = 1
	}
	interval := time.Second / 10
	if rate < 10 {
		// Below ten a second, one token per interval is the only
		// honest shape: rate/10 would floor to 1 and run fast.
		per = 1
		interval = time.Second / time.Duration(rate)
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				for i := 0; i < per; i++ {
					select {
					case l.tokens <- struct{}{}:
					default: // bucket full; the scan is not keeping up
					}
				}
			}
		}
	}()
	return l
}

// wait blocks until a probe may be sent, or the context ends.
//
// Returns the context's error on cancellation so a caller cannot
// mistake "we were told to stop" for "we were allowed to send".
func (l *limiter) wait(ctx context.Context) error {
	if l == nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}

func (l *limiter) close() {
	if l != nil {
		close(l.stop)
	}
}
