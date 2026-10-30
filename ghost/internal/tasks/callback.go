package tasks

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/callback"
	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// Out-of-band callbacks: holding a port open while a payload runs.
//
// A task asks for one by setting `callback` to `tcp` or `udp`. The
// agent binds a port before the tool starts, rewrites the task's own
// arguments so the payload points at it, runs the tool, waits, and
// reports what arrived.
//
// # The placeholders
//
// Anywhere in the task's other arguments -- a raw request body, a
// nuclei variable, a header, a URL -- these are replaced:
//
//	{{callback}}        host:port, which is what a payload usually wants
//	{{callback_host}}   the address on its own
//	{{callback_port}}   the port on its own
//	{{callback_url}}    http://host:port/<token>, for the common case
//
// Substitution rather than a fixed argument because there is no one
// place a callback address goes: an SSRF wants it in a query
// parameter, an XXE in a DTD, a log4j probe inside a `${jndi:...}`,
// and a header injection in a header. The task says where; the agent
// says what.
//
// `{{callback_url}}` carries a per-task token so that two tests
// running at once on one Ghost can be told apart by which path was
// requested -- the listener keeps whatever arrived, and with one port
// shared by nothing that is still the only discriminator there is.

// CallbackWindow is how long to keep listening after the tool exits.
//
// Out-of-band is out of band: the request that triggers it returns
// immediately and the connection arrives when something downstream
// gets round to it -- a queued job, a retry, a crawler picking the URL
// up minutes later. Closing the port the instant the tool exits is
// how a real finding is missed, which is the one outcome this whole
// package exists to avoid.
// A var, not a const, so a test can shorten it. Nothing in the agent
// writes to it: an operator wanting a longer wait sets `callback_wait_s`
// on the task, which is read per run below.
var CallbackWindow = 90 * time.Second

// callbackWindow is the window for one run: the task's own
// `callback_wait_s` if it gave one, else the default.
//
// Per task because the right wait is a property of what is being
// tested. A reflected SSRF answers in milliseconds; a payload that
// lands in a log a batch job reads is minutes away, and the operator
// who wrote it knows which.
func callbackWindow(args map[string]any) time.Duration {
	if n := intOr(args, "callback_wait_s", 0); n > 0 {
		if n > 900 {
			n = 900 // a quarter hour, past which a task is a stuck task
		}
		return time.Duration(n) * time.Second
	}
	return CallbackWindow
}

type callbackRun struct {
	l       *callback.Listener
	proto   string
	token   string
	nonce   string
	probed  bool
	why     string
	skipped string
}

// wantsCallback reads the `callback` argument. "" means no.
func wantsCallback(args map[string]any) string {
	switch v := args["callback"].(type) {
	case bool:
		if v {
			return "tcp"
		}
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		if s == "tcp" || s == "udp" {
			return s
		}
		if s == "true" || s == "yes" {
			return "tcp"
		}
	}
	return ""
}

// openCallback binds a port and rewrites `args` to point at it.
//
// Never fatal. A task that asked for a callback and could not get a
// port still runs -- the payload simply goes without one and the
// result says so. Refusing to run would turn a missing capability
// into a missing scan, and the operator asked for the scan.
func openCallback(ctx context.Context, args map[string]any) *callbackRun {
	proto := wantsCallback(args)
	if proto == "" {
		return nil
	}
	// The address a target should be told to reach, which is the one
	// an external observer sees -- not an interface address, which on
	// a NATed host names nothing from the other side.
	addr := recon.OutboundAddress(ctx, str(args, "public_ip_url"))
	host := addr.IP
	if h := str(args, "callback_host"); h != "" {
		// An operator override, for the case the Ghost sits behind a
		// forward you arranged yourself and the address it can see is
		// not the one the target should use.
		host = h
	}
	if host == "" {
		return &callbackRun{proto: proto,
			skipped: "this agent does not know its own outbound address, " +
				"so there is nothing to tell a target to connect to"}
	}
	l, err := callback.Open(ctx, proto, host)
	if err != nil {
		return &callbackRun{proto: proto,
			skipped: "no port could be bound for a callback: " + err.Error()}
	}
	r := &callbackRun{l: l, proto: proto, token: randToken(10)}
	substituteCallback(args, l.Address(), host, l.Port, r.token)
	return r
}

// substituteCallback rewrites every string in `args`, in place.
//
// Walks maps and slices because a task's arguments are arbitrary
// JSON: a replay's bytes are one string, nuclei's variables are a
// map, and a header list is a slice. Replacing only top-level strings
// would silently leave `{{callback}}` in the one place it was
// actually written.
func substituteCallback(args map[string]any, addr, host string, port int, token string) {
	rep := strings.NewReplacer(
		"{{callback}}", addr,
		"{{callback_host}}", host,
		"{{callback_port}}", strconv.Itoa(port),
		"{{callback_url}}", "http://"+addr+"/"+token,
	)
	for k, v := range args {
		if k == "callback" {
			continue
		}
		args[k] = walkStrings(v, rep.Replace)
	}
}

func walkStrings(v any, f func(string) string) any {
	switch t := v.(type) {
	case string:
		return f(t)
	case []any:
		for i := range t {
			t[i] = walkStrings(t[i], f)
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = walkStrings(t[k], f)
		}
		return t
	}
	return v
}

// A per-task path, so two tests running at once on one Ghost can be
// told apart by which URL was requested. Not a secret and not trying
// to be: it distinguishes, it does not authenticate.
func randToken(n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// A predictable token still distinguishes two tasks on one
		// host, which is all this is for.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b)
}

// ProbeCallback asks Oddjob to dial a port this agent just bound,
// before the payload goes out.
//
// Set by the agent, like Parallelism and AssetsHeld. Nil means there
// is nobody to ask, and the run then reports `unknown` rather than
// claiming a clean result it cannot support.
var ProbeCallback func(ctx context.Context, port int, proto string) (
	nonce string, sent bool, detail string, err error)

func (r *callbackRun) prove(ctx context.Context) {
	if r == nil || r.l == nil || ProbeCallback == nil {
		if r != nil && r.l != nil {
			r.why = "nothing was available to test reachability from outside"
		}
		return
	}
	nonce, sent, detail, err := ProbeCallback(ctx, r.l.Port, r.proto)
	if err != nil {
		r.why = "the reachability probe could not be run: " + err.Error()
		return
	}
	r.nonce = nonce
	if !sent {
		r.why = detail
		return
	}
	// Sent is not received. A UDP datagram leaves whether or not
	// anything is listening, and even a TCP connect proves the path
	// rather than the delivery -- so the listener has to have SEEN
	// the nonce. Give it a moment: the probe and this check race.
	for i := 0; i < 20; i++ {
		if r.l.Take(nonce) {
			r.probed = true
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	r.why = "the probe was sent but never arrived at the listener"
}

// report closes the port and describes what happened, in the three
// states that are actually distinguishable.
func (r *callbackRun) report(ctx context.Context, window time.Duration) map[string]any {
	if r == nil {
		return nil
	}
	if r.l == nil {
		return map[string]any{
			"proto": r.proto, "state": "unknown", "why": r.skipped,
		}
	}
	hits := r.l.WaitFor(ctx, window)
	r.l.Close()
	// Anything of ours that arrived late still is not a finding.
	if r.nonce != "" {
		r.l.Take(r.nonce)
		hits = r.l.Hits()
	}

	state, why := "absent", "the port was reachable and nothing connected"
	switch {
	case len(hits) > 0:
		state, why = "found", "a connection arrived on the callback port"
	case !r.probed:
		// The important one. Silence on a port nothing could reach is
		// not evidence, and reporting it as `absent` would be the
		// tool claiming a result it did not measure.
		state = "unknown"
		why = "the callback port could not be proved reachable from " +
			"outside, so this test measured nothing: " + r.why
	}
	return map[string]any{
		"proto": r.proto, "port": r.l.Port, "advertised": r.l.Address(),
		"token": r.token, "reachable": r.probed,
		"state": state, "why": why,
		"window_s": int(window / time.Second),
		"hits":     hits,
	}
}

// Run executes one task, holding a callback port open around it when
// the task asked for one.
//
// Wrapped here rather than inside each runner for the same reason the
// placeholders are a substitution: every kind can want a callback and
// none of them should have to know how one works. A task that does
// not ask for one pays an `args["callback"]` lookup.
//
// The order matters and is the whole design:
//
//  1. bind, before anything is sent. A port bound after the payload
//     has gone is a port that was shut when the answer came.
//  2. prove it reachable, also before. Doing this afterwards would
//     mean a blocked port and a clean result are still the same
//     silence at the moment it matters.
//  3. run the tool, with the address already substituted in.
//  4. keep listening past the exit, because out-of-band is.
func Run(ctx context.Context, runner Runner, args map[string]any,
	workDir string) Result {

	cb := openCallback(ctx, args)
	if cb == nil {
		return runner(ctx, args, workDir)
	}
	cb.prove(ctx)
	res := runner(ctx, args, workDir)
	return withCallback(res, cb.report(ctx, callbackWindow(args)))
}

// withCallback folds the callback report into a result's JSON output.
//
// Parsed and re-serialised rather than string-spliced: the output is
// a scanner's own document and the importer reads it as one, so
// pasting a key in by hand would be one malformed brace away from
// losing the whole scan. A result whose output is NOT an object --
// nmap's XML, a bare array -- keeps it in the summary instead, where
// it is still said rather than silently dropped.
func withCallback(res Result, report map[string]any) Result {
	if report == nil {
		return res
	}
	state, _ := report["state"].(string)
	note := "callback: " + state
	if why, ok := report["why"].(string); ok && why != "" {
		note += " — " + why
	}

	var doc map[string]any
	if res.Output != "" && json.Unmarshal([]byte(res.Output), &doc) == nil &&
		doc != nil {
		doc["callback"] = report
		if b, err := json.Marshal(doc); err == nil {
			res.Output = string(b)
			res.Summary = joinSummary(res.Summary, note)
			return res
		}
	}
	res.Summary = joinSummary(res.Summary, note)
	return res
}

func joinSummary(s, note string) string {
	if s == "" {
		return note
	}
	return s + "; " + note
}
