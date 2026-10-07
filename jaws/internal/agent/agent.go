// Package agent is the loop: register, heartbeat, run, report.
package agent

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/xsecurity-ai/oddjob/jaws/internal/capacity"
	"github.com/xsecurity-ai/oddjob/jaws/internal/client"
	"github.com/xsecurity-ai/oddjob/jaws/internal/config"
	"github.com/xsecurity-ai/oddjob/jaws/internal/identity"
	"github.com/xsecurity-ai/oddjob/jaws/internal/recon"
	"github.com/xsecurity-ai/oddjob/jaws/internal/spool"
	"github.com/xsecurity-ai/oddjob/jaws/internal/tasks"
	"github.com/xsecurity-ai/oddjob/jaws/internal/tools"
)

type Agent struct {
	cfg *config.Config
	cli *client.Client
	sp  *spool.Spool
	id  *identity.Identity

	mu      sync.Mutex
	busy    bool
	current int
	// running is every task in flight, not just one. `busy` and
	// `current` are kept alongside it so the status endpoint and any
	// server predating concurrency still read something true.
	running map[int]bool
	// cap_ is what this host was assessed able to run at once, and the
	// reasoning. Re-derived as load changes, which is what makes the
	// tuning live rather than a decision taken once at install.
	cap_   int
	capWhy string
	// missing is {tool: why} for everything this host could not get.
	// The server reads it to avoid sending work that needs them.
	missing map[string]string
	wake    chan struct{}
}

func New(cfg *config.Config) *Agent {
	// A spool that cannot be opened is not fatal: an agent that still
	// runs scans and reports them live is far better than one that
	// refuses to start. What is lost is the crash-safety, so it is
	// said out loud rather than discovered later.
	sp, err := spool.Open(cfg.SpoolDir())
	if err != nil {
		log.Printf("WARNING: no spool at %s (%v) — results will not survive "+
			"a crash between finishing a scan and reporting it",
			cfg.SpoolDir(), err)
	}
	return &Agent{
		cfg:     cfg,
		sp:      sp,
		running: map[int]bool{},
		// One until the host has been looked at, which happens in
		// Run. Starting at anything higher would have the first
		// heartbeat claim slots nothing has checked for.
		cap_:   1,
		capWhy: "not assessed yet",
		cli:    client.New(cfg.Server, cfg.CallbackKey, cfg.Insecure),
		// Buffered depth 1: a wake that arrives while one is already
		// pending is the same wake. Blocking the caller — which is an
		// inbound HTTP handler — would be worse.
		wake: make(chan struct{}, 1),
	}
}

// VerifyServer checks an inbound call against the server this agent
// pinned at enrollment.
//
// Lives on the Agent rather than being satisfied by *Identity
// directly, for two reasons that both bit:
//
// A typed nil wrapped in an interface is not nil. Handing callin an
// `*Identity` that happened to be nil produced a non-nil Verifier
// whose nil check passed and which then panicked on the first inbound
// request — a crash reachable by anyone who could open the port.
//
// And the identity does not exist when the listener is built: it is
// created during enrollment, which happens later. Capturing it at
// construction meant capturing nothing, permanently. Read here, under
// the lock, it is whatever the agent currently has.
func (a *Agent) VerifyServer(method, path string, body []byte,
	ts, nonce, sig string) bool {
	a.mu.Lock()
	id := a.id
	a.mu.Unlock()
	if id == nil {
		return false
	}
	return id.VerifyServer(method, path, body, ts, nonce, sig)
}

// Wake asks the loop to poll now instead of at the next heartbeat.
// Safe to call from the inbound API.
func (a *Agent) Wake() {
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// Status is what the inbound API reports.
func (a *Agent) Status() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	priv, advice := tools.RawSocketCapable()
	return map[string]any{
		"name":         a.cfg.Name,
		"version":      config.Version,
		"platform":     runtime.GOOS,
		"arch":         runtime.GOARCH,
		"privileged":   priv,
		"privilege":    advice,
		"busy":         a.busy,
		"current_task": a.current,
		"owed_results": a.owed(),
		"server":       a.cfg.Server,
	}
}

// Register announces the agent, installing the baseline tools first so
// the inventory it reports is the one it will actually have.
func (a *Agent) Register(ctx context.Context) error {
	priv, advice := tools.RawSocketCapable()
	log.Printf("privilege: %s", advice)

	host, _ := hostname()
	announce := func(note string) error {
		a.mu.Lock()
		missing := make(map[string]string, len(a.missing))
		for k, v := range a.missing {
			missing[k] = v
		}
		a.mu.Unlock()
		resp, err := a.cli.Register(ctx, client.RegisterReq{
			Platform:     runtime.GOOS,
			Arch:         runtime.GOARCH,
			Version:      config.Version,
			Hostname:     host,
			Privileged:   priv,
			Tools:        tools.Installed(ctx),
			MissingTools: missing,
			CallInURL:    a.cfg.Advertise,
			OutboundIP:   recon.OutboundIP(),
			Interfaces:   recon.InterfaceIPs(),
		})
		if err != nil {
			return err
		}
		if note != "" {
			log.Printf("registered as agent %d on project %s (%s)",
				resp.AgentID, resp.Project, note)
		}
		return nil
	}

	// Announce before installing anything. Provisioning a bare Windows
	// box through chocolatey takes minutes, and registering only at
	// the end meant the server knew nothing about the agent for all of
	// it -- the UI showed "awaiting first contact" for a host that was
	// in fact working. Registration is idempotent, so saying it twice
	// costs nothing and the second one carries the real inventory.
	if err := announce(""); err != nil {
		log.Printf("initial announce failed (%v) — continuing; the "+
			"registration after tool install is the one that matters", err)
	}

	log.Printf("ensuring baseline tools: %v", tools.Baseline)
	// What could not be had, and why. Reported to the server so it can
	// stop handing this agent work it cannot do: a task that fails for
	// a missing tool costs three dispatches and tells the operator
	// nothing they could act on.
	missing := map[string]string{}
	for _, r := range tools.Ensure(ctx, tools.Baseline, tools.Privileged()) {
		switch r.Action {
		case "installed":
			log.Printf("  installed %s %s", r.Tool, r.Version)
		case "present":
			log.Printf("  %s already present (%s)", r.Tool, r.Version)
		default:
			// Not fatal. An agent with six of seven tools can still do
			// six of seven jobs, and the server is told which.
			log.Printf("  %s: %s — %s", r.Tool, r.Action, r.Detail)
			why := r.Detail
			if why == "" {
				why = r.Action
			}
			missing[r.Tool] = why
		}
	}
	a.mu.Lock()
	a.missing = missing
	a.mu.Unlock()

	// Again, now that the inventory is true.
	return announce("ready")
}

// ensureIdentity loads this agent's keypair, or trades an enrollment
// token for one.
//
// Done before anything else talks to the server, because from here on
// every request is signed with it.
func (a *Agent) ensureIdentity(ctx context.Context) error {
	path := a.cfg.IdentityPath()
	id, err := identity.Load(path)
	if err != nil {
		// A corrupt identity is not something to paper over by
		// generating a new one: the server knows the old public key,
		// so a silent replacement would just fail to authenticate
		// with a confusing message.
		return fmt.Errorf("%s exists but cannot be read (%w) — move it "+
			"aside and enroll this agent again", path, err)
	}
	if id != nil {
		a.id = id
		a.cli.UseIdentity(id)
		if id.CanSeal() {
			log.Printf("identity: agent %d on %s, pinned, channel sealed",
				id.AgentID, id.Project)
		} else {
			// Said every time rather than once: an agent reporting a
			// client's findings in the clear should be noisy about it.
			log.Printf("WARNING: agent %d on %s has no key-agreement key — "+
				"results travel unsealed, protected only by whatever TLS "+
				"is between here and the server. Re-enroll to fix.",
				id.AgentID, id.Project)
		}
		return nil
	}

	if a.cfg.EnrollToken == "" {
		if a.cfg.CallbackKey != "" {
			// An older agent, or one deliberately run on a key. It
			// still works; it is simply not the stronger scheme.
			log.Printf("no identity — authenticating with the callback key")
			return nil
		}
		return fmt.Errorf("nothing to authenticate with: pass --enroll with " +
			"the token Oddjob showed when this agent was created")
	}

	priv, pub, err := identity.Generate()
	if err != nil {
		return fmt.Errorf("generating a keypair: %w", err)
	}
	kexPriv, kexPub, err := identity.GenerateKex()
	if err != nil {
		return fmt.Errorf("generating a key-agreement pair: %w", err)
	}
	log.Printf("enrolling with a one-time token")
	resp, err := a.cli.Enroll(ctx, a.cfg.EnrollToken, pub, kexPub)
	if err != nil {
		return fmt.Errorf("enrolling: %w", err)
	}
	if !resp.Sealing || resp.ServerKexPublicKey == "" {
		// The token is spent either way, so this cannot be retried —
		// but running on would mean sending a client's scan results
		// over a channel this agent was built to encrypt. Stopping
		// with the reason is the better failure.
		return fmt.Errorf(
			"enrolled as agent %d, but the server did not establish an "+
				"encrypted channel (sealing=%v). Refusing to run: results "+
				"would travel unsealed. The server is likely older than "+
				"this agent", resp.AgentID, resp.Sealing)
	}
	id, err = identity.New(path, identity.File{
		AgentID: resp.AgentID, Project: resp.Project, Server: a.cfg.Server,
		PrivateKey: priv, PublicKey: pub,
		ServerPublicKey:    resp.ServerPublicKey,
		KexPrivateKey:      kexPriv,
		KexPublicKey:       kexPub,
		ServerKexPublicKey: resp.ServerKexPublicKey,
		ConnectionMode:     resp.ConnectionMode,
		EnrolledAt:         time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		// The exchange succeeded and the token is now burned, so a
		// failure to persist means this agent cannot be recovered
		// without enrolling again. Say exactly that.
		return fmt.Errorf("enrolled as agent %d but could not save the "+
			"identity to %s (%w) — the token is spent, so enroll again "+
			"once the path is writable", resp.AgentID, path, err)
	}
	a.id = id
	a.cli.UseIdentity(id)
	log.Printf("enrolled as agent %d on %s; this agent now only accepts "+
		"tasking from this Oddjob", resp.AgentID, resp.Project)
	return nil
}

// Run is the main loop. It returns only when ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.ensureIdentity(ctx); err != nil {
		return err
	}
	if err := a.registerWithRetry(ctx); err != nil {
		return err
	}

	// Before taking anything new: whatever is owed from last time.
	a.drain(ctx)

	// What this host can stand. The masscan probe runs ONCE, here,
	// because it is the only part that puts packets on the wire and
	// the answer does not change with load; cores and memory are
	// re-read on a timer below, which is what makes the tuning live.
	first := capacity.Measure(ctx, true)
	a.mu.Lock()
	a.cap_, a.capWhy = first.Parallel, first.Reason
	a.mu.Unlock()
	log.Printf("capacity: %d simultaneous task(s) — %s",
		first.Parallel, first.Reason)
	if first.MasscanRate > 0 {
		log.Printf("masscan sustained %d pps to a discard range locally. "+
			"That is this host's send path, NOT the path to any target.",
			first.MasscanRate)
	}

	retune := time.NewTicker(60 * time.Second)
	defer retune.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-retune.C:
				a.retune(ctx)
			}
		}
	}()

	tick := time.NewTicker(a.cfg.Heartbeat)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return nil
		case <-tick.C:
		case <-a.wake:
		}

		a.drain(ctx)

		resp, err := a.beat(ctx)
		if err != nil {
			// Keep beating. A server restart or a brief network outage
			// must not end the agent — it is typically on a host nobody
			// will log back into for days.
			log.Printf("heartbeat: %v", err)
			continue
		}
		if resp.Shutdown {
			// Killed from Oddjob. Drain first: a result this agent is
			// still holding is the last useful thing it can do, and
			// exiting with it undelivered would lose a scan that ran.
			log.Printf("told to stop: %s", resp.Reason)
			a.drain(ctx)
			return nil
		}
		// `tasks` when the server sends it, falling back to the
		// single `task` so this still works against one that predates
		// handing out more than one.
		batch := resp.Tasks
		if len(batch) == 0 && resp.Task != nil {
			batch = []client.Task{*resp.Task}
		}
		for i := range batch {
			t := batch[i]
			a.mu.Lock()
			a.running[t.ID] = true
			a.busy, a.current = true, t.ID
			a.mu.Unlock()
			go func() {
				defer func() {
					a.mu.Lock()
					delete(a.running, t.ID)
					a.busy = len(a.running) > 0
					if !a.busy {
						a.current = 0
					} else {
						for id := range a.running {
							a.current = id
							break
						}
					}
					a.mu.Unlock()
					// Ask for the next one straight away rather than
					// waiting out a heartbeat interval: a queue of
					// four hundred lookups should not take an extra
					// eight seconds per task to get through.
					a.Wake()
				}()
				a.execute(ctx, &t)
			}()
		}
	}
}

// beat checks in and reports what this agent is doing.
//
// State is read from the agent rather than passed in, so the beats
// sent while working and the one sent from the idle loop cannot
// disagree about what this agent is doing.
func (a *Agent) beat(ctx context.Context) (*client.HeartbeatResp, error) {
	a.mu.Lock()
	ids := make([]int, 0, len(a.running))
	for id := range a.running {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	first, capacity, why := a.current, a.cap_, a.capWhy
	a.mu.Unlock()

	free := capacity - len(ids)
	if free < 0 {
		free = 0
	}
	return a.cli.Heartbeat(ctx, client.HeartbeatReq{
		Ready:          free > 0,
		RunningTask:    first,
		RunningTasks:   ids,
		SlotsFree:      free,
		Capacity:       capacity,
		CapacityReason: why,
	})
}

// retune re-measures the host and adopts the new number.
//
// Called periodically rather than once at startup: an agent shares its
// machine with whatever else runs there, and a capacity decided while
// the box was idle is wrong by the time somebody starts a build on it.
// The masscan probe is NOT repeated — it puts packets on the wire, and
// doing that every minute to re-learn a number that does not change is
// not a trade worth making. Cores and memory are free to read.
func (a *Agent) retune(ctx context.Context) {
	as := capacity.Measure(ctx, false)
	a.mu.Lock()
	changed := as.Parallel != a.cap_
	a.cap_, a.capWhy = as.Parallel, as.Reason
	a.mu.Unlock()
	if changed {
		log.Printf("capacity now %d (%s)", as.Parallel, as.Reason)
	}
}

func (a *Agent) registerWithRetry(ctx context.Context) error {
	delay := 2 * time.Second
	for {
		err := a.Register(ctx)
		if err == nil {
			return nil
		}
		log.Printf("register: %v (retrying in %s)", err, delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < 2*time.Minute {
			delay *= 2
		}
	}
}

// execute runs one task to completion. Several may be in flight at
// once, so it does NOT touch `busy`, `current` or `running`: the loop
// that started it owns those. It used to set them itself, which was
// correct while exactly one task could exist and became a bug the
// moment two could — whichever finished first cleared `busy` while the
// other was still going, and the server was told there was a free slot
// that did not exist.
func (a *Agent) execute(ctx context.Context, t *client.Task) {
	log.Printf("task %d: %s", t.ID, t.Kind)
	if a.sp != nil {
		if err := a.sp.Begin(t.ID, t.Kind); err != nil {
			log.Printf("task %d: spool: %v", t.ID, err)
		}
	}
	if err := a.cli.StartTask(ctx, t.ID); err != nil {
		log.Printf("task %d: could not mark running: %v", t.ID, err)
	}

	runner, ok := tasks.Runners[t.Kind]
	if !ok {
		a.report(ctx, t.ID, client.Result{Status: "failed", ExitCode: -1,
			Error: "this agent has no runner for kind " + t.Kind +
				" — it may be older than the server"})
		return
	}

	start := time.Now()
	// Recovered rather than allowed to crash: one malformed task must
	// not take down an agent that is the only way onto that network.
	res := func() (r tasks.Result) {
		defer func() {
			if p := recover(); p != nil {
				r = tasks.Result{Status: "failed", ExitCode: -1,
					Error: "panic in runner: " + toString(p)}
			}
		}()
		return runner(ctx, tasks.Decode(t.Args), a.cfg.WorkDir)
	}()

	log.Printf("task %d: %s in %s — %s", t.ID, res.Status,
		time.Since(start).Round(time.Second), res.Summary+res.Error)

	// On disk before it goes on the wire. From here the result is
	// owed to the server and will be re-sent until acknowledged,
	// including across a restart.
	if a.sp != nil {
		if err := a.sp.Finish(t.ID, res.Status, res.Output, res.Stderr,
			res.Summary, res.ExitCode, res.Error); err != nil {
			log.Printf("task %d: spool: %v", t.ID, err)
		}
	}

	a.report(ctx, t.ID, client.Result{
		Status: res.Status, Output: res.Output, Stderr: res.Stderr,
		Summary: res.Summary, ExitCode: res.ExitCode, Error: res.Error,
	})
}

func (a *Agent) report(ctx context.Context, id int, r client.Result) {
	if err := a.cli.SubmitResult(ctx, id, r); err != nil {
		if a.sp != nil {
			a.sp.Attempted(id)
			// Not lost any more: it is on disk and the next drain will
			// try again. Worth saying at all because a result that is
			// hours late is still a surprise to whoever is watching.
			log.Printf("task %d: not delivered (%v) — held in the spool "+
				"and will be retried", id, err)
			return
		}
		log.Printf("task %d: RESULT LOST: %v", id, err)
		return
	}
	if a.sp != nil {
		if err := a.sp.Delivered(id); err != nil {
			log.Printf("task %d: spool: %v", id, err)
		}
	}
}

// drain re-sends anything the spool still owes the server, and closes
// out work that was interrupted.
//
// Run at startup and on every heartbeat. The startup case is the one
// that matters: it is how a result that finished moments before a
// reboot still reaches the engagement.
func (a *Agent) drain(ctx context.Context) {
	if a.sp == nil {
		return
	}

	// Tasks that were mid-flight when the process stopped. The tool is
	// gone with it, so they cannot be finished -- but the server is
	// still waiting, and a task stuck in `running` forever is worse
	// than a task that says plainly it was interrupted.
	//
	// Anything THIS process is running right now is not an orphan.
	// drain runs on every heartbeat, and tasks now execute
	// concurrently rather than blocking the loop, so a scan that takes
	// longer than one heartbeat interval is still open in the spool
	// when drain next looks at it. Without this check every such task
	// was reported interrupted eight seconds after it started, while
	// it was still running — and then retried, and reported again.
	a.mu.Lock()
	live := make(map[int]bool, len(a.running))
	for id := range a.running {
		live[id] = true
	}
	a.mu.Unlock()

	orphans, _ := a.sp.Orphaned()
	for _, e := range orphans {
		if live[e.TaskID] {
			continue
		}
		log.Printf("task %d: was running when this agent stopped — "+
			"reporting it as interrupted", e.TaskID)
		_ = a.sp.Finish(e.TaskID, "failed", "", "", "", -1,
			"the agent stopped while this task was running; "+
				"it did not complete and produced no output")
	}

	pending, _ := a.sp.Pending()
	for _, e := range pending {
		if ctx.Err() != nil {
			return
		}
		log.Printf("task %d: delivering a result held since %s (attempt %d)",
			e.TaskID, e.EndedAt, e.Attempts+1)
		a.report(ctx, e.TaskID, client.Result{
			Status: e.Status, Output: e.Output, Stderr: e.Stderr,
			Summary: e.Summary, ExitCode: e.ExitCode, Error: e.Error,
		})
	}
}

// owed is how many results are waiting to be delivered, for the
// call-in API. An operator asking "is this agent stuck?" wants this
// number, not a boolean.
func (a *Agent) owed() int {
	if a.sp == nil {
		return 0
	}
	_, pending := a.sp.Count()
	return pending
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return "unknown"
}
