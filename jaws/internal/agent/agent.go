// Package agent is the loop: register, heartbeat, run, report.
package agent

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

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
		cfg: cfg,
		sp:  sp,
		cli: client.New(cfg.Server, cfg.CallbackKey, cfg.Insecure),
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
		resp, err := a.cli.Register(ctx, client.RegisterReq{
			Platform:   runtime.GOOS,
			Arch:       runtime.GOARCH,
			Version:    config.Version,
			Hostname:   host,
			Privileged: priv,
			Tools:      tools.Installed(ctx),
			CallInURL:  a.cfg.Advertise,
			OutboundIP: recon.OutboundIP(),
			Interfaces: recon.InterfaceIPs(),
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
	for _, r := range tools.Ensure(ctx, tools.Baseline, tools.Privileged()) {
		switch r.Action {
		case "installed":
			log.Printf("  installed %s %s", r.Tool, r.Version)
		case "present":
			log.Printf("  %s already present (%s)", r.Tool, r.Version)
		default:
			// Not fatal. An agent with three of four tools can still do
			// three of four jobs, and the server is told what it has.
			log.Printf("  %s: %s — %s", r.Tool, r.Action, r.Detail)
		}
	}

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
		if resp.Task == nil {
			continue
		}
		a.runWithHeartbeat(ctx, resp.Task)
	}
}

// beat checks in and reports what this agent is doing.
//
// State is read from the agent rather than passed in, so the beats
// sent while working and the one sent from the idle loop cannot
// disagree about what this agent is doing.
func (a *Agent) beat(ctx context.Context) (*client.HeartbeatResp, error) {
	a.mu.Lock()
	busy, id := a.busy, a.current
	a.mu.Unlock()
	return a.cli.Heartbeat(ctx, client.HeartbeatReq{
		Ready: !busy, RunningTask: id,
	})
}

// runWithHeartbeat executes a task while continuing to check in.
//
// A scan can run for the better part of an hour. Going quiet for that
// long is indistinguishable from having died, which is why the server
// had to infer `busy` from the fact that a task was claimed — an
// inference that was wrong whenever a claim was stranded. Beating
// throughout means the agent says what is true instead.
//
// The beats carry Ready=false, so none of them can be answered with
// more work: the queue is held server-side until this returns.
func (a *Agent) runWithHeartbeat(ctx context.Context, t *client.Task) {
	// `busy` and `current` are set by execute() itself, which is the
	// one writer; this only has to keep beating while it runs.
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(a.cfg.Heartbeat)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if _, err := a.beat(ctx); err != nil {
					// Logged, never fatal: losing a beat must not
					// interrupt a scan that is part-way through the
					// client's estate.
					log.Printf("heartbeat while running %d: %v", t.ID, err)
				}
			}
		}
	}()
	defer close(done)

	a.execute(ctx, t)
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

func (a *Agent) execute(ctx context.Context, t *client.Task) {
	a.mu.Lock()
	a.busy, a.current = true, t.ID
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy, a.current = false, 0
		a.mu.Unlock()
	}()

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
	orphans, _ := a.sp.Orphaned()
	for _, e := range orphans {
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
