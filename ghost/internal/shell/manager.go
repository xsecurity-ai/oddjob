package shell

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
)

// Spec is one listener Oddjob has asked this Ghost to hold.
type Spec struct {
	ID       int    `json:"id"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func (s Spec) key() string { return fmt.Sprintf("%s/%d", s.Protocol, s.Port) }

// Status is what became of one. Sent back on the next heartbeat.
//
// `Bound` is a fact about this host, not an opinion: it is true only
// when the socket is actually held. The operator's screen says
// "pending" until one of these arrives, which is the honest state --
// see `app/listeners.report`, which refuses to read silence as
// failure.
type Status struct {
	ID    int    `json:"id"`
	Bound bool   `json:"bound"`
	Error string `json:"error,omitempty"`
}

// closer is the half of a listener the manager needs.
type closer interface {
	Close() error
}

type held struct {
	spec Spec
	stop context.CancelFunc
	ln   closer
}

// Manager keeps this Ghost's listeners matching what Oddjob asked
// for.
//
// Reconciliation, not commands: the heartbeat carries the whole
// desired set every time and this works out the difference. A
// command stream would need the agent to have received every message
// ever sent -- and an agent that was offline for an hour has not,
// so its ports would be whatever the last message it did get said.
//
// The tunnel is opened when the first listener is wanted and closed
// when the last goes, because a websocket held open for nothing is a
// connection an operator has to explain in a netstat.
type Manager struct {
	// dial opens a fresh tunnel home. Called again after a drop.
	dial func(context.Context) (Transport, error)

	mu     sync.Mutex
	mux    *Mux
	closer func()
	held   map[string]*held
	status map[int]Status
}

func NewManager(dial func(context.Context) (Transport, error)) *Manager {
	return &Manager{dial: dial, held: map[string]*held{},
		status: map[int]Status{}}
}

// Report is what to tell Oddjob on the next beat.
//
// Only listeners this agent has actually tried are in it. A spec it
// has never seen is absent rather than reported as failed, because
// "I have not got to it" and "it would not bind" are different
// answers and only one of them needs an operator.
func (m *Manager) Report() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.status))
	for _, s := range m.status {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Reconcile makes the held set match `want`.
//
// Ports already held with the same id are left ALONE. Rebinding one
// on every beat would drop every shell on it every few seconds,
// which is the one thing this feature exists to prevent.
func (m *Manager) Reconcile(ctx context.Context, want []Spec) {
	wanted := map[string]Spec{}
	for _, s := range want {
		if s.Protocol == "" {
			s.Protocol = "tcp"
		}
		if s.Port <= 0 || s.Port > 65535 {
			// The server validates this too. Checked again here
			// because a Ghost binding whatever a server told it to
			// is a Ghost that does what a compromised server says.
			continue
		}
		wanted[s.key()] = s
	}

	m.mu.Lock()
	var drop []*held
	for key, h := range m.held {
		if w, ok := wanted[key]; !ok || w.ID != h.spec.ID {
			drop = append(drop, h)
			delete(m.held, key)
			delete(m.status, h.spec.ID)
		}
	}
	m.mu.Unlock()

	for _, h := range drop {
		log.Printf("shell: releasing %s", h.spec.key())
		h.stop()
		_ = h.ln.Close()
	}

	for key, spec := range wanted {
		m.mu.Lock()
		_, already := m.held[key]
		m.mu.Unlock()
		if already {
			continue
		}
		m.open(ctx, spec)
	}

	m.mu.Lock()
	idle := len(m.held) == 0 && m.mux != nil
	stop := m.closer
	m.mu.Unlock()
	if idle && stop != nil {
		stop()
	}
}

// open binds one listener and records what happened either way.
func (m *Manager) open(ctx context.Context, spec Spec) {
	mux, err := m.tunnel(ctx)
	if err != nil {
		// No route home, so a bound port would catch shells nobody
		// can see. Recorded as a failure WITH the reason -- an
		// operator reading "tunnel: 401" looks at the agent's keys
		// rather than at the client's firewall.
		m.note(spec.ID, false, fmt.Sprintf("no tunnel to oddjob: %v", err))
		return
	}

	// Its own context, so releasing one listener does not stop the
	// others. Cancelling it ends this listener's accept loop.
	lctx, cancel := context.WithCancel(ctx)
	var ln closer
	switch spec.Protocol {
	case "udp":
		p, perr := OpenPacket(lctx, mux, spec.Port)
		if perr != nil {
			cancel()
			m.note(spec.ID, false, perr.Error())
			return
		}
		ln = p
		go func() {
			if err := p.Run(lctx); err != nil && lctx.Err() == nil {
				log.Printf("shell: udp/%d stopped: %v", spec.Port, err)
			}
		}()
	default:
		l, lerr := Open(lctx, mux, spec.Port)
		if lerr != nil {
			cancel()
			// The message people actually need: "address already in
			// use" is the whole answer most of the time.
			m.note(spec.ID, false, lerr.Error())
			return
		}
		ln = l
		go func() {
			if err := l.Run(lctx); err != nil && lctx.Err() == nil {
				log.Printf("shell: tcp/%d stopped: %v", spec.Port, err)
			}
		}()
	}

	m.mu.Lock()
	m.held[spec.key()] = &held{spec: spec, stop: cancel, ln: ln}
	m.mu.Unlock()
	m.note(spec.ID, true, "")
	log.Printf("shell: holding %s", spec.key())
}

// tunnel returns the live mux, dialling one if there is none.
func (m *Manager) tunnel(ctx context.Context) (*Mux, error) {
	m.mu.Lock()
	if m.mux != nil {
		mux := m.mux
		m.mu.Unlock()
		return mux, nil
	}
	m.mu.Unlock()

	t, err := m.dial(ctx)
	if err != nil {
		return nil, err
	}
	mux := NewMux(t)
	tctx, cancel := context.WithCancel(ctx)

	m.mu.Lock()
	m.mux = mux
	m.closer = func() {
		cancel()
		mux.Close()
		m.mu.Lock()
		m.mux = nil
		m.closer = nil
		m.mu.Unlock()
	}
	stop := m.closer
	m.mu.Unlock()

	go func() {
		err := mux.Run(tctx)
		// Read BEFORE stop(), which cancels this very context --
		// asking afterwards always answers "deliberate" and the
		// release below never runs.
		deliberate := tctx.Err() != nil
		stop()
		if deliberate {
			return // this manager shutting down on purpose
		}
		// The tunnel went while listeners still want it.
		//
		// The listeners have to be RELEASED, not kept. Each one
		// holds a pointer to this mux, and the transport under it is
		// dead -- so a port left bound would go on accepting
		// callbacks and sending them into a closed socket, for ever.
		// Reconcile would not fix it either: it sees the port as
		// already held and leaves it alone, which is exactly right
		// when the tunnel is up and exactly wrong here.
		//
		// Nothing announces that failure. The port answers, the
		// payload connects, and no session ever appears in Oddjob.
		// So: drop them, and let the next beat rebind against a
		// fresh tunnel. The shells that were live are lost either
		// way -- the route to them is what went -- which is why the
		// server marks them `lost` rather than `closed`.
		log.Printf("shell: tunnel ended (%v); releasing listeners to rebind", err)
		m.releaseAll()
	}()
	return mux, nil
}

// releaseAll drops every listener and forgets what was reported
// about them, so the next Reconcile binds them again from scratch.
func (m *Manager) releaseAll() {
	m.mu.Lock()
	all := make([]*held, 0, len(m.held))
	for key, h := range m.held {
		all = append(all, h)
		delete(m.held, key)
		delete(m.status, h.spec.ID)
	}
	m.mu.Unlock()
	for _, h := range all {
		h.stop()
		_ = h.ln.Close()
	}
}

func (m *Manager) note(id int, bound bool, why string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status[id] = Status{ID: id, Bound: bound, Error: why}
}

// Close releases every listener and the tunnel.
func (m *Manager) Close() {
	m.releaseAll()
	m.mu.Lock()
	stop := m.closer
	m.mu.Unlock()
	if stop != nil {
		stop()
	}
}
