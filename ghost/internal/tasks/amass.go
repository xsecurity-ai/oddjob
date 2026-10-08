// Amass, in process, as a library rather than a subprocess.
//
// # Why
//
// The agent used to shell out to whatever `amass` was on the host. On
// our own droplet that was v3.19.2 from a snap, with no configuration,
// and it did not finish a PASSIVE enumeration of `example.com` inside
// five minutes — two and a half of which were system time, so it was
// not waiting on the network, it was thrashing. A real engagement zone
// took sixteen minutes and counting.
//
// None of the knobs that matter are reachable from the v3 command
// line. Recursion, how many DNS queries may be in flight, the query
// rate per resolver and which resolvers to use are all library-level
// settings, and the CLI exposes either nothing or a flag that applies
// only to active mode. So the way to make it faster is to stop talking
// to it through argv.
//
// # What this buys, besides speed
//
//   - No dependency on a binary being installed, at a version nobody
//     chose, behaving differently per host. The enumeration a ghost
//     runs is the one this repository pins.
//   - Results come out of the graph rather than being scraped from
//     stdout. v3 writes prose to the same stream as the names — "No
//     assets were discovered" is a sentence, and it used to be counted
//     as a hostname.
//   - Partial results survive a timeout. A run that is cut off has
//     still found most of what it was going to find, and throwing that
//     away was the old behaviour.
//
// # CGO
//
// amass v4 reaches sqlite through `modernc.org/sqlite` and
// `glebarez/go-sqlite`, both of which are pure Go. The ghost builds
// `CGO_ENABLED=0` for six targets and still does; that is asserted by
// the release build rather than assumed here.

package tasks

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/datasrcs"
	"github.com/owasp-amass/amass/v4/enum"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// Defaults for the knobs the v3 command line did not expose.
//
// These are the whole point of the change, so they are named and
// overridable per task rather than buried.
const (
	// In flight at once. amass defaults this far lower; the work is
	// almost entirely waiting on somebody else's resolver or API, so
	// the ceiling that matters is politeness rather than local CPU.
	defaultMaxDNSQueries = 20000
	// Per resolver, per second. Spread across many resolvers this is
	// well short of what any one of them would consider abuse.
	defaultResolversQPS = 100
)

// Public resolvers used when the task names none.
//
// Stated rather than inherited from the host: an agent inside a
// corporate network picks up a resolver that answers for the internal
// view of a zone, and an enumeration that silently returns somebody's
// split-horizon records is a wrong answer that looks like a right one.
var defaultResolvers = []string{
	"8.8.8.8", "8.8.4.4", // Google
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
}

// runAmassLib enumerates one zone with the amass v4 library.
func runAmassLib(ctx context.Context, args map[string]any, _ string) Result {
	// amass enumerates one zone at a time, so more than one is an
	// error rather than a silent drop.
	ds := subjects(args, "domain", "domains")
	if len(ds) == 0 {
		return failed("amass needs `targets` (or `domain`)")
	}
	if len(ds) > 1 {
		return failed(
			"amass takes one domain per task; got %d (%s) — queue one task each",
			len(ds), strings.Join(ds, ", "))
	}
	dom := ds[0]

	cfg := config.NewConfig()
	cfg.AddDomain(dom)
	// Passive by default. Active enumeration sends traffic to the
	// target's own infrastructure, which is a scope decision, so it is
	// asked for rather than assumed.
	cfg.Passive = str(args, "mode") != "active"
	// Recursive: follow what the sources turn up rather than stopping
	// at the first level. It is the difference between the zone and a
	// list of the names that happened to be indexed.
	cfg.Recursive = boolArg(args, "recursive", true)
	cfg.Verbose = false
	cfg.MaxDNSQueries = intArg(args, "max_dns_queries", defaultMaxDNSQueries)
	cfg.ResolversQPS = intArg(args, "resolvers_qps", defaultResolversQPS)
	cfg.AddResolvers(resolversFor(args)...)

	sys, err := systems.NewLocalSystem(cfg)
	if err != nil {
		return failed("amass: %v", err)
	}
	defer func() { _ = sys.Shutdown() }()

	if err := sys.SetDataSources(datasrcs.GetAllSources(sys)); err != nil {
		return failed("amass data sources: %v", err)
	}
	graphs := sys.GraphDatabases()
	if len(graphs) == 0 {
		return failed("amass: no graph database")
	}
	graph := graphs[0]

	// The deadline is ours, not amass's. `Start` returns when the
	// enumeration is done OR when the context is cancelled, and the
	// graph is read either way — a run that was cut off has still
	// found most of what it was going to find, and discarding that was
	// the old behaviour.
	runCtx, cancel := context.WithTimeout(ctx, timeout(args, 45*time.Minute))
	defer cancel()

	started := time.Now()
	e := enum.NewEnumeration(cfg, sys, graph)
	runErr := e.Start(runCtx)

	assets, err := graph.DB.FindByType(oam.FQDN, cfg.CollectionStartTime)
	if err != nil {
		// Only now is the error fatal. Failing on `runErr` before
		// reading the graph would throw away a timed-out run's results.
		if runErr != nil {
			return failed("amass: %v", runErr)
		}
		return failed("amass graph: %v", err)
	}

	seen := map[string]struct{}{}
	for _, a := range assets {
		if f, ok := a.Asset.(domain.FQDN); ok {
			seen[strings.ToLower(strings.TrimSuffix(f.Name, "."))] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	// Under the zone asked about, and nothing else. The graph holds
	// whatever the sources mentioned, which on a shared certificate is
	// somebody else's estate.
	names = hostnamesUnder(names, dom)

	note := ""
	if runErr != nil {
		// Said, not swallowed. A partial answer presented as a complete
		// one is the coverage gap that gets written up as "no further
		// names exist".
		note = fmt.Sprintf(" (incomplete: %v)", runErr)
	}
	mode := "passive"
	if !cfg.Passive {
		mode = "active"
	}
	return Result{
		Status: "done",
		Output: recon.JSON(map[string]any{
			"domain": dom, "names": names, "mode": mode,
			"complete": runErr == nil,
			"seconds":  int(time.Since(started).Seconds()),
		}),
		Stderr: strings.TrimSpace(note),
		Summary: fmt.Sprintf("amass found %d name(s) under %s in %ds%s",
			len(names), dom, int(time.Since(started).Seconds()), note),
	}
}

// intArg is a whole number from the task, or `def`.
//
// JSON numbers arrive as float64, which is the only form the server
// ever sends; an int is accepted too so a caller constructing args in
// Go is not surprised. Zero and negative mean "use the default"
// rather than "no queries at all", because the second is a ghost that
// looks alive and finds nothing.
func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	}
	return def
}

// boolArg is a flag from the task, or `def` when it is absent.
//
// Absent and false are different answers and must stay that way: the
// default here is true, so reading a missing key as false would turn
// recursion off for every task that did not mention it.
func boolArg(args map[string]any, key string, def bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}

// resolversFor is the task's resolvers, or the defaults.
func resolversFor(args map[string]any) []string {
	if rs := subjects(args, "resolver", "resolvers"); len(rs) > 0 {
		return rs
	}
	return defaultResolvers
}
