// Command drone is a grey-zone enumeration agent for Oddjob.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/xsecurity-ai/oddjob/drone/internal/agent"
	"github.com/xsecurity-ai/oddjob/drone/internal/callin"
	"github.com/xsecurity-ai/oddjob/drone/internal/config"
	"github.com/xsecurity-ai/oddjob/drone/internal/recon"
	"github.com/xsecurity-ai/oddjob/drone/internal/retire"
	"github.com/xsecurity-ai/oddjob/drone/internal/tools"
)

const usage = `drone — enumeration agent for Oddjob

  drone run      connect to Oddjob and take tasking
  drone check    report what this host can do, and exit
  revive    clear a retirement marker so a stopped drone can start again
  drone install  install the baseline tools, and exit
  drone lookup   resolve a name or address, and exit
  drone rdns     find the domains hosted on an address, and exit
  drone version

Keys can come from the environment instead of the command line, which
is how to keep them out of the process list on a shared host:

  DRONE_SERVER  DRONE_KEY  DRONE_CALL_IN_KEY  DRONE_ADVERTISE
  DRONE_ENROLL_TOKEN  DRONE_WORKDIR  DRONE_PUBLIC_IP_URL
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "revive":
		os.Exit(cmdRevive(os.Args[2:]))
	case "check":
		os.Exit(cmdCheck(os.Args[2:]))
	case "install":
		os.Exit(cmdInstall(os.Args[2:]))
	case "lookup":
		os.Exit(cmdLookup(os.Args[2:]))
	case "rdns":
		os.Exit(cmdRDNS(os.Args[2:]))
	case "version":
		fmt.Printf("drone %s (%s/%s, %s)\n", config.Version,
			runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdRun(argv []string) int {
	cfg := config.Defaults()
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fs.StringVar(&cfg.Server, "server", "", "Oddjob base URL")
	fs.StringVar(&cfg.CallbackKey, "key", "", "callback key (or DRONE_KEY)")
	fs.StringVar(&cfg.CallInKey, "call-in-key", "", "key the server must present")
	fs.StringVar(&cfg.EnrollToken, "enroll", "", "one-time enrollment token from Oddjob (or DRONE_ENROLL_TOKEN)")
	fs.StringVar(&cfg.Listen, "listen", "", "inbound API address, e.g. 127.0.0.1:7777")
	fs.StringVar(&cfg.Advertise, "advertise", "", "URL the server should use to reach --listen")
	fs.StringVar(&cfg.Name, "name", cfg.Name, "name to report")
	fs.DurationVar(&cfg.Heartbeat, "heartbeat", cfg.Heartbeat, "poll interval")
	fs.DurationVar(&cfg.MaxSilence, "max-silence", cfg.MaxSilence,
		"uninstall and stop after this long unable to reach Oddjob (0 disables)")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&cfg.AllowPlaintext, "allow-plaintext", false,
		"permit a non-loopback http:// server")
	fs.StringVar(&cfg.WorkDir, "workdir", cfg.WorkDir, "where tool output is staged")
	fs.IntVar(&cfg.Parallel, "parallel", cfg.Parallel,
		"tasks to run at once (0 sizes from the host, or DRONE_PARALLEL)")
	fs.StringVar(&cfg.PublicIPURL, "public-ip-url", cfg.PublicIPURL,
		"service asked for our public address once at registration "+
			"(empty, or DRONE_PUBLIC_IP_URL=off, to ask nobody)")
	_ = fs.Parse(argv)

	cfg.FromEnv()

	// Before the credential check, and before touching the network:
	// has this Drone already been retired?
	//
	// Exiting is not what stops a Drone. `--restart unless-stopped`
	// and `Restart=always` both bring it back within seconds, and both
	// are what the documentation tells people to use — so without a
	// mark on disk, "kill this drone" is a four-second pause. The work
	// directory is a volume precisely so this survives.
	//
	// Ahead of Validate() because a retired Drone's enrollment token
	// is spent: it would otherwise report "nothing to authenticate
	// with", which is true, useless, and hides the real reason.
	if t, ok := retire.Marked(cfg.WorkDir); ok {
		log.Printf("this drone was retired: %s", t.Reason)
		if t.At != "" {
			log.Printf("  at %s", t.At)
		}
		if len(t.Failed) > 0 {
			log.Printf("  tools it could NOT remove, still on this host: %v",
				t.Failed)
		}
		log.Printf("  not starting. To bring it back deliberately: "+
			"drone revive --workdir %s", cfg.WorkDir)
		// Zero, not an error: a supervisor that sees a failure exit
		// restarts it, logs the failure, and does that forever.
		return 0
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "drone: \n  %v\n", err)
		return 2
	}
	if cfg.Insecure {
		// Narrower than it used to read: the payload is sealed under
		// keys pinned at enrollment, so a man in the middle cannot read
		// results or forge tasking. What is given up is the transport's
		// own protection of the enrollment exchange and the metadata.
		log.Printf("WARNING: TLS verification is OFF. The payload is still " +
			"sealed end to end, but the enrollment exchange and all traffic " +
			"metadata are exposed to anyone on the path")
	}
	if cfg.AllowPlaintext {
		log.Printf("WARNING: talking to a plaintext http:// server by " +
			"request. The payload is sealed; the enrollment exchange is not")
	}

	priv, advice := tools.RawSocketCapable()
	if !priv {
		// Said at startup rather than discovered per-task: several
		// modules simply will not work, and finding that out one scan
		// at a time wastes an engagement day.
		log.Printf("WARNING: %s", advice)
		log.Printf("         masscan will refuse; nmap will fall back to connect scans")
	}

	ag := agent.New(cfg)

	var in *callin.Server
	if cfg.Listen != "" {
		in = callin.New(cfg.Listen, cfg.CallInKey, ag, ag)
		in.Start()
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := ag.Run(ctx)

	if in != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		in.Stop(sctx)
		cancel()
	}
	if err != nil && ctx.Err() == nil {
		log.Printf("drone: %v", err)
		return 1
	}
	return 0
}

func cmdRevive(argv []string) int {
	cfg := config.Defaults()
	fs := flag.NewFlagSet("revive", flag.ExitOnError)
	fs.StringVar(&cfg.WorkDir, "workdir", cfg.WorkDir, "the drone's work directory")
	_ = fs.Parse(argv)
	cfg.FromEnv()

	t, ok := retire.Marked(cfg.WorkDir)
	if !ok {
		fmt.Printf("not retired: no marker in %s\n", cfg.WorkDir)
		return 0
	}
	if err := retire.Unmark(cfg.WorkDir); err != nil {
		fmt.Fprintf(os.Stderr, "drone: could not clear the marker: %v\n", err)
		return 1
	}
	fmt.Printf("cleared the retirement marker (%s).\n", t.Reason)
	// The identity went with the kill, and the tools it uninstalled
	// are not coming back on their own. Say so rather than letting
	// somebody discover it on the next task.
	fmt.Printf("This drone still needs a fresh enrollment token, and any " +
		"tools it uninstalled will be reinstalled on the next start.\n")
	return 0
}

func cmdCheck(argv []string) int {
	cfg := config.Defaults()
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	fs.StringVar(&cfg.PublicIPURL, "public-ip-url", cfg.PublicIPURL,
		"service asked for our public address (empty to ask nobody)")
	_ = fs.Parse(argv)
	cfg.FromEnv()

	ctx := context.Background()
	priv, advice := tools.RawSocketCapable()
	mgr, why := tools.DetectManager()
	mgrName := "none"
	if mgr != nil {
		mgrName = mgr.Name
		why = ""
	}
	hp := recon.DetectHostPlatform()
	addr := recon.OutboundAddress(ctx, cfg.PublicIPURL)
	out := map[string]any{
		"version":  config.Version,
		"platform": runtime.GOOS,
		// What the machine under this process is, as distinct from
		// what this process is. They differ in a container, and under
		// WSL2 they differ in the way that matters most: a Linux
		// binary on a Windows host.
		"host_platform":        hp.Host,
		"host_platform_label":  hp.String(),
		"host_platform_source": hp.HostWhy,
		"container":            hp.Container,
		"arch":                 runtime.GOARCH,
		"privileged":           priv,
		"privilege":            advice,
		"package_manager":      mgrName,
		"outbound_ip":          addr.IP,
		// Never the address without where it came from: "172.17.0.3"
		// and "198.51.100.7" are not the same kind of claim and cannot
		// be told apart by looking at them.
		"outbound_ip_source": addr.Source,
		"interfaces":         recon.InterfaceIPs(),
		"tools":              tools.Installed(ctx),
	}
	if addr.Note != "" {
		out["outbound_ip_note"] = addr.Note
	}
	if why != "" {
		out["package_manager_note"] = why
	}
	// Named separately so "httpx is installed, why does httpx not
	// work" has an answer on the first look rather than the third.
	if imp := tools.Impostors(ctx); len(imp) > 0 {
		out["wrong_tool_on_path"] = imp
	}
	missing := []string{}
	for _, t := range tools.Baseline {
		if tools.Path(t) == "" {
			missing = append(missing, t)
		}
	}
	out["missing_baseline"] = missing
	fmt.Println(recon.JSON(out))
	// Non-zero when something a task would need is absent, so this is
	// usable as a readiness probe rather than only as something to read.
	if !priv || len(missing) > 0 {
		return 1
	}
	return 0
}

func cmdInstall(argv []string) int {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	extra := fs.String("tools", "", "comma-separated; default is the baseline")
	_ = fs.Parse(argv)

	want := tools.Baseline
	if *extra != "" {
		want = splitComma(*extra)
	}
	reports := tools.Ensure(context.Background(), want, tools.Privileged())
	fmt.Println(recon.JSON(reports))
	for _, r := range reports {
		if r.Action == "failed" {
			return 1
		}
	}
	return 0
}

func cmdLookup(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: drone lookup <name|ip> [...]")
		return 2
	}
	out := make([]*recon.Lookup, 0, len(argv))
	for _, q := range argv {
		out = append(out, recon.NSLookup(context.Background(), q))
	}
	fmt.Println(recon.JSON(out))
	return 0
}

func cmdRDNS(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "usage: drone rdns <ip> [...]")
		return 2
	}
	// `drone rdns` is the hand-run version and has no project behind
	// it, so there are no known names to confirm forward against —
	// PTR only. The empty index says "nothing was checked", which the
	// output reports rather than implying none exist.
	idx := recon.BuildNameIndex(context.Background(), nil)
	out := make([]*recon.ReverseIP, 0, len(argv))
	for _, ip := range argv {
		out = append(out, recon.ReverseIPLookup(context.Background(), ip, idx))
	}
	fmt.Println(recon.JSON(out))
	return 0
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		if r != ' ' {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

var _ = json.Marshal
