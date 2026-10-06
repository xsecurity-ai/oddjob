// Command jaws is a grey-zone enumeration agent for Oddjob.
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

	"github.com/xsecurity-ai/oddjob/jaws/internal/agent"
	"github.com/xsecurity-ai/oddjob/jaws/internal/callin"
	"github.com/xsecurity-ai/oddjob/jaws/internal/config"
	"github.com/xsecurity-ai/oddjob/jaws/internal/recon"
	"github.com/xsecurity-ai/oddjob/jaws/internal/tools"
)

const usage = `jaws — enumeration agent for Oddjob

  jaws run      connect to Oddjob and take tasking
  jaws check    report what this host can do, and exit
  jaws install  install the baseline tools, and exit
  jaws lookup   resolve a name or address, and exit
  jaws rdns     find the domains hosted on an address, and exit
  jaws version

Keys can come from the environment instead of the command line, which
is how to keep them out of the process list on a shared host:

  JAWS_SERVER  JAWS_KEY  JAWS_CALL_IN_KEY  JAWS_ADVERTISE
  JAWS_ENROL_TOKEN  JAWS_WORKDIR
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
	case "check":
		os.Exit(cmdCheck())
	case "install":
		os.Exit(cmdInstall(os.Args[2:]))
	case "lookup":
		os.Exit(cmdLookup(os.Args[2:]))
	case "rdns":
		os.Exit(cmdRDNS(os.Args[2:]))
	case "version":
		fmt.Printf("jaws %s (%s/%s, %s)\n", config.Version,
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
	fs.StringVar(&cfg.CallbackKey, "key", "", "callback key (or JAWS_KEY)")
	fs.StringVar(&cfg.CallInKey, "call-in-key", "", "key the server must present")
	fs.StringVar(&cfg.EnrolToken, "enrol", "", "one-time enrolment token from Oddjob (or JAWS_ENROL_TOKEN)")
	fs.StringVar(&cfg.Listen, "listen", "", "inbound API address, e.g. 127.0.0.1:7777")
	fs.StringVar(&cfg.Advertise, "advertise", "", "URL the server should use to reach --listen")
	fs.StringVar(&cfg.Name, "name", cfg.Name, "name to report")
	fs.DurationVar(&cfg.Heartbeat, "heartbeat", cfg.Heartbeat, "poll interval")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&cfg.AllowPlaintext, "allow-plaintext", false,
		"permit a non-loopback http:// server")
	fs.StringVar(&cfg.WorkDir, "workdir", cfg.WorkDir, "where tool output is staged")
	_ = fs.Parse(argv)

	cfg.FromEnv()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "jaws: \n  %v\n", err)
		return 2
	}
	if cfg.Insecure {
		// Narrower than it used to read: the payload is sealed under
		// keys pinned at enrolment, so a man in the middle cannot read
		// results or forge tasking. What is given up is the transport's
		// own protection of the enrolment exchange and the metadata.
		log.Printf("WARNING: TLS verification is OFF. The payload is still " +
			"sealed end to end, but the enrolment exchange and all traffic " +
			"metadata are exposed to anyone on the path")
	}
	if cfg.AllowPlaintext {
		log.Printf("WARNING: talking to a plaintext http:// server by " +
			"request. The payload is sealed; the enrolment exchange is not")
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
		log.Printf("jaws: %v", err)
		return 1
	}
	return 0
}

func cmdCheck() int {
	ctx := context.Background()
	priv, advice := tools.RawSocketCapable()
	mgr, why := tools.DetectManager()
	mgrName := "none"
	if mgr != nil {
		mgrName = mgr.Name
		why = ""
	}
	out := map[string]any{
		"version":         config.Version,
		"platform":        runtime.GOOS,
		"arch":            runtime.GOARCH,
		"privileged":      priv,
		"privilege":       advice,
		"package_manager": mgrName,
		"outbound_ip":     recon.OutboundIP(),
		"interfaces":      recon.InterfaceIPs(),
		"tools":           tools.Installed(ctx),
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
		fmt.Fprintln(os.Stderr, "usage: jaws lookup <name|ip> [...]")
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
		fmt.Fprintln(os.Stderr, "usage: jaws rdns <ip> [...]")
		return 2
	}
	out := make([]*recon.ReverseIP, 0, len(argv))
	for _, ip := range argv {
		out = append(out, recon.ReverseIPLookup(context.Background(), ip))
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
