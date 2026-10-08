// Package config holds how a Drone was told to run.
package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/drone/internal/recon"
)

// Version is stamped at build time with -ldflags, from the VERSION
// file at the repository root. That file is the single place a version
// number is decided; see scripts/version.sh.
//
// Three shapes reach the server on register, and they mean different
// things:
//
//	0.1.0                 a release build
//	0.1.0-dev-1759900000  built from a working tree, at that commit
//	dev                   not stamped at all
//
// "dev" is the literal below and is what a bare `go build` or `go
// test` produces. It is deliberately not a version number: an agent
// reporting it was not built by the Makefile, the Dockerfile or CI,
// and Oddjob's fleet summary shows it in its own row rather than
// sorting it in among the releases. A plausible-looking default here
// would be worse than an implausible one — it would be indistinguish-
// able from a real release in the one table whose job is telling them
// apart.
var Version = "dev"

type Config struct {
	// Server is the Oddjob base URL, e.g. https://oddjob.internal.
	Server string
	// CallbackKey authenticates this agent TO the server.
	CallbackKey string
	// CallInKey authenticates the SERVER to this agent, on the inbound
	// listener. Separate from CallbackKey on purpose: they protect
	// opposite directions, and one leaking should not hand over both.
	CallInKey string
	// EnrollToken is one-time, traded for a keypair on first run.
	EnrollToken string

	// Listen is the inbound address, empty to disable. Loopback by
	// default because the reverse channel is a convenience and an open
	// port on an engagement host is a liability.
	Listen string
	// Advertise is the URL the server should use to reach Listen. Only
	// meaningful when the server can actually route to it.
	Advertise string

	Name      string
	Heartbeat time.Duration
	// MaxSilence is how long this Drone will go unable to reach Oddjob
	// before it uninstalls what it installed and stops for good.
	//
	// A Drone is a privileged process holding a credential to someone
	// else's engagement data, and engagements end whether or not
	// anybody remembers to tear down the fleet. Left alone it survives
	// reboots -- that is what `--restart unless-stopped` and
	// `Restart=always` are for -- so the thing that eventually removes
	// it has to be the Drone itself.
	//
	// Zero disables it, which is the right answer for a long-lived
	// Drone on infrastructure you own and watch, and the wrong one
	// almost everywhere else.
	MaxSilence time.Duration
	// Insecure skips TLS verification. Engagement infrastructure
	// routinely has a self-signed certificate; refusing to connect is
	// not a useful default for a tool that lives on that network. It is
	// still opt-in, and announced loudly at startup.
	Insecure bool
	// WorkDir is where tool output is staged before it is sent home.
	WorkDir string
	// AllowPlaintext permits a non-loopback http:// server. Opt-in and
	// announced, because the thing it gives up is quiet.
	AllowPlaintext bool

	// PublicIPURL is the service asked, once at registration, what
	// this host's traffic looks like from outside. Nothing but the
	// bare request is sent, and the answer is the only one that
	// survives NAT — the routing table cannot see past the first hop,
	// and in a container it cannot see past the container.
	//
	// Settable so it can be pointed at infrastructure of our own, and
	// emptiable (DRONE_PUBLIC_IP_URL=off) because on a quiet
	// engagement a single connection to a third party may be more
	// exposure than the address is worth. Empty falls straight to the
	// local answer, labelled as local.
	PublicIPURL string

	// Parallel is how many tasks this Drone runs at once. Zero means
	// work it out from the host -- see internal/capacity, which is the
	// default and the right answer almost always.
	//
	// Set it when you know something the host does not advertise: a
	// container whose memory limit /proc/meminfo does not reflect, a
	// box you are deliberately keeping quiet, or an engagement where
	// the uplink rather than the scanner is the constraint. It wins
	// over the memory estimate rather than being clamped by it,
	// because the operator saying 8 and getting 2 with no explanation
	// is how people conclude the setting does nothing.
	Parallel int
}

// hasSavedIdentity reports whether a previous run already enrolled.
// Only the presence of the file matters here; whether it is readable
// is the agent's problem to report properly, with the path in the
// message, rather than this turning into "nothing to authenticate
// with" for a file that is merely unreadable.
func (c *Config) hasSavedIdentity() bool {
	_, err := os.Stat(c.IdentityPath())
	return err == nil
}

// isLoopback reports whether the server URL points back at this host.
// A reverse tunnel terminates on 127.0.0.1, and demanding TLS inside
// an SSH tunnel is theatre.
func isLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) Validate() error {
	var problems []string
	if strings.TrimSpace(c.Server) == "" {
		problems = append(problems, "--server is required (the Oddjob base URL)")
	} else if !strings.HasPrefix(c.Server, "http://") &&
		!strings.HasPrefix(c.Server, "https://") {
		problems = append(problems, "--server must start with http:// or https://")
	} else if strings.HasPrefix(c.Server, "http://") && !c.AllowPlaintext &&
		!isLoopback(c.Server) {
		// The payload is sealed end to end, so plaintext here does not
		// expose scan results. It still exposes which agent is talking
		// to which Oddjob, how often, and how much — and it leaves the
		// enrollment exchange, which is NOT sealed because it is what
		// establishes the key, open to anyone on the path.
		//
		// Loopback is excepted because that is a tunnel endpoint, where
		// the encryption is the tunnel's and adding TLS inside it buys
		// nothing.
		problems = append(problems,
			"--server is plaintext http://. Use https://, or pass "+
				"--allow-plaintext if this is deliberate (a tunnel, a lab). "+
				"Loopback addresses are already excepted.")
	}
	// Three ways to be authenticated, and the check cannot see the
	// third: an identity already saved on disk from a previous run.
	// So this only refuses when there is clearly nothing at all --
	// the identity file is looked for later, before any request.
	if strings.TrimSpace(c.CallbackKey) == "" &&
		strings.TrimSpace(c.EnrollToken) == "" &&
		!c.hasSavedIdentity() {
		problems = append(problems,
			"nothing to authenticate with: pass --enroll with the one-time "+
				"token Oddjob showed when this agent was created, or --key "+
				"for an agent enrolled before identities existed")
	}
	if c.Listen != "" && c.CallInKey == "" {
		// Otherwise the listener is an unauthenticated command endpoint
		// on a privileged process. Refusing is the only safe answer.
		problems = append(problems,
			"--listen needs --call-in-key, or the inbound API would be unauthenticated")
	}
	if c.Heartbeat < time.Second {
		problems = append(problems, "--heartbeat must be at least 1s")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  "))
	}
	return nil
}

// Defaults returns a Config with the sane values filled in.
func Defaults() *Config {
	host, _ := os.Hostname()
	if host == "" {
		host = "drone"
	}
	return &Config{
		Name:        fmt.Sprintf("%s-%s", host, runtime.GOOS),
		Heartbeat:   15 * time.Second,
		Listen:      "",
		WorkDir:     defaultWorkDir(),
		MaxSilence:  12 * time.Hour,
		PublicIPURL: recon.DefaultPublicIPURL,
	}
}

func defaultWorkDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return d + string(os.PathSeparator) + "drone"
	}
	return os.TempDir() + string(os.PathSeparator) + "drone"
}

// SpoolDir is where results wait until the server has them. Under
// WorkDir, which the operator already chose and which has to be
// writable for the tools to stage output anyway.
func (c *Config) SpoolDir() string {
	return filepath.Join(c.WorkDir, "spool")
}

// IdentityPath is where the agent's keypair and the pinned server key
// live. Beside the spool, and 0600.
func (c *Config) IdentityPath() string {
	return filepath.Join(c.WorkDir, "identity.json")
}

func env(name string) string { return os.Getenv("DRONE_" + name) }

// FromEnv fills anything still empty from DRONE_* variables, so a key
// need never appear in a command line — process lists are readable by
// every user on the box, which on an engagement host is the point.
func (c *Config) FromEnv() {
	if c.Server == "" {
		c.Server = env("SERVER")
	}
	if c.CallbackKey == "" {
		c.CallbackKey = env("KEY")
	}
	if c.CallInKey == "" {
		c.CallInKey = env("CALL_IN_KEY")
	}
	if c.EnrollToken == "" {
		c.EnrollToken = env("ENROLL_TOKEN")
	}
	// Only when the flag was left at its default: an explicit
	// --workdir is the operator saying where, and the environment
	// should not quietly win against that.
	if v := env("WORKDIR"); v != "" && c.WorkDir == Defaults().WorkDir {
		c.WorkDir = v
	}
	if c.Advertise == "" {
		c.Advertise = env("ADVERTISE")
	}
	// Same rule again, and "off" is spelled out rather than being the
	// empty string: an empty DRONE_PUBLIC_IP_URL is indistinguishable
	// from an unset one, and "I did not set this" must not silently
	// mean "I turned this off".
	if v := env("PUBLIC_IP_URL"); v != "" && c.PublicIPURL == Defaults().PublicIPURL {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "off", "none", "disabled":
			c.PublicIPURL = ""
		default:
			c.PublicIPURL = v
		}
	}
	// Same rule as WORKDIR: the environment only fills what the flag
	// left at its default. "0" is a deliberate value here, meaning
	// never time out, so it has to be distinguishable from unset.
	if v := env("MAX_SILENCE"); v != "" && c.MaxSilence == Defaults().MaxSilence {
		if d, err := time.ParseDuration(v); err == nil {
			c.MaxSilence = d
		} else {
			log.Printf("WARNING: DRONE_MAX_SILENCE=%q is not a duration "+
				"(try 12h) — keeping %s", v, c.MaxSilence)
		}
	}
	// Same rule: only when the flag was left alone. A bad value is
	// reported and ignored rather than silently becoming zero, which
	// reads as "autosize" and would look like the setting was never
	// applied at all.
	if v := env("PARALLEL"); v != "" && c.Parallel == 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			c.Parallel = n
		} else {
			log.Printf("WARNING: DRONE_PARALLEL=%q is not a count — "+
				"sizing from the host instead", v)
		}
	}
}
