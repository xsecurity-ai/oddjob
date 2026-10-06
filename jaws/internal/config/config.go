// Package config holds how Jaws was told to run.
package config

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// Version is stamped at build time with -ldflags.
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

	// Listen is the inbound address, empty to disable. Loopback by
	// default because the reverse channel is a convenience and an open
	// port on an engagement host is a liability.
	Listen string
	// Advertise is the URL the server should use to reach Listen. Only
	// meaningful when the server can actually route to it.
	Advertise string

	Name      string
	Heartbeat time.Duration
	// Insecure skips TLS verification. Engagement infrastructure
	// routinely has a self-signed certificate; refusing to connect is
	// not a useful default for a tool that lives on that network. It is
	// still opt-in, and announced loudly at startup.
	Insecure bool
	// WorkDir is where tool output is staged before it is sent home.
	WorkDir string
}

func (c *Config) Validate() error {
	var problems []string
	if strings.TrimSpace(c.Server) == "" {
		problems = append(problems, "--server is required (the Oddjob base URL)")
	} else if !strings.HasPrefix(c.Server, "http://") &&
		!strings.HasPrefix(c.Server, "https://") {
		problems = append(problems, "--server must start with http:// or https://")
	}
	if strings.TrimSpace(c.CallbackKey) == "" {
		problems = append(problems,
			"--key is required (shown once when the agent was enrolled)")
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
		host = "jaws"
	}
	return &Config{
		Name:      fmt.Sprintf("%s-%s", host, runtime.GOOS),
		Heartbeat: 15 * time.Second,
		Listen:    "",
		WorkDir:   defaultWorkDir(),
	}
}

func defaultWorkDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return d + string(os.PathSeparator) + "jaws"
	}
	return os.TempDir() + string(os.PathSeparator) + "jaws"
}

// FromEnv fills anything still empty from JAWS_* variables, so a key
// need never appear in a command line — process lists are readable by
// every user on the box, which on an engagement host is the point.
func (c *Config) FromEnv() {
	if c.Server == "" {
		c.Server = os.Getenv("JAWS_SERVER")
	}
	if c.CallbackKey == "" {
		c.CallbackKey = os.Getenv("JAWS_KEY")
	}
	if c.CallInKey == "" {
		c.CallInKey = os.Getenv("JAWS_CALL_IN_KEY")
	}
	if c.Advertise == "" {
		c.Advertise = os.Getenv("JAWS_ADVERTISE")
	}
}
