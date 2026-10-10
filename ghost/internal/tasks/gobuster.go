package tasks

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OJ/gobuster/v3/gobusterdir"
	"github.com/OJ/gobuster/v3/libgobuster"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// Content discovery, in this process.
//
// It used to shell out to a `gobuster` binary and read a wordlist off
// the host, which meant two ways to fail before a single request was
// sent: no binary, or no wordlist. Both were common. An agent dropped
// onto a host inside a client's network has whatever that host has,
// and "install dirb first" is not something the agent can do for
// itself from in there.
//
// # The embedded wordlist
//
// SecLists' `Discovery/Web-Content/common.txt`, 4,751 entries,
// embedded verbatim. MIT licensed, which this repository's Apache-2.0
// can carry with the notice kept -- see LICENSE-THIRD-PARTY.
//
// dirb's list of the same name is the other obvious candidate and is
// GPLv2. Taking that one would be a licence problem for every
// downstream user of a public Apache-2.0 repository, which is why it
// is not here.
//
// A wordlist on the host still wins when one is named or found: it
// may be longer, and somebody chose it for this engagement. The
// embedded one is a floor, so that an agent on a host with nothing
// installed still does something useful rather than reporting a
// clean zero.

//go:embed wordlists/common.txt
var builtinWordlist string

// wordlistPath returns a file for gobuster to read, and whether it is
// the built-in one.
//
// libgobuster takes a PATH rather than a reader, and its only
// alternative is "-" for stdin, which would mean swapping os.Stdin
// out from under a process that runs several tasks at once. Writing
// the embedded list to the task's own work directory is less clever
// and cannot race.
func wordlistPath(args map[string]any, workDir string) (string, bool, error) {
	if w := str(args, "wordlist"); w != "" {
		if _, err := os.Stat(w); err != nil {
			return "", false, fmt.Errorf("wordlist %s: %w", w, err)
		}
		return w, false, nil
	}
	// A list the host happens to have is better than the built-in one:
	// it is longer, and somebody chose it for this engagement.
	if p := firstExisting(
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/dirb/wordlists/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/opt/homebrew/share/dirb/wordlists/common.txt",
	); p != "" {
		return p, false, nil
	}
	p := filepath.Join(workDir, "gobuster-builtin.txt")
	if err := os.WriteFile(p, []byte(builtinWordlist), 0o600); err != nil {
		return "", false, fmt.Errorf("staging the built-in wordlist: %w", err)
	}
	return p, true, nil
}

// runGobuster walks a site's paths.
func runGobuster(ctx context.Context, args map[string]any, workDir string) Result {
	us := subjects(args, "url", "urls")
	if len(us) == 0 {
		return failed("gobuster needs `targets` (or `url`)")
	}
	if len(us) > 1 {
		return failed(
			"gobuster takes one url per task; got %d — queue one task each",
			len(us))
	}
	url := strings.TrimRight(us[0], "/")

	list, builtin, err := wordlistPath(args, workDir)
	if err != nil {
		return failed("%v", err)
	}

	global := &libgobuster.Options{
		Threads:    intArg(args, "threads", 10),
		Wordlist:   list,
		NoProgress: true,
		Quiet:      true,
		Delay:      time.Duration(intArg(args, "delay_ms", 0)) * time.Millisecond,
	}
	parsed, err := neturl.Parse(url)
	if err != nil || parsed.Host == "" {
		return failed("%q is not a usable url", url)
	}
	ua := str(args, "user_agent")
	if ua == "" {
		ua = defaultUserAgent
	}
	// Set through the embedded structs by name rather than as promoted
	// fields: promoted fields in a struct literal need go1.27 and this
	// module is go1.26.
	// Started from the library's own initialiser, which allocates the
	// parsed Sets. Building the struct literally leaves them nil and
	// gobuster refuses with "StatusCodes and StatusCodesBlacklist are
	// both not set" -- it checks the SET, not the string.
	dirOpts := gobusterdir.NewOptions()
	*dirOpts = gobusterdir.OptionsDir{
		StatusCodesParsed:          dirOpts.StatusCodesParsed,
		StatusCodesBlacklistParsed: dirOpts.StatusCodesBlacklistParsed,
		ExtensionsParsed:           dirOpts.ExtensionsParsed,
		ExcludeLengthParsed:        dirOpts.ExcludeLengthParsed,
		HTTPOptions: libgobuster.HTTPOptions{
			BasicHTTPOptions: libgobuster.BasicHTTPOptions{
				UserAgent: ua,
				Timeout:   time.Duration(intArg(args, "timeout_s", 10)) * time.Second,
				// A client's estate, not a lab. Certificates inside an
				// internal network are routinely self-signed or expired,
				// and refusing them means discovering nothing on the
				// hosts most worth looking at.
				NoTLSValidation: true,
			},
			URL:            parsed,
			FollowRedirect: true,
			Method:         http.MethodGet,
			// Authenticated discovery, when the task carries credentials.
			// Empty strings leave gobuster's own defaults alone.
			Username: str(args, "username"),
			Password: str(args, "password"),
			Cookies:  str(args, "cookies"),
		},
		Extensions: str(args, "extensions"),
		// Everything except 404. A blacklist rather than an allowlist
		// because the interesting answers are the unexpected ones: a 401
		// or a 403 on /admin says it exists, and gobuster's own default
		// allowlist of 200,204,301,302,307 hides exactly those.
		StatusCodesBlacklist: "404",
	}
	black, err := libgobuster.ParseCommaSeparatedInt(dirOpts.StatusCodesBlacklist)
	if err != nil {
		return failed("status blacklist: %v", err)
	}
	dirOpts.StatusCodesBlacklistParsed = black
	if dirOpts.Extensions != "" {
		ext, err := libgobuster.ParseExtensions(dirOpts.Extensions)
		if err != nil {
			return failed("extensions: %v", err)
		}
		dirOpts.ExtensionsParsed = ext
	}

	logger := libgobuster.NewLogger(false)
	plugin, err := gobusterdir.New(global, dirOpts, logger)
	if err != nil {
		return failed("gobuster setup: %v", err)
	}
	g, err := libgobuster.NewGobuster(global, plugin, logger)
	if err != nil {
		return failed("gobuster setup: %v", err)
	}

	// Drained in the background. The channels are unbuffered, so a
	// reader that is not running blocks the scan rather than merely
	// losing output.
	found := make(chan string, 256)
	errs := make(chan string, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case r, ok := <-g.Progress.ResultChan:
				if !ok {
					return
				}
				if s, e := r.ResultToString(); e == nil {
					if s = strings.TrimSpace(s); s != "" {
						select {
						case found <- s:
						default: // full: the summary is a count, not a log
						}
					}
				}
			case e, ok := <-g.Progress.ErrorChan:
				if !ok {
					return
				}
				select {
				case errs <- e.Error():
				default:
				}
			case <-g.Progress.MessageChan:
				// Progress chatter. Drained so it cannot block.
			case <-ctx.Done():
				return
			}
		}
	}()

	runErr := g.Run(ctx)
	// Run closes ResultChan itself on the way out. Closing it here as
	// well panics with "close of closed channel" -- which the live
	// test caught and no amount of reading the signature would have.
	// The drain goroutine exits on that close; `done` is how we know
	// it has finished writing before the slices are read.
	<-done
	close(found)
	close(errs)

	paths := make([]string, 0, len(found))
	for s := range found {
		paths = append(paths, s)
	}
	sort.Strings(paths)
	var stderr []string
	for s := range errs {
		stderr = append(stderr, s)
	}

	if runErr != nil && len(paths) == 0 {
		return failed("gobuster: %v", runErr)
	}

	which := list
	if builtin {
		which = "built-in (SecLists common.txt)"
	}
	return Result{
		Status: "done",
		Output: recon.JSON(map[string]any{
			"url": url, "wordlist": which, "found": paths}),
		Stderr: tail(strings.Join(stderr, "\n"), 4000),
		Summary: fmt.Sprintf("gobuster: %d path(s) on %s, %s wordlist",
			len(paths), url, map[bool]string{true: "built-in",
				false: "host"}[builtin]),
	}
}

// : Said on every request, because an engagement's traffic should be
// : attributable from the target's own logs without anybody having to
// : ask us who was scanning them.
const defaultUserAgent = "Oddjob-Ghost (authorised security assessment)"
