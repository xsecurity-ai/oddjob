package tasks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"time"

	"github.com/OJ/gobuster/v3/gobustervhost"
	"github.com/OJ/gobuster/v3/libgobuster"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// Virtual host discovery, in this process.
//
// The same library and the same wordlist machinery as content
// discovery next door -- gobustervhost is gobusterdir's sibling in a
// module this agent already builds against, so this adds no
// dependency and no second binary.
//
// # What it answers that nothing else here does
//
// Every other web task asks one server what paths it has. This asks
// one ADDRESS what servers it has. On a shared IP, and behind every
// CDN and reverse proxy, the response depends on the Host header and
// the default vhost is frequently a holding page with nothing behind
// it. An estate can have an entire application reachable only by
// asking for it by name -- same address, same port, same TLS, and
// invisible to a scan that only ever sends the name it already knew.
//
// # The false positive this is built around
//
// A wildcard vhost answers everything. Point one at an address and
// every word in the list "exists", which is thousands of findings
// and none of them real. gobuster's answer is to exclude by response
// length, and that only works if somebody measured the wildcard
// first. So this measures it: before the sweep, a name that cannot
// exist is requested, and if the server answers it at all, that
// length is excluded for the rest of the run and said out loud in
// the output. Without that step the common case is not a bad result,
// it is a result that is entirely noise.

// runVhost sweeps Host headers against one url.
func runVhost(ctx context.Context, args map[string]any, workDir string) Result {
	us := subjects(args, "url", "urls")
	if len(us) == 0 {
		return failed("vhost needs `targets` (or `url`)")
	}
	if len(us) > 1 {
		return failed(
			"vhost takes one url per task; got %d — queue one task each",
			len(us))
	}
	url := strings.TrimRight(us[0], "/")
	parsed, err := neturl.Parse(url)
	if err != nil || parsed.Host == "" {
		return failed("%q is not a usable url", url)
	}

	// The domain the words are appended to. Taken from the url unless
	// the caller names one, because the interesting case is exactly
	// when they differ: sweeping `*.acme.example` against an address
	// that answers to something else entirely is how a shared host is
	// found.
	domain := str(args, "domain")
	if domain == "" {
		domain = strings.Split(parsed.Host, ":")[0]
	}

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

	// Measure the wildcard before sweeping. See the note above: this
	// is the step that decides whether the output is findings or
	// noise.
	wildcard := probeWildcard(ctx, url, domain, args)

	opts := gobustervhost.NewOptions()
	*opts = gobustervhost.OptionsVhost{
		ExcludeLengthParsed: opts.ExcludeLengthParsed,
		ExcludeStatusParsed: opts.ExcludeStatusParsed,
		HTTPOptions: libgobuster.HTTPOptions{
			BasicHTTPOptions: libgobuster.BasicHTTPOptions{
				UserAgent: userAgent(args),
				Timeout:   time.Duration(intArg(args, "timeout_s", 10)) * time.Second,
				// As in gobuster.go: a client's estate, not a lab.
				NoTLSValidation: true,
			},
			URL: parsed,
			// NOT followed, unlike content discovery. A vhost that
			// redirects is itself the answer -- `intranet` sending a
			// 301 to an internal name is the finding, and following
			// it reports the destination's body instead.
			FollowRedirect: false,
			Method:         http.MethodGet,
			Username:       str(args, "username"),
			Password:       str(args, "password"),
			Cookies:        str(args, "cookies"),
		},
		Domain: domain,
		// The words are names under the domain, not whole hostnames.
		AppendDomain: true,
	}
	if wildcard.answers {
		opts.ExcludeLengthParsed.Add(int(wildcard.size))
	}

	logger := libgobuster.NewLogger(false)
	plugin, err := gobustervhost.New(global, opts, logger)
	if err != nil {
		return failed("vhost setup: %v", err)
	}
	g, err := libgobuster.NewGobuster(global, plugin, logger)
	if err != nil {
		return failed("vhost setup: %v", err)
	}

	// Drained in the background, for the reason gobuster.go gives:
	// the channels are unbuffered, so a reader that is not running
	// blocks the scan rather than merely losing output.
	found := make(chan gobustervhost.Result, 256)
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
				if res, ok2 := r.(gobustervhost.Result); ok2 {
					select {
					case found <- res:
					default:
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
			case <-ctx.Done():
				return
			}
		}
	}()

	runErr := g.Run(ctx)
	// Run closes ResultChan itself; closing it here too panics. See
	// the same note in gobuster.go, which a live test found.
	<-done
	close(found)
	close(errs)

	names := make([]string, 0, len(found))
	hits := make([]vhostHit, 0, len(found))
	for r := range found {
		n := strings.TrimSpace(r.Vhost)
		if n == "" {
			continue
		}
		h := vhostHit{Vhost: n, Status: r.StatusCode, Size: r.Size}
		if r.Header != nil {
			h.Server = r.Header.Get("Server")
			h.ContentType = r.Header.Get("Content-Type")
			h.Redirect = r.Header.Get("Location")
		}
		hits = append(hits, h)
		names = append(names, n)
	}
	sort.Strings(names)
	sort.Slice(hits, func(i, j int) bool { return hits[i].Vhost < hits[j].Vhost })

	var stderr []string
	for s := range errs {
		stderr = append(stderr, s)
	}
	if runErr != nil && len(names) == 0 {
		return failed("vhost: %v", runErr)
	}

	which := list
	if builtin {
		which = "built-in (SecLists common.txt)"
	}
	out := map[string]any{
		"url": url, "domain": domain, "wordlist": which,
		"found": names, "hits": hits,
	}
	sum := fmt.Sprintf("vhost: %d name(s) on %s", len(names), url)
	// Reported, not just acted on. An operator reading "0 found"
	// needs to know whether that was a clean result or a wildcard
	// that swallowed the run.
	if wildcard.answers {
		out["wildcard"] = map[string]any{
			"answers": true, "status": wildcard.status, "size": wildcard.size,
			"probe": wildcard.probe,
		}
		sum += fmt.Sprintf(" — wildcard answers %d at %d bytes, excluded",
			wildcard.status, wildcard.size)
	}
	return Result{
		Status: "done", Output: recon.JSON(out),
		Stderr:  tail(strings.Join(stderr, "\n"), 4000),
		Summary: sum,
	}
}

// vhostHit is one name the address answered to, and what it said.
type vhostHit struct {
	Vhost       string `json:"vhost"`
	Status      int    `json:"status,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Server      string `json:"server,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Redirect    string `json:"redirect,omitempty"`
}

type wildcardProbe struct {
	answers bool
	status  int
	size    int64
	probe   string
}

// probeWildcard asks for a name that cannot exist.
//
// A name nobody would register, under the domain being swept. If the
// server answers it with anything other than a refusal, it answers
// everything, and every result from the sweep that looks like this
// one is that same page rather than a discovered host.
//
// Failure here is not failure of the task: if the probe cannot be
// made, the sweep still runs and simply excludes nothing. Reporting
// "could not determine" is handled by the caller, which only claims a
// wildcard when one actually answered.
func probeWildcard(ctx context.Context, url, domain string,
	args map[string]any) wildcardProbe {
	name := "oddjob-no-such-vhost-7f3a1c." + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return wildcardProbe{}
	}
	req.Host = name
	req.Header.Set("User-Agent", userAgent(args))

	cl := &http.Client{
		Timeout: time.Duration(intArg(args, "timeout_s", 10)) * time.Second,
		// Not followed, so the length measured is this response's and
		// not the destination's -- the sweep is comparing against the
		// same thing.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: insecureTransport(),
	}
	resp, err := cl.Do(req)
	if err != nil {
		return wildcardProbe{}
	}
	defer func() { _ = resp.Body.Close() }()
	n, _ := discard(resp.Body)

	// A 400 or a 421 is the server refusing an unknown Host, which is
	// the correct behaviour and the opposite of a wildcard.
	if resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusMisdirectedRequest ||
		resp.StatusCode == http.StatusNotFound {
		return wildcardProbe{probe: name}
	}
	return wildcardProbe{answers: true, status: resp.StatusCode,
		size: n, probe: name}
}

// insecureTransport is the wildcard probe's client transport.
//
// Certificate validation off, for the reason gobuster.go gives for
// doing the same: certificates inside a client's estate are routinely
// self-signed, expired, or issued for a name other than the one being
// asked for -- and the last of those is guaranteed here, because the
// whole point of the probe is to send a Host header the certificate
// does not cover. Validating would fail every probe on every TLS
// service and silently disable the wildcard check exactly where it
// matters most.
//
// This transport is used for the probe only. It is not shared with
// anything that carries credentials.
func insecureTransport() *http.Transport {
	// Type-asserted with the comma-ok form rather than bare. The
	// bare form is a panic if anything in the process has replaced
	// http.DefaultTransport -- which is exactly the sort of thing a
	// library does on init -- and a scanner that panics on one task
	// takes the agent's whole run with it. A fresh Transport is a
	// fine answer when the default is not the one we expected.
	base, ok := http.DefaultTransport.(*http.Transport)
	var t *http.Transport
	if ok {
		t = base.Clone()
	} else {
		t = &http.Transport{}
	}
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: see above — the probe deliberately sends a Host the certificate cannot match
	return t
}

// discard reads a body to count it and keeps nothing.
//
// Bounded. The length is all that is wanted and a wildcard vhost can
// serve an arbitrarily large page; reading it whole to measure it
// would let a target decide how much memory this agent spends. Past
// the cap the exact size stops mattering anyway -- anything this big
// is not the short holding page a wildcard serves.
func discard(r io.Reader) (int64, error) {
	const cap = 1 << 20
	n, err := io.Copy(io.Discard, io.LimitReader(r, cap))
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}
