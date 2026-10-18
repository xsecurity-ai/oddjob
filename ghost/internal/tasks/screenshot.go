package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	neturl "net/url"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// A picture of the page, taken by a real browser, in this process.
//
// # What it answers that nothing else here does
//
// Every other web task reports what a page SAID: a status, a title, a
// server header, a body. None of them report what it LOOKS LIKE, and
// on an estate of tens of thousands of URLs that is the question an
// operator actually has to answer first -- which of these is a parked
// holding page, which is a vendor's default install, which is a login
// form worth an hour. A 200 with the title "Dashboard" is a login
// portal, a logged-in admin console or a React shell that rendered an
// error, and the title cannot tell them apart. A screenshot can, in
// the time it takes to look at it.
//
// It is also the artefact a report wants. "The admin console was
// reachable without authentication" is a sentence; the screenshot is
// the evidence, and taking it later by hand means going back to a
// client's estate for something we were already standing in front of.
//
// # Why this runs on the ghost and not on Oddjob
//
// The same reason every other scanner does. The ghost is INSIDE the
// engagement: its egress address is the one the client authorised,
// its requests cross the same path the rest of the assessment crossed,
// and an application that shows one thing to the internet and another
// to an internal range would be photographed from the wrong side if
// Oddjob took the picture itself. The scope gate, the rules of
// engagement and the measured capacity system all live on this path
// too; a screenshotter bolted onto the server would have none of them.
//
// # What a headless browser is, in rules-of-engagement terms
//
// It EXECUTES the page. Fetching a URL and rendering it are not the
// same act: the renderer runs the site's JavaScript, which fires
// analytics, opens WebSockets, posts to whatever the page posts to on
// load, and follows whatever the script decides to follow. A crawl is
// classified `state_changing` in backend/app/roe.py because a link
// can be `/logout`; this does everything a link can do and then runs
// the author's code as well. It is classified the same way and for a
// stronger reason -- see the entry there.
//
// # Chromium's sandbox, and why --no-sandbox is passed
//
// Chromium confines its renderer with a user-namespace sandbox, or
// with a setuid helper where namespaces are unavailable. Neither can
// be built in the container this agent ships in, for two independent
// reasons:
//
//   - The container runs as uid 0 (see ghost/Dockerfile: file
//     capabilities are not honoured through a Docker exec, so nmap
//     and masscan need container root to have CAP_NET_RAW at all).
//     Chromium refuses outright to start as root with the sandbox on
//     -- "Running as root without --no-sandbox is not supported".
//   - The container is run with `--cap-drop=ALL`, and Docker's
//     default seccomp profile only permits `clone` with
//     CLONE_NEWUSER when CAP_SYS_ADMIN is in the bounding set. So
//     even as a non-root user the namespace sandbox cannot be
//     created: chromium aborts with "Failed to move to new
//     namespace".
//
// Verified rather than assumed: with the sandbox left on, chromium in
// this image exits non-zero and writes no file at all.
//
// So the flag is not a convenience, and it is not free either. What
// it costs: a renderer compromise -- a hostile page exploiting the
// browser -- is no longer confined to the renderer process; it lands
// in the container. What is left standing between that and the host
// is the container itself, which drops every capability but two, runs
// no service, and holds only this agent's spool and identity. The
// alternative is granting CAP_SYS_ADMIN, which is a strictly larger
// grant than the one being avoided. Worth knowing, not worth hiding.
//
// # Memory
//
// Chromium is by a wide margin the heaviest thing a ghost runs, which
// is why `screenshot` is a kind in capacity.kindMemMB rather than one
// of the unconstrained light tools -- a 458 MB droplet in this fleet
// must not be handed a browser. The measurement and the figure are in
// internal/capacity/afford.go.

// How many pages one task will photograph.
//
// Bounded because the result is carried home in one JSON document
// that the agent holds in memory and encodes before posting, which
// transiently doubles it -- the same constraint katana.go sizes its
// body budget against, with a heavier payload. A whole estate is
// photographed by queueing many tasks, not by one enormous one.
const (
	defaultPages = 20
	maxPages     = 50
)

// Per-image and per-task size caps, in bytes.
//
// A viewport capture of a 1280x800 page is typically 60-400 KB of
// PNG. The per-image cap is therefore not a routine limit, it is the
// guard against the page that is nothing but a full-bleed photograph:
// past it the image is DROPPED and its size reported, because a
// truncated PNG is not a smaller picture, it is a corrupt file that
// renders as nothing and says so to nobody.
const (
	defaultMaxBytes = 3 << 20  // one image
	defaultBudget   = 24 << 20 // all images in one task
)

// How long one page gets, end to end, and how long to let it settle
// after the load event before the shutter.
//
// The settle delay is the difference between photographing a
// single-page application and photographing its empty shell: the
// document is "loaded" long before the framework has drawn anything.
const (
	defaultPageTimeout = 25 * time.Second
	defaultSettleMs    = 1500
)

// The browser binary names this agent will drive, in the order they
// are tried.
//
// chromedp has its own list, but its fallback when nothing matches is
// to return "google-chrome" and let the exec fail -- which reports a
// missing browser as "fork/exec google-chrome: no such file or
// directory" from inside a library, several frames from anything an
// operator can act on. Asking first means the answer can be "absent",
// said plainly, with the names that were tried.
var browserNames = []string{
	// Chromium's headless-only build, where a distribution ships one:
	// the same engine with none of the UI, and the cheapest of these
	// by some margin.
	"headless_shell", "headless-shell",
	"chromium", "chromium-browser",
	"google-chrome", "google-chrome-stable", "chrome",
	// macOS puts neither on PATH. A ghost does run there -- see
	// internal/tools/priv.go, which has a whole darwin branch -- and
	// without these it would report "no browser" on a laptop with
	// Chrome open in front of the operator.
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
}

// browserPath is the browser on this host, or "" if there is none.
func browserPath(args map[string]any) (string, string) {
	if p := str(args, "browser"); p != "" {
		// An operator naming one wins. Still resolved through
		// LookPath so a bare name works, and still reported back, so
		// "which browser took this" is answerable from the result.
		if full, err := exec.LookPath(p); err == nil {
			return full, p
		}
		return "", p
	}
	for _, n := range browserNames {
		if full, err := exec.LookPath(n); err == nil {
			return full, n
		}
	}
	return "", ""
}

// Unsupported lists the task kinds this host lacks a PREREQUISITE
// for, as distinct from the ones it lacks the memory for.
//
// Reported on the heartbeat alongside capacity's own answer, and for
// the same reason: the server skips the kind when choosing work for
// this agent, instead of handing over a task it will immediately
// give back. Handing it back is a livelock -- the task returns to the
// pool, the same ghost takes it again, and the queue spins on it.
//
// Only the browser, today. The other tools are either linked into
// this binary or installable, and `tools.Known` already answers for
// those; a browser is neither. It is several hundred megabytes and
// putting one on a host inside a client's estate is a decision for
// whoever built that host, not for a task.
func Unsupported() []string {
	if exe, _ := browserPath(nil); exe == "" {
		return []string{"screenshot"}
	}
	return nil
}

// shot is one page photographed, and what the browser knew about it.
type shot struct {
	URL string `json:"url"`
	// Where the browser ended up. Different from `url` whenever the
	// page redirected, and that difference is frequently the finding
	// -- an admin console that bounces to an SSO host is a different
	// answer from one that serves a login form itself.
	FinalURL string `json:"final_url,omitempty"`
	// The main document's status. Absent (0) means the browser never
	// reported one, which is "could not determine" and not 200: a
	// page served from the back/forward cache, or a navigation that
	// ended in a browser error page, produces no response event.
	Status int    `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
	Server string `json:"server,omitempty"`
	// The PAGE's media type, not the image's. Named so it cannot be
	// read as the latter: the image is always a PNG, and a field
	// called `content_type` sitting next to `png_base64` would be
	// taken for the PNG's by whoever reads this next.
	PageContentType string `json:"page_content_type,omitempty"`
	Width           int    `json:"width"`
	Height          int    `json:"height"`
	Bytes           int    `json:"bytes"`
	SHA256          string `json:"sha256"`
	// The PNG itself, base64. Base64 rather than raw bytes because
	// the result travels as a field in a JSON document and lands in
	// a text column on the way through: a PNG contains NUL bytes,
	// which Postgres rejects in text outright. The server decodes it
	// once and stores the bytes.
	PNG string `json:"png_base64"`
}

// miss is a page that was not photographed, and why.
//
// Carried in the result rather than dropped. "We photographed 18 of
// 20" with no account of the other two is the shape of answer this
// codebase keeps finding and fixing: absent and could-not-determine
// are different, and the operator is the one who has to decide which
// of the two they are looking at.
type miss struct {
	URL    string `json:"url"`
	Error  string `json:"error"`
	Bytes  int    `json:"bytes,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// runScreenshot photographs one or more URLs.
func runScreenshot(ctx context.Context, args map[string]any, _ string) Result {
	us := subjects(args, "url", "urls", "site", "sites")
	if len(us) == 0 {
		return failed("screenshot needs `targets` (or `url`)")
	}

	// http(s) only, checked here rather than left to the browser.
	// Chromium will open `file:///etc/shadow` and `chrome://net-internals`
	// perfectly happily, and a screenshot task is the one kind whose
	// whole output is a picture of whatever it was pointed at.
	// Nothing in this agent should be able to photograph the host it
	// is running on because a URL was spelled oddly.
	wanted := make([]string, 0, len(us))
	var refused []miss
	for _, u := range us {
		if !webURL(u) {
			refused = append(refused, miss{URL: u,
				Error: "not an http(s) URL; a browser would open it as a " +
					"local or internal page, which is not what this task is for"})
			continue
		}
		wanted = append(wanted, u)
	}
	if len(wanted) == 0 {
		return failed("screenshot needs http(s) URLs; none of the %d given "+
			"were", len(us))
	}

	limit := intOr(args, "max_pages", defaultPages)
	if limit > maxPages {
		limit = maxPages
	}
	// Everything the task ASKED for, including what was refused above
	// and what the page limit is about to cut. The summary counts
	// against this rather than against what was attempted, so
	// "7 of 9" is a statement about the request and the two missing
	// ones are always accounted for somewhere.
	queued := len(us)
	beyondLimit := 0
	if len(wanted) > limit {
		beyondLimit = len(wanted) - limit
		wanted = wanted[:limit]
	}

	exe, asked := browserPath(args)
	if exe == "" {
		// Not retried and not disguised. A ghost with no browser
		// cannot grow one: the image ships chromium, and installing
		// several hundred megabytes of browser onto a host inside a
		// client's estate is not something this agent does on its
		// own. See tools.Known, which deliberately has no entry.
		if asked != "" {
			return failed("screenshot: no browser named %q on this host", asked)
		}
		return failed("screenshot: no browser on this host (tried %s). "+
			"The ghost image ships chromium; a ghost installed by hand "+
			"needs it installed by hand too.",
			strings.Join(browserNames, ", "))
	}

	width := intOr(args, "width", 1280)
	height := intOr(args, "height", 800)
	maxBytes := intOr(args, "max_bytes", defaultMaxBytes)
	budget := intOr(args, "budget_bytes", defaultBudget)
	settle := time.Duration(intOr(args, "settle_ms", defaultSettleMs)) *
		time.Millisecond
	perPage := time.Duration(intOr(args, "page_timeout_s",
		int(defaultPageTimeout/time.Second))) * time.Second

	opts := []chromedp.ExecAllocatorOption{}
	opts = append(opts, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.ExecPath(exe),
		// Said on every request this browser makes, for the reason
		// every other task says it: an engagement's traffic should be
		// attributable from the client's own logs without anybody
		// having to ask us who it was.
		chromedp.UserAgent(userAgent(args)),
		// See the sandbox note at the top of this file. This is the
		// flag, and that is the reasoning.
		chromedp.NoSandbox,
		// /dev/shm is 64 MB in a default Docker container and
		// chromium will fill it and crash the renderer on a heavy
		// page. The flag moves those allocations to /tmp, which is
		// the container's own writable layer.
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.DisableGPU,
		// Certificates inside a client's estate are routinely
		// self-signed, expired, or issued for another name -- the
		// same reason gobuster.go and the vhost probe turn
		// validation off. A browser that refuses to render the
		// interstitial would photograph Chromium's warning page on
		// every internal host, which is a picture of our own browser
		// rather than of the client's estate.
		chromedp.IgnoreCertErrors,
	)
	// No `UserDataDir`, deliberately: left unset, chromedp makes a
	// fresh temporary profile per allocator and removes it when the
	// allocator is cancelled. That is exactly what is wanted here --
	// one engagement's cookies must not be in the browser the next
	// task uses -- and naming a directory would make the profile
	// persist instead.
	if p := str(args, "proxy"); p != "" {
		opts = append(opts, chromedp.ProxyServer(p))
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()

	// One browser for the whole task, a fresh TAB per page. Starting
	// chromium per URL would pay the ~100 MB process cost twenty
	// times over and take seconds each; sharing one tab would carry
	// each site's cookies and storage into the next picture.
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()
	if err := chromedp.Run(browserCtx); err != nil {
		return failed("screenshot: %s would not start: %v", exe, err)
	}

	var (
		shots   []shot
		missed  = refused
		spent   int
		skipped int
	)
	for _, u := range wanted {
		if spent >= budget {
			// Not an error about the page -- we never looked at it.
			// Said as its own count so "10 of 20" is explained.
			skipped++
			continue
		}
		s, err := capture(browserCtx, u, args, captureOpts{
			width: width, height: height, settle: settle, perPage: perPage,
		})
		if err != nil {
			missed = append(missed, miss{URL: u, Error: trimErr(err)})
			continue
		}
		if s.Bytes > maxBytes {
			// Dropped whole. A truncated PNG is a corrupt file, not
			// a smaller picture; reporting the size is the honest
			// answer and `max_bytes` is the knob.
			missed = append(missed, miss{URL: u, Bytes: s.Bytes,
				Error: fmt.Sprintf("the capture is %d bytes, past this "+
					"task's %d-byte limit", s.Bytes, maxBytes),
				Reason: "too_large"})
			continue
		}
		spent += s.Bytes
		shots = append(shots, s)
	}

	out := map[string]any{
		"shots":    shots,
		"failed":   missed,
		"browser":  exe,
		"viewport": map[string]int{"width": width, "height": height},
		"bytes":    spent,
	}
	if skipped > 0 {
		out["skipped_over_budget"] = skipped
	}
	if beyondLimit > 0 {
		out["beyond_page_limit"] = beyondLimit
	}

	sum := fmt.Sprintf("screenshot: %d of %d page(s) captured, %.1f MB",
		len(shots), queued, float64(spent)/(1<<20))
	if len(missed) > 0 {
		sum += fmt.Sprintf("; %d could not be", len(missed))
	}
	if skipped > 0 {
		sum += fmt.Sprintf("; %d not attempted (past the %d MB budget)",
			skipped, budget>>20)
	}
	if beyondLimit > 0 {
		sum += fmt.Sprintf("; %d beyond the %d-page limit",
			beyondLimit, limit)
	}
	// A task that photographed nothing at all has failed, even though
	// every individual page merely "did not load". The operator asked
	// for pictures and got none; reporting that as done would put a
	// green row in the queue for a task with no result in it.
	if len(shots) == 0 {
		return Result{
			Status: "failed", Output: recon.JSON(out), Summary: sum,
			Error:    "no page could be photographed",
			ExitCode: -1,
		}
	}
	return Result{Status: "done", Output: recon.JSON(out), Summary: sum}
}

type captureOpts struct {
	width, height int
	settle        time.Duration
	perPage       time.Duration
}

// capture photographs one URL in its own tab.
func capture(parent context.Context, url string, args map[string]any,
	o captureOpts) (shot, error) {

	tabCtx, cancelTab := chromedp.NewContext(parent)
	// Closes the tab, and with it the renderer process and everything
	// that page allocated. Deferred per page rather than per task:
	// twenty tabs left open is twenty renderers resident, which is
	// the whole memory budget spent on pages nobody is looking at any
	// more.
	defer cancelTab()

	ctx, cancel := context.WithTimeout(tabCtx, o.perPage)
	defer cancel()

	// The main document's response, caught as it arrives.
	//
	// A browser does not hand back a status code: it renders. So the
	// network event is the only place the status, the content type
	// and the Server header exist, and without them a screenshot of
	// an error page is indistinguishable from a screenshot of a site.
	//
	// The FIRST document response only. Sub-frames are documents too,
	// and an ad iframe's 204 is not this page's answer.
	var (
		mu     sync.Mutex
		status int
		server string
		ctype  string
	)
	chromedp.ListenTarget(ctx, func(ev any) {
		e, ok := ev.(*network.EventResponseReceived)
		if !ok || e.Response == nil || e.Type != network.ResourceTypeDocument {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if status != 0 {
			return
		}
		status = int(e.Response.Status)
		ctype = e.Response.MimeType
		// Matched without regard to case, and by walking the map
		// rather than looking up two spellings. DevTools hands back
		// the header as the wire had it: HTTP/2 lower-cases, HTTP/1.1
		// does not, and a server is free to send `SERVER`. Asking for
		// one spelling reports "no server header" about a response
		// that had one, which is the absent/could-not-determine
		// substitution this codebase treats as a bug.
		for k, v := range e.Response.Headers {
			if strings.EqualFold(k, "server") {
				server = fmt.Sprint(v)
				break
			}
		}
	})

	var (
		png      []byte
		title    string
		finalURL string
	)
	acts := []chromedp.Action{
		network.Enable(),
	}
	if h := extraHeaders(args); len(h) > 0 {
		// Credentials from the project's own store, for the same
		// reason katana takes them: a screenshot of a login page is
		// a picture of the front door, and most of an application is
		// behind it. They are never logged and never appear in the
		// result.
		acts = append(acts, network.SetExtraHTTPHeaders(h))
	}
	acts = append(acts,
		chromedp.EmulateViewport(int64(o.width), int64(o.height)),
		chromedp.Navigate(url),
		// Not WaitVisible on a selector: there is no selector that is
		// true of every page, and a page that never shows it would
		// burn the whole per-page timeout and then produce nothing.
		// A fixed settle is a worse answer on a fast site and a far
		// better one on a slow or broken one.
		chromedp.Sleep(o.settle),
		chromedp.Location(&finalURL),
		chromedp.Title(&title),
		chromedp.CaptureScreenshot(&png),
	)
	if err := chromedp.Run(ctx, acts...); err != nil {
		return shot{}, err
	}
	if len(png) == 0 {
		return shot{}, fmt.Errorf("the browser returned no image")
	}

	sum := sha256.Sum256(png)
	mu.Lock()
	defer mu.Unlock()
	return shot{
		URL: url, FinalURL: finalURL, Status: status,
		Title:  trunc(strings.TrimSpace(title), 400),
		Server: trunc(server, 255), PageContentType: trunc(ctype, 128),
		Width: o.width, Height: o.height,
		Bytes:  len(png),
		SHA256: hex.EncodeToString(sum[:]),
		PNG:    base64.StdEncoding.EncodeToString(png),
	}, nil
}

// extraHeaders are the request headers this task should add.
//
// The User-Agent is NOT here: it is set on the browser itself, where
// it also reaches the navigator object the page can read. Setting it
// twice would be two sources of truth for the same header.
func extraHeaders(args map[string]any) network.Headers {
	out := network.Headers{}
	for _, h := range stringsArg(args, "headers") {
		name, value, found := strings.Cut(h, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !found || name == "" || strings.EqualFold(name, "user-agent") {
			continue
		}
		out[name] = value
	}
	if c := str(args, "cookies"); c != "" {
		out["Cookie"] = c
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// webURL reports whether this is something a web browser should be
// pointed at on an engagement. See the note at the call site.
func webURL(u string) bool {
	p, err := neturl.Parse(strings.TrimSpace(u))
	if err != nil || p.Host == "" {
		return false
	}
	switch strings.ToLower(p.Scheme) {
	case "http", "https":
		return true
	}
	return false
}

// trimErr keeps an error readable in a result row.
//
// chromedp wraps the DevTools protocol, and a navigation failure
// arrives with the stack of the library that noticed it. The first
// line is the part that says what happened to the page.
func trimErr(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	return trunc(s, 300)
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
