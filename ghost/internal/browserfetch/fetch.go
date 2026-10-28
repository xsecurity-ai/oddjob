package browserfetch

import (
	"context"
	"io"
	"net/http"
	"time"
)

// Result is one fetch and how it had to be made.
type Result struct {
	Status      int
	Header      http.Header
	Body        []byte
	ContentType string
	// Which WAF refused the FIRST attempt, or "". Kept even when the
	// retry then succeeded, because "this host is behind Cloudflare
	// and refuses a plain client" is worth recording -- it is the
	// difference between a quiet estate and one that is quietly
	// filtering us.
	BlockedBy string
	// True when the answer came from the browser handshake. An
	// operator reading a page that only arrived this way should
	// know it did.
	UsedBrowser bool
	// Still refused after the retry. The page is not evidence of
	// anything about the application.
	StillBlocked bool
}

// Fetcher gets a URL, and gets it again properly if the first
// answer was a bot filter rather than the site.
//
// Two clients, not one with a swapped transport: the plain one is
// what every request should use, and keeping it the default means
// the browser handshake is something that happens when a refusal
// says it is needed rather than a thing we always do. An engagement
// should look like what it is until looking like what it is stops
// the work.
type Fetcher struct {
	Plain   *http.Client
	Browser *http.Client
	// Longest body read, per attempt. Zero means 2 MiB.
	MaxBody int64
	// The User-Agent for the plain attempt -- the project's own,
	// normally, which is attributable on purpose.
	UserAgent string
	// Off entirely. A refusal is then recorded as a refusal and
	// nothing is retried, which is the right behaviour for an
	// engagement that has been told not to look like a browser.
	Disabled bool
}

func (f *Fetcher) maxBody() int64 {
	if f.MaxBody > 0 {
		return f.MaxBody
	}
	return 2 << 20
}

func (f *Fetcher) plain() *http.Client {
	if f.Plain != nil {
		return f.Plain
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (f *Fetcher) browser() *http.Client {
	if f.Browser != nil {
		return f.Browser
	}
	return Client(20*time.Second, true)
}

// Get fetches `url`, retrying through a browser handshake if the
// first answer was a bot filter.
//
// The retry is attempted ONLY when `Blocked` names a product. A
// plain 403 with nothing behind it is the server's answer and is
// returned as it stands -- asking again in a costume would turn a
// real access-control boundary into a second request at a client
// for no reason.
func (f *Fetcher) Get(ctx context.Context, url string) (*Result, error) {
	res, err := f.once(ctx, f.plain(), url, f.UserAgent, false)
	if err != nil {
		return nil, err
	}
	who := Blocked(res.Status, res.Header, res.Body)
	if who == "" || f.Disabled {
		res.BlockedBy = who
		// Recorded but not retried: `Disabled` means the operator
		// asked for the plain client, so `StillBlocked` is the
		// honest state rather than a failure of the retry.
		res.StillBlocked = who != ""
		return res, nil
	}

	// The UA has to change with the handshake. Sending the
	// project's tool-shaped User-Agent over a Chrome ClientHello is
	// a worse signal than either, and the retry would fail for a
	// reason that looks like the first failure.
	second, err := f.once(ctx, f.browser(), url, ChromeUA, true)
	if err != nil {
		// The first answer is still what we have, so this returns
		// it rather than the retry's error -- deliberately, and
		// not a swallowed failure: "Cloudflare refused us and the
		// retry did not connect" is a RESULT about the host, and
		// turning it into an error would discard the block page we
		// already hold and report the fetch as never having
		// happened.
		res.BlockedBy = who
		res.StillBlocked = true
		return res, nil //nolint:nilerr // the first response is the answer
	}
	second.BlockedBy = who
	second.UsedBrowser = true
	second.StillBlocked = Blocked(
		second.Status, second.Header, second.Body) != ""
	return second, nil
}

func (f *Fetcher) once(ctx context.Context, cl *http.Client, url, ua string,
	browser bool) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if browser {
		Headers(req.Header, ua)
	} else if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBody()))
	if err != nil {
		// What arrived before the read failed is still evidence,
		// and a truncated block page is still recognisably one.
		body = append([]byte(nil), body...)
	}
	return &Result{
		Status:      resp.StatusCode,
		Header:      resp.Header,
		Body:        body,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}
