// Package client is the outbound half: a Ghost talking to Oddjob.
package client

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/identity"
)

type Client struct {
	base string
	key  string
	id   *identity.Identity
	http *http.Client
}

// UseIdentity switches this client from presenting a bearer key to
// signing each request. Once set, the key is not sent at all: the
// server refuses a key from an agent that has an identity, and sending
// both would only mean leaking the weaker secret onto the wire twice a
// minute for no benefit.
func (c *Client) UseIdentity(id *identity.Identity) { c.id = id }

func New(base, key string, insecure bool) *Client {
	// Cloned from the default so the agent inherits HTTP_PROXY, the
	// connection pool sizes and the timeouts Go tunes, rather than the
	// zero value's none-of-that.
	//
	// Comma-ok, not a bare assertion. http.DefaultTransport is a
	// package-level RoundTripper any imported library can replace with
	// a wrapper of its own; a bare assertion would then panic inside
	// New(), which runs before the agent has logged a single line, on a
	// host nobody is watching. Proxy support is the one default worth
	// carrying by hand into the fallback — a Ghost on an engagement
	// network frequently has no route out except the client's proxy.
	tr, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		tr = tr.Clone()
	} else {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	if insecure {
		// Opt-in, and never the default. Worth being precise about what
		// it does and does not give up: the body is sealed end-to-end
		// under a key only this agent and its Oddjob hold, and the
		// server is authenticated by a pinned Ed25519 identity, so
		// skipping certificate verification costs the transport's
		// opinion of who the peer is — not the agent's.
		//
		// MinVersion is set explicitly because replacing TLSClientConfig
		// discards whatever the cloned default transport had. Go's own
		// client default is already 1.2; writing it down means a future
		// edit to this struct cannot silently allow 1.0.
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 — opt-in, see config
			MinVersion:         tls.VersionTLS12,
		}
	}
	return &Client{
		base: strings.TrimRight(base, "/"),
		key:  key,
		// No global timeout: a result POST can carry tens of megabytes
		// of scan XML over a slow link, and cutting that off turns a
		// finished scan into a lost one. Per-call contexts bound the
		// short requests instead.
		http: &http.Client{Transport: tr},
	}
}

// RegisterReq is what this agent tells the server about itself.
type RegisterReq struct {
	//: runtime.GOOS: what this binary is. Correct for choosing a
	//: binary or an install snippet, and the wrong answer to "which
	//: machine is the Windows one" — see HostPlatform.
	Platform   string            `json:"platform"`
	Arch       string            `json:"arch"`
	Version    string            `json:"version"`
	Hostname   string            `json:"hostname"`
	Privileged bool              `json:"privileged"`
	Tools      map[string]string `json:"tools"`
	//: Tools this host could not get, and why. The server uses it to
	//: stop sending work that needs them — a task that fails for a
	//: missing tool costs three dispatches and tells the operator
	//: nothing they can act on.
	MissingTools map[string]string `json:"missing_tools,omitempty"`
	CallInURL    string            `json:"call_in_url,omitempty"`
	//: What the agent sees of itself. The server only ever sees the
	//: last hop the connection came from, which behind NAT or a
	//: tunnel is not the agent at all.
	OutboundIP string `json:"outbound_ip,omitempty"`
	//: How OutboundIP was arrived at: an external service, the local
	//: routing table, or a container's private namespace. Sent because
	//: the three are not interchangeable and the number alone cannot
	//: be told apart — a container address used to arrive here looking
	//: exactly like an egress address.
	OutboundIPSource string `json:"outbound_ip_source,omitempty"`
	//: What qualifies it: which lookup failed, what the address is
	//: not. Prose, for a tooltip rather than a column.
	OutboundIPNote string   `json:"outbound_ip_note,omitempty"`
	Interfaces     []string `json:"interfaces,omitempty"`
	//: The OS of the machine underneath, where that differs from
	//: Platform: a Linux container on WSL2 on Windows Server reports
	//: platform=linux, host_platform=windows. Empty when it could not
	//: be determined, which is deliberately distinct from "linux".
	HostPlatform string `json:"host_platform,omitempty"`
	//: The evidence for HostPlatform, so the claim can be checked.
	HostPlatformSource string `json:"host_platform_source,omitempty"`
	//: The container runtime this agent is inside, empty if none was
	//: detected. Absence of a marker is not proof of absence of a
	//: container.
	Container string `json:"container,omitempty"`
}

type RegisterResp struct {
	OK          bool     `json:"ok"`
	AgentID     int      `json:"agent_id"`
	Project     string   `json:"project"`
	Installable []string `json:"installable"`
	TaskKinds   []string `json:"task_kinds"`
	Note        string   `json:"note"`
}

type Task struct {
	ID   int             `json:"id"`
	Kind string          `json:"kind"`
	Args json.RawMessage `json:"args"`
}

// HTTPError is a reply the server refused with.
//
// A typed error rather than a formatted string because one caller has
// to make a decision on the code: a spooled result whose task the
// server has never heard of will never be accepted, and retrying it
// every heartbeat forever is the behaviour this replaces. Everything
// else just prints it, and it prints the same as before.
type HTTPError struct {
	Method string
	Path   string
	Code   int
	Status string
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: %s: %s", e.Method, e.Path, e.Status, e.Body)
}

type HeartbeatResp struct {
	OK bool `json:"ok"`
	// Task is the first of Tasks, kept so an agent reading only this
	// field still gets work from a server that hands out several.
	Task  *Task  `json:"task"`
	Tasks []Task `json:"tasks"`
	//: Set when the agent has been killed from Oddjob. It is answered
	//: rather than refused so it can stop, instead of retrying forever
	//: against a 403 it cannot interpret.
	Shutdown bool   `json:"shutdown"`
	Reason   string `json:"reason"`
	//: What Oddjob says this agent may run at once: the operator's
	//: per-ghost number if they set one, the agent's own assessment
	//: otherwise, with the engagement's ceiling applied on top. Zero
	//: or absent from an older server means "no opinion", which is
	//: not the same as "run nothing" and must not be read as it.
	MaxParallel int `json:"max_parallel"`
}

// EnrollReq trades a one-time token for an identity.
type EnrollReq struct {
	EnrollToken  string `json:"enroll_token"`
	PublicKey    string `json:"public_key"`
	KexPublicKey string `json:"kex_public_key,omitempty"`
}

type EnrollResp struct {
	OK                 bool   `json:"ok"`
	AgentID            int    `json:"agent_id"`
	Project            string `json:"project"`
	ServerPublicKey    string `json:"server_public_key"`
	ServerKexPublicKey string `json:"server_kex_public_key"`
	//: The server confirming it recorded our key-agreement half. If
	//: this is false the channel cannot be sealed, and the agent
	//: refuses rather than reporting scans in the clear.
	Sealing        bool   `json:"sealing"`
	ConnectionMode string `json:"connection_mode"`
}

// Enroll runs before there is any identity, so it is the one call that
// carries no credential but the token itself.
func (c *Client) Enroll(ctx context.Context, token, pub, kexPub string) (*EnrollResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out EnrollResp
	err := c.do(ctx, "POST", "/api/ghosts/enroll",
		EnrollReq{EnrollToken: token, PublicKey: pub, KexPublicKey: kexPub}, &out)
	return &out, err
}

type Result struct {
	Status   string `json:"status"` // done | failed
	Output   string `json:"output,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Summary  string `json:"summary,omitempty"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// newNonce mirrors the identity package's: 128 bits, used once.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (c *Client) do(ctx context.Context, method, path string,
	body any, out any) error {

	var raw []byte
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding %s: %w", path, err)
		}
		raw, rdr = b, bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return err
	}
	var sealKey []byte
	if c.id != nil {
		// Sealed first, then signed, so the signature covers exactly
		// what goes on the wire. The headers carry the timestamp and
		// nonce the binding needs, so they are minted here and reused
		// for both.
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := newNonce()

		if c.id.CanSeal() {
			k, err := c.id.SealKey()
			if err != nil {
				return fmt.Errorf("deriving the seal key: %w", err)
			}
			sealKey = k
			env, err := identity.Seal(k, raw, identity.ChannelBinding(
				"req", c.id.AgentID, method, path, ts, nonce))
			if err != nil {
				// Refused rather than sent in the clear. An agent that
				// cannot seal is an agent that stops talking, not one
				// that quietly downgrades.
				return fmt.Errorf("sealing %s: %w", path, err)
			}
			raw = []byte(env)
			rdr = bytes.NewReader(raw)
			req.Body = io.NopCloser(rdr)
			req.ContentLength = int64(len(raw))
			req.Header.Set(identity.SealedHeader, identity.SealVersion)
		}

		for k, v := range c.id.SignAt(method, path, raw, ts, nonce) {
			req.Header.Set(k, v)
		}
	} else {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Ghost (authorised security assessment)")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// A sealed reply has to be opened before anything can be said
	// about it, including whether it is an error.
	if resp.Header.Get(identity.SealedHeader) != "" && sealKey != nil {
		// Read back from the REQUEST, which this client set, so the
		// binding uses the same values the signature did.
		ts := req.Header.Get("X-Ghost-Timestamp")
		nonce := req.Header.Get("X-Ghost-Nonce")
		opened, err := identity.Unseal(sealKey, string(payload),
			identity.ChannelBinding("res", c.id.AgentID, method, path, ts, nonce))
		if err != nil {
			return fmt.Errorf("%s %s: the reply did not open (%w) — it was "+
				"not sealed by the Oddjob this agent enrolled with", method,
				path, err)
		}
		payload = opened
	}

	if resp.StatusCode >= 300 {
		// Carry the server's own message. "401" alone sends people
		// hunting through firewall rules when the answer is that the
		// key was revoked.
		snippet := payload
		if len(snippet) > 600 {
			snippet = snippet[:600]
		}
		return &HTTPError{
			Method: method, Path: path, Code: resp.StatusCode,
			Status: resp.Status, Body: strings.TrimSpace(string(snippet)),
		}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(payload, out)
}

// Register tells the server what this agent is. Idempotent.
func (c *Client) Register(ctx context.Context, r RegisterReq) (*RegisterResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out RegisterResp
	if err := c.do(ctx, http.MethodPost, "/api/ghosts/register", r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HeartbeatReq is what the agent says about itself when it checks in.
//
// It beats while it is WORKING as well as while it is idle — a scan can
// run for the better part of an hour, and an agent that goes quiet for
// that long is indistinguishable from one that died. So the beat cannot
// also mean "give me work": readiness is stated here instead.
type HeartbeatReq struct {
	// Ready is false at capacity. The server holds the queue until it
	// is true, so nothing is handed to an agent with nothing free.
	Ready bool `json:"ready"`
	// RunningTask is the first of RunningTasks, for servers that
	// predate running several at once.
	RunningTask int `json:"running_task,omitempty"`
	// RunningTasks is everything in flight. The server trusts this
	// over its own record: the agent is the only side that can be
	// sure, and it is what tells "still going" from "died and came
	// back" — the same silence from outside.
	RunningTasks []int `json:"running_tasks"`
	// SlotsFree is how many more it will take right now.
	SlotsFree int `json:"slots_free"`
	// Capacity is what it decided this host can run at once, and why.
	// Sent every beat because it is re-derived as load changes.
	Capacity       int    `json:"capacity"`
	CapacityReason string `json:"capacity_reason,omitempty"`
}

func (c *Client) Heartbeat(ctx context.Context, req HeartbeatReq) (*HeartbeatResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out HeartbeatResp
	if err := c.do(ctx, http.MethodPost, "/api/ghosts/heartbeat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) StartTask(ctx context.Context, id int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/ghosts/tasks/%d/start", id), nil, nil)
}

// SubmitResult sends the output home, retrying because the scan has
// already happened: throwing the result away over one bad minute of
// network would mean running it again against the client's estate.
func (c *Client) SubmitResult(ctx context.Context, id int, r Result) error {
	path := fmt.Sprintf("/api/ghosts/tasks/%d/result", id)
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		err := c.do(rctx, http.MethodPost, path, r, nil)
		cancel()
		if err == nil {
			return nil
		}
		last = err
		// A refusal is final; only transport trouble is worth retrying.
		if strings.Contains(err.Error(), "400 ") ||
			strings.Contains(err.Error(), "401 ") ||
			strings.Contains(err.Error(), "403 ") ||
			strings.Contains(err.Error(), "404 ") ||
			strings.Contains(err.Error(), "422 ") {
			return err
		}
	}
	return fmt.Errorf("after 5 attempts: %w", last)
}

// RetiredReq is a Ghost's last message: it has stopped, and this is
// what it took with it.
type RetiredReq struct {
	Reason string `json:"reason"`
	// Tools uninstalled, tools left because they were already on the
	// host, and tools we could not remove. The third list is the one
	// that matters: it is the cleanup somebody still has to do by hand.
	Removed []string `json:"removed,omitempty"`
	Kept    []string `json:"kept,omitempty"`
	Failed  []string `json:"failed,omitempty"`
}

// Retired tells Oddjob this Ghost has shut down for good.
//
// Best effort and short: it is sent while retiring, and a Ghost that
// hung here would be one that failed to clean up because it could not
// file a report about cleaning up. One attempt, then carry on.
func (c *Client) Retired(ctx context.Context, reason string,
	removed, kept, failed []string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return c.do(ctx, http.MethodPost, "/api/ghosts/retired",
		RetiredReq{Reason: reason, Removed: removed, Kept: kept,
			Failed: failed}, nil)
}
