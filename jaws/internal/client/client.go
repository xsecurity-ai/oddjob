// Package client is the outbound half: Jaws talking to Oddjob.
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

	"github.com/xsecurity-ai/oddjob/jaws/internal/identity"
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
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 — opt-in, see config
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

// Register tells the server what this agent is. Idempotent.
type RegisterReq struct {
	Platform   string            `json:"platform"`
	Arch       string            `json:"arch"`
	Version    string            `json:"version"`
	Hostname   string            `json:"hostname"`
	Privileged bool              `json:"privileged"`
	Tools      map[string]string `json:"tools"`
	CallInURL  string            `json:"call_in_url,omitempty"`
	//: What the agent sees of itself. The server only ever sees the
	//: last hop the connection came from, which behind NAT or a
	//: tunnel is not the agent at all.
	OutboundIP string   `json:"outbound_ip,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
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
	err := c.do(ctx, "POST", "/api/agents/enroll",
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
	req.Header.Set("User-Agent", "Jaws (authorised security assessment)")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	// A sealed reply has to be opened before anything can be said
	// about it, including whether it is an error.
	if resp.Header.Get(identity.SealedHeader) != "" && sealKey != nil {
		ts := req.Header.Get("X-Jaws-Timestamp")
		nonce := req.Header.Get("X-Jaws-Nonce")
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
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status,
			strings.TrimSpace(string(snippet)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(payload, out)
}

func (c *Client) Register(ctx context.Context, r RegisterReq) (*RegisterResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out RegisterResp
	if err := c.do(ctx, http.MethodPost, "/api/agents/register", r, &out); err != nil {
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
	if err := c.do(ctx, http.MethodPost, "/api/agents/heartbeat", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) StartTask(ctx context.Context, id int) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/api/agents/tasks/%d/start", id), nil, nil)
}

// SubmitResult sends the output home, retrying because the scan has
// already happened: throwing the result away over one bad minute of
// network would mean running it again against the client's estate.
func (c *Client) SubmitResult(ctx context.Context, id int, r Result) error {
	path := fmt.Sprintf("/api/agents/tasks/%d/result", id)
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
