// Package client is the outbound half: Jaws talking to Oddjob.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	OK   bool  `json:"ok"`
	Task *Task `json:"task"`
	//: Set when the agent has been killed from Oddjob. It is answered
	//: rather than refused so it can stop, instead of retrying forever
	//: against a 403 it cannot interpret.
	Shutdown bool   `json:"shutdown"`
	Reason   string `json:"reason"`
}

// EnrolReq trades a one-time token for an identity.
type EnrolReq struct {
	EnrolToken string `json:"enrol_token"`
	PublicKey  string `json:"public_key"`
}

type EnrolResp struct {
	OK              bool   `json:"ok"`
	AgentID         int    `json:"agent_id"`
	Project         string `json:"project"`
	ServerPublicKey string `json:"server_public_key"`
	ConnectionMode  string `json:"connection_mode"`
}

// Enrol runs before there is any identity, so it is the one call that
// carries no credential but the token itself.
func (c *Client) Enrol(ctx context.Context, token, pub string) (*EnrolResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out EnrolResp
	err := c.do(ctx, "POST", "/api/agents/enrol",
		EnrolReq{EnrolToken: token, PublicKey: pub}, &out)
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
	if c.id != nil {
		// Signed over exactly these bytes. Anything that rewrites the
		// body after this point breaks the signature, which is why the
		// marshalled form is reused rather than re-encoded.
		for k, v := range c.id.Sign(method, path, raw) {
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

	if resp.StatusCode >= 300 {
		// Carry the server's own message. "401" alone sends people
		// hunting through firewall rules when the answer is that the
		// key was revoked.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 600))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status,
			strings.TrimSpace(string(snippet)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
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

func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatResp, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out HeartbeatResp
	if err := c.do(ctx, http.MethodPost, "/api/agents/heartbeat", nil, &out); err != nil {
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
