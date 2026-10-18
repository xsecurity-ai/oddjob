package tasks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// One operator-edited HTTP request, put on the wire from inside the
// client's estate.
//
// # Why this is a task at all
//
// Oddjob used to send a replayed request from the server, with an HTTP
// client, out of the server's own egress address. For an engagement
// that is the wrong address: the client authorised and allowlisted the
// ghost's, the traffic has to be attributable to the test, and on an
// internal engagement the server cannot reach the target at all.
//
// # Exactly as written
//
// The request arrives base64-encoded and is written to the socket
// unchanged. Nothing here parses it, and nothing here rebuilds it from
// parsed fields, because every interesting replay is a request that a
// parser would correct:
//
//	a header order that differs from the browser's
//	`content-length` in lower case, or twice
//	two Host headers
//	`GET /x HTTP/1.1` with the space in the wrong place, or no version
//	a Content-Length that deliberately disagrees with the body
//
// Go's net/http would fix or refuse every one of those, which is why
// this opens a net.Conn and does the writing itself. The RESPONSE is
// different: the raw bytes are captured for the record, and the stdlib
// reader is used only to know where the response ENDS, so that the
// task does not sit on the socket until the timeout for every reply.
//
// # What decides the destination
//
// `host` and `port`, which the server reads out of the target row
// after checking it against the engagement's scope. Not the Host
// header, which travels as bytes like everything else. That separation
// is deliberate: it is what makes a Host-header test possible without
// the header being able to move where the packet goes.

// Capped at 1 MiB regardless of what the server asks for. The response
// cap keeps a hostile or merely enormous reply from being read into
// this agent's memory in full -- the ghost runs on hosts as small as
// 458 MB, and the stored column is tens of kilobytes anyway.
const replayHardCap = 1 << 20

// runReplay sends one raw request and brings back one raw response.
func runReplay(ctx context.Context, args map[string]any, _ string) Result {
	rawB64 := str(args, "raw_b64")
	if rawB64 == "" {
		return failed("replay needs `raw_b64`: the request, base64-encoded")
	}
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return failed("replay: `raw_b64` is not valid base64: %v", err)
	}
	host := str(args, "host")
	if host == "" {
		return failed("replay needs `host`: where to send it")
	}
	port := intArg(args, "port", 0)
	scheme := strings.ToLower(str(args, "scheme"))
	if scheme == "" {
		scheme = "http"
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	sni := str(args, "sni")
	if sni == "" {
		sni = host
	}
	timeout := time.Duration(intArg(args, "timeout_s", 20)) * time.Second
	respCap := intArg(args, "resp_cap", 48*1024)
	if respCap <= 0 || respCap > replayHardCap {
		respCap = replayHardCap
	}

	status, body, elapsed, sendErr := sendRaw(ctx, rawDest{
		host: host, port: port, tls: scheme == "https", sni: sni,
		verify:  boolArg(args, "verify_tls", false),
		timeout: timeout, cap: respCap,
	}, raw)

	out := map[string]any{
		"elapsed_ms":    elapsed.Milliseconds(),
		"response_b64":  base64.StdEncoding.EncodeToString(body),
		"response_size": len(body),
	}
	if status > 0 {
		out["status"] = status
	}
	sum := fmt.Sprintf("replay: %s:%d", host, port)
	if sendErr != nil {
		// Reported as a RESULT, not as a failed task. "This host now
		// refuses the connection" is a finding about the estate, and
		// the server files a row for it beside the original so the
		// difference is visible. A failed task would be read as "the
		// ghost could not carry out the instruction", which is a
		// statement about this agent and is not what happened.
		//
		// It also matters that this does not requeue: the server does
		// not hand a replay to a second ghost, because which ghost
		// sent it is part of the answer.
		out["error"] = sendErr.Error()
		sum += " — " + sendErr.Error()
	} else if status > 0 {
		sum += fmt.Sprintf(" — %d in %d ms", status, elapsed.Milliseconds())
	} else {
		// Bytes came back and no response could be read out of them.
		// Said as its own thing rather than folded into either of the
		// two above: "the server answered with something that is not
		// an HTTP response" is a third answer, and it is frequently
		// the point of sending a malformed request line.
		sum += fmt.Sprintf(" — %d bytes, not a readable HTTP response",
			len(body))
		out["unreadable"] = true
	}
	return Result{Status: "done", Output: recon.JSON(out), Summary: sum}
}

// rawDest is where a raw request goes and on what terms.
type rawDest struct {
	host    string
	port    int
	tls     bool
	sni     string
	verify  bool
	timeout time.Duration
	cap     int
}

// sendRaw writes bytes to one address and reads what comes back.
//
// -> (status, the raw response bytes, how long it took, error).
//
// A non-nil error means nothing was received. A zero status with bytes
// present means something was received that is not a response Go can
// read, which is a result and not an error -- see the caller.
func sendRaw(ctx context.Context, d rawDest, raw []byte) (int, []byte, time.Duration, error) {
	addr := net.JoinHostPort(d.host, strconv.Itoa(d.port))
	started := time.Now()

	dialer := &net.Dialer{Timeout: d.timeout}
	var conn net.Conn
	var err error
	if d.tls {
		// Validation off unless the operator asked for it, for the
		// reason gobuster.go and vhost.go give: certificates inside a
		// client's estate are routinely self-signed, expired, or
		// issued for another name, and refusing to talk to one is not
		// a useful default for a test tool. The switch is in the
		// replay dialog and this is what it sets.
		td := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{
			ServerName: d.sni,
			//nolint:gosec // G402: off by default on purpose; the dialog's "Verify TLS" switch is what sets this
			InsecureSkipVerify: !d.verify,
		}}
		// DialContext rather than tls.DialWithDialer: the handshake
		// has to be cancellable by the same context the rest of the
		// task is, or a ghost told to stop keeps one open against a
		// client's host until the dialer's own timeout.
		conn, err = td.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return 0, nil, time.Since(started), err
	}
	defer func() { _ = conn.Close() }()

	// One deadline for the whole exchange rather than one per read.
	// A server that answers a byte at a time inside the per-read
	// window would otherwise hold this agent open indefinitely.
	deadline := started.Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err = conn.Write(raw); err != nil {
		return 0, nil, time.Since(started), fmt.Errorf("writing the request: %w", err)
	}

	// Everything read off the socket is tee'd into `seen`, so what is
	// reported is the server's actual bytes -- its status line, its
	// header casing and order, its framing -- and not a re-rendering
	// of a parsed response. The parser below reads THROUGH this tee
	// and exists only to find the end of the message.
	seen := &cappedBuffer{limit: d.cap}
	br := bufio.NewReader(io.TeeReader(conn, seen))

	resp, err := http.ReadResponse(br, &http.Request{Method: methodOf(raw)})
	if err != nil {
		// Not a response Go can parse. The bytes are still the answer,
		// and for a deliberately malformed request they are usually
		// the whole point, so they are returned with a zero status
		// rather than thrown away. Drain what is left first, bounded,
		// so the capture is not cut at whatever bufio happened to
		// have buffered when the parse gave up.
		_, _ = io.Copy(io.Discard, io.LimitReader(br, int64(d.cap)))
		if seen.Len() == 0 {
			return 0, nil, time.Since(started), fmt.Errorf("no response: %w", err)
		}
		return 0, seen.Bytes(), time.Since(started), nil
	}
	// Read to the end of the body so the tee holds the whole message.
	// Bounded by the cap: the body is the part a target controls the
	// size of.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(d.cap)))
	_ = resp.Body.Close()
	return resp.StatusCode, seen.Bytes(), time.Since(started), nil
}

// methodOf reads the verb off the front of a raw request.
//
// http.ReadResponse needs it for one reason only: a response to HEAD
// has the headers of a body it will never send, and a reader that does
// not know the request was a HEAD waits for that body until the
// deadline. Nothing else about the request is parsed, and this does
// not alter what is sent -- the bytes went out before this is called.
//
// An unreadable request line yields "" and the reader treats the
// response as having a body, which is the right guess: a malformed
// request line is not a HEAD.
func methodOf(raw []byte) string {
	end := bytes.IndexAny(raw, "\r\n")
	if end < 0 {
		end = len(raw)
	}
	if sp := bytes.IndexByte(raw[:end], ' '); sp > 0 {
		return string(bytes.ToUpper(raw[:sp]))
	}
	return ""
}

// cappedBuffer collects bytes up to a limit and silently drops the
// rest.
//
// Silent on purpose. This is the capture of a response, the server
// stores a bounded prefix of it anyway, and what is wanted past the
// cap is nothing. Erroring would abort the read and leave the socket
// in a state the caller would then have to reason about.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	// The full length, always. Reporting a short write to io.TeeReader
	// makes it return an error and stop the read -- which would turn
	// "the response was longer than the cap" into "the response could
	// not be read", and those are different answers.
	return len(p), nil
}

func (c *cappedBuffer) Len() int      { return c.buf.Len() }
func (c *cappedBuffer) Bytes() []byte { return c.buf.Bytes() }
