package tasks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawServer accepts one connection, hands back `reply` verbatim, and
// records every byte it was sent.
//
// Written against net.Listener rather than httptest.Server on purpose:
// httptest parses the request with net/http, and the whole question
// under test is what reaches the wire BEFORE any parser touches it. A
// server that corrects its input cannot prove the client did not.
//
// `want` is how many bytes to wait for before answering; 0 means "up
// to the blank line", which is all the tests that only assert on
// headers need. Reading a fixed count is what makes a body-carrying
// request comparable byte for byte — "read until the blank line" stops
// at the head and whatever else happened to be in the same segment,
// which is a different answer on a different run.
func rawServer(t *testing.T, reply string, want int) (host string, port int, got func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	recv := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recv <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 0, 4096)
		one := make([]byte, 256)
		for {
			if want > 0 {
				if len(buf) >= want {
					break
				}
			} else if strings.Contains(string(buf), "\r\n\r\n") {
				break
			}
			n, err := conn.Read(one)
			buf = append(buf, one[:n]...)
			if err != nil {
				break
			}
		}
		_, _ = conn.Write([]byte(reply))
		recv <- string(buf)
	}()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, not a TCP address", ln.Addr())
	}
	return "127.0.0.1", addr.Port, func() string {
		select {
		case s := <-recv:
			return s
		case <-time.After(5 * time.Second):
			t.Fatal("the server never saw a request")
			return ""
		}
	}
}

func replayArgs(host string, port int, raw string) map[string]any {
	return map[string]any{
		"host":       host,
		"port":       port,
		"scheme":     "http",
		"raw_b64":    base64.StdEncoding.EncodeToString([]byte(raw)),
		"timeout_s":  5,
		"verify_tls": false,
	}
}

func decodeReplay(t *testing.T, r Result) (map[string]any, string) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(r.Output), &out); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, r.Output)
	}
	body := ""
	if s, ok := out["response_b64"].(string); ok && s != "" {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("response_b64 is not base64: %v", err)
		}
		body = string(b)
	}
	return out, body
}

// The request must arrive byte for byte. Header order, header casing,
// a duplicated header and a Content-Length that disagrees with the
// body are all things somebody edits a packet in order to test, and
// anything that reassembles the request from parsed fields sends a
// different one.
func TestReplaySendsTheRequestVerbatim(t *testing.T) {
	raw := "POST /a/b?c=1 HTTP/1.1\r\n" +
		"Host: vhost.acme.example\r\n" +
		"x-ODD-case: Yes\r\n" +
		"Cookie: a=1\r\n" +
		"Cookie: b=2\r\n" +
		"content-length: 999\r\n" +
		"\r\n" +
		"x=1"
	host, port, got := rawServer(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
		len(raw))

	r := runReplay(context.Background(), replayArgs(host, port, raw), t.TempDir())
	if r.Status != "done" {
		t.Fatalf("status=%q error=%q", r.Status, r.Error)
	}
	// Byte for byte, head AND body: order, casing, the duplicated
	// Cookie and the Content-Length that disagrees with the body.
	if sent := got(); sent != raw {
		t.Errorf("the request was altered on the way out.\n got: %q\nwant: %q",
			sent, raw)
	}
	out, _ := decodeReplay(t, r)
	if out["status"] != float64(200) {
		t.Errorf("status = %v, want 200", out["status"])
	}
}

// The destination is the `host`/`port` arguments, never the Host
// header. That separation is what makes a Host-header test possible
// without the header being able to move where the packet goes.
func TestReplayDialsTheArgumentNotTheHostHeader(t *testing.T) {
	host, port, got := rawServer(t, "HTTP/1.1 421 Misdirected\r\nContent-Length: 0\r\n\r\n", 0)
	raw := "GET / HTTP/1.1\r\nHost: somewhere-else.acme.example:8443\r\n\r\n"

	r := runReplay(context.Background(), replayArgs(host, port, raw), t.TempDir())
	if r.Status != "done" {
		t.Fatalf("status=%q error=%q", r.Status, r.Error)
	}
	if sent := got(); !strings.Contains(sent, "Host: somewhere-else.acme.example:8443") {
		t.Errorf("the Host header did not travel as written: %q", sent)
	}
	out, _ := decodeReplay(t, r)
	if out["status"] != float64(421) {
		t.Errorf("status = %v, want 421 — it reached the dialled address", out["status"])
	}
}

// The response is kept as the server's own bytes. Reconstructing it
// from a parsed http.Response normalises header casing and order,
// which is frequently the thing being compared between the original
// and the edit.
func TestReplayKeepsTheResponseVerbatim(t *testing.T) {
	reply := "HTTP/1.1 418 I am a teapot\r\n" +
		"x-WEIRD-Casing: 1\r\n" +
		"Server: acme-edge\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"teapo"
	host, port, got := rawServer(t, reply, 0)

	r := runReplay(context.Background(),
		replayArgs(host, port, "GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\n"),
		t.TempDir())
	_ = got()
	out, body := decodeReplay(t, r)
	if body != reply {
		t.Errorf("the response was re-rendered.\n got: %q\nwant: %q", body, reply)
	}
	if out["status"] != float64(418) {
		t.Errorf("status = %v, want 418", out["status"])
	}
}

// A reply that is not an HTTP response is a third answer, not an
// error and not a status. Sending a malformed request line in order
// to see what the server does with it is the ordinary reason to use
// this tool, so the bytes have to come back.
func TestReplayUnreadableResponseIsStillAResult(t *testing.T) {
	host, port, got := rawServer(t, "NOT-HTTP-AT-ALL\r\nnonsense\r\n", 0)

	r := runReplay(context.Background(),
		replayArgs(host, port, "GET  HTTP/9.9 /x\r\nHost: a.acme.example\r\n\r\n"),
		t.TempDir())
	_ = got()
	if r.Status != "done" {
		t.Fatalf("status=%q error=%q", r.Status, r.Error)
	}
	out, body := decodeReplay(t, r)
	if _, has := out["status"]; has {
		t.Errorf("a status was claimed for an unreadable reply: %v", out["status"])
	}
	if out["unreadable"] != true {
		t.Errorf("unreadable = %v, want true", out["unreadable"])
	}
	if !strings.Contains(body, "NOT-HTTP-AT-ALL") {
		t.Errorf("the bytes were thrown away: %q", body)
	}
}

// A connection that fails is a result worth keeping: "this host now
// refuses" is itself a finding, and the server files a row for it
// beside the original. A failed TASK would read as the ghost being
// unable to carry out the instruction, which is a different claim.
func TestReplayRefusedConnectionIsDoneWithAnError(t *testing.T) {
	// Port 1 on loopback: nothing listens, and the refusal is
	// immediate rather than a timeout the suite has to wait out.
	r := runReplay(context.Background(),
		replayArgs("127.0.0.1", 1, "GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\n"),
		t.TempDir())
	if r.Status != "done" {
		t.Fatalf("status = %q, want done — a refusal is a result", r.Status)
	}
	out, _ := decodeReplay(t, r)
	if out["error"] == nil || out["error"] == "" {
		t.Errorf("no error was reported for a refused connection: %v", out)
	}
	if _, has := out["status"]; has {
		t.Errorf("a status was invented for a connection that never opened")
	}
}

func TestReplayNeedsItsArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"no raw", map[string]any{"host": "a.acme.example"}},
		{"no host", map[string]any{"raw_b64": base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\n\r\n"))}},
		{"raw is not base64", map[string]any{"host": "a.acme.example", "raw_b64": "not base64!!"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runReplay(context.Background(), tc.args, t.TempDir())
			if r.Status != "failed" {
				t.Errorf("status = %q, want failed", r.Status)
			}
		})
	}
}

// Past the cap the read keeps going and the extra is dropped. Returning
// a short write would make io.TeeReader stop with an error, which turns
// "longer than the cap" into "could not be read" — two different
// answers, and only one of them is true.
func TestCappedBufferDropsRatherThanFails(t *testing.T) {
	c := &cappedBuffer{limit: 4}
	for _, chunk := range []string{"ab", "cdef", "gh"} {
		n, err := c.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("Write(%q) = %d, %v; want %d, nil", chunk, n, err, len(chunk))
		}
	}
	if got := string(c.Bytes()); got != "abcd" {
		t.Errorf("kept %q, want %q", got, "abcd")
	}
}

// The response cap is honoured end to end, and a reply longer than it
// is truncated rather than lost.
func TestReplayTruncatesALongResponse(t *testing.T) {
	body := strings.Repeat("A", 4096)
	reply := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) +
		"\r\n\r\n" + body
	host, port, got := rawServer(t, reply, 0)

	args := replayArgs(host, port, "GET / HTTP/1.1\r\nHost: a.acme.example\r\n\r\n")
	args["resp_cap"] = 128
	r := runReplay(context.Background(), args, t.TempDir())
	_ = got()
	out, captured := decodeReplay(t, r)
	if len(captured) != 128 {
		t.Errorf("captured %d bytes, want 128", len(captured))
	}
	// Still a readable response: the cap limits what is KEPT, not what
	// is read off the socket.
	if out["status"] != float64(200) {
		t.Errorf("status = %v, want 200", out["status"])
	}
}

func TestMethodOf(t *testing.T) {
	for raw, want := range map[string]string{
		"GET / HTTP/1.1\r\n":  "GET",
		"head / HTTP/1.1\r\n": "HEAD",
		"POST /a HTTP/1.1":    "POST",
		"nonsense":            "",
		" / HTTP/1.1\r\n":     "",
		"":                    "",
	} {
		if got := methodOf([]byte(raw)); got != want {
			t.Errorf("methodOf(%q) = %q, want %q", raw, got, want)
		}
	}
}
