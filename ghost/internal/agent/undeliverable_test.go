package agent

import (
	"errors"
	"fmt"
	"testing"

	"github.com/xsecurity-ai/oddjob/ghost/internal/client"
)

// When a spooled result is worth giving up on, and — much more
// importantly — when it is not.
//
// The bug being fixed: one task on a real agent reached attempt 6,439,
// re-sending the same payload on every heartbeat for a day against a
// 404 that was never going to change.
//
// The bug NOT to introduce while fixing it: for about an hour the
// agent's routes did not match the server's and every call returned
// 404. Anything that treats a bare 404 as "give up" would have thrown
// away real scan output from a client's estate because of a
// deployment mistake. That case is the first test here, and it is the
// one that matters.
func TestUndeliverable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// The whole point. A 404 because the ROUTE is wrong says
		// nothing about the task, and the result must survive it.
		{"a 404 from a missing endpoint is retried", &client.HTTPError{
			Code: 404, Status: "404 Not Found",
			Body: `{"detail":"no such endpoint: /api/agents/tasks"}`}, false},
		{"...and so is a bare 404 with no explanation", &client.HTTPError{
			Code: 404, Status: "404 Not Found", Body: ""}, false},

		// A 404 that says the server looked for this task and has not
		// got it is a fact about the task, and will not change.
		{"a task the server does not have is given up on", &client.HTTPError{
			Code: 404, Status: "404 Not Found",
			Body: `{"detail":"no such task for this agent"}`}, true},
		{"...whatever case it is written in", &client.HTTPError{
			Code: 404, Status: "404 Not Found",
			Body: `{"detail":"No Such Task For This Agent"}`}, true},

		// Everything else is transient until proven otherwise.
		{"401 is retried — a key can be restored", &client.HTTPError{
			Code: 401, Body: "not authenticated"}, false},
		{"500 is retried", &client.HTTPError{
			Code: 500, Body: "no such task for this agent"}, false},
		{"a network error is retried", errors.New("connection refused"), false},
		{"nil is not a failure at all", nil, false},
	}
	for _, c := range cases {
		why, got := undeliverable(c.err)
		if got != c.want {
			t.Errorf("%s: undeliverable=%v want %v (err=%v)",
				c.name, got, c.want, c.err)
		}
		if got && why == "" {
			t.Errorf("%s: gave up without recording a reason", c.name)
		}
	}
}

func TestUndeliverableSeesThroughWrapping(t *testing.T) {
	// `do` wraps retries as "after 5 attempts: %w", so the decision
	// has to survive being nested. `errors.As`, not a type assertion.
	inner := &client.HTTPError{
		Code: 404, Status: "404 Not Found",
		Body: `{"detail":"no such task for this agent"}`}
	wrapped := fmt.Errorf("after 5 attempts: %w", inner)
	if _, ok := undeliverable(wrapped); !ok {
		t.Error("a wrapped HTTPError was not recognised")
	}
}

func TestHTTPErrorStillReadsTheSameWayToAnOperator(t *testing.T) {
	// It became a type so one caller could branch on the code. Every
	// other caller prints it, and those messages are what somebody
	// debugging at two in the morning actually sees.
	e := &client.HTTPError{
		Method: "POST", Path: "/api/ghosts/heartbeat",
		Code: 401, Status: "401 Unauthorized", Body: "not authenticated"}
	want := "POST /api/ghosts/heartbeat: 401 Unauthorized: not authenticated"
	if e.Error() != want {
		t.Errorf("reads as %q, want %q", e.Error(), want)
	}
}
