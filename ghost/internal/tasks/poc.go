package tasks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xsecurity-ai/oddjob/ghost/internal/recon"
)

// Running a proof of concept, and saying whether it still reproduces.
//
// A PoC here is a nuclei template, for three reasons and the first is
// the practical one:
//
//   - **The agent image has no interpreter.** No python, no perl, no
//     ruby, no node -- `sh`, `curl`, `nmap`, `nuclei`, `httpx`. A PoC
//     that is a script is a PoC that cannot run on a Ghost.
//   - **It is declarative.** A model writing YAML with matchers cannot
//     reach the filesystem, spawn a process or open a socket of its
//     own choosing. A model writing a shell script can do all three,
//     on the engagement's own infrastructure, aimed at a client.
//   - **It is re-runnable, which is the whole point.** The artefact
//     that proves a finding today is the artefact that answers "has
//     this been fixed" in six weeks, and it answers it the same way.
//
// # The exit contract
//
// `Poc.exit_code` has defined it since before any of this existed:
//
//	0  reproduced        the matchers fired; the finding is still real
//	1  not reproduced    nuclei ran, matched nothing: FIXED, or moved
//	2  could not test    we never got an answer, so this proves nothing
//
// Two and one are the distinction the whole thing turns on. A
// template that could not reach the host matched nothing, and
// reporting that as "fixed" would close a live finding on the
// strength of a network error.
const (
	PocReproduced = 0
	PocFixed      = 1
	PocUnknown    = 2
)

// PocTimeout bounds one proof. A template is a handful of requests
// against one host; anything past this is stuck rather than slow.
const PocTimeout = 3 * time.Minute

func init() { Runners["poc"] = runPoc }

// TaskIDKey is where the agent puts the id of the task it is running,
// so a runner can name it back to the server. Set by the agent AFTER
// decoding the server's args, so a task cannot claim to be another
// one by putting this in its own arguments.
const TaskIDKey = "_task_id"

// SecretPlaceholder is what an authenticating proof carries in place
// of the credential. The value never travels with the template: the
// server keeps it, this agent fetches it when the task runs, and it
// is substituted here.
const SecretPlaceholder = "{{secret}}"

// TaskSecret fetches the credential an authenticating proof presents.
// Set by the agent, like Parallelism and AssetsHeld.
//
// **Nil must mean the safe answer, which here is "could not test".**
// A proof with no way to fetch its credential would otherwise run
// with the placeholder unsubstituted, present the literal string
// `{{secret}}`, be refused by the service and match nothing -- which
// this task reports as FIXED. Closing a live credential finding
// because the agent could not ask for the key is the worst wrong
// answer available.
var TaskSecret func(ctx context.Context, taskID int64) (string, error)

// scrub removes a credential from anything leaving this host.
//
// One place, at the single point a Result is built, for the reason
// every scrubber is written once: a value redacted in four callers is
// a value printed in the fifth. `pocHits` already keeps an allowlist
// of fields, so a request body never travels -- but `matched-at`
// carries a URL, and a template that put the credential in a query
// string would send it home inside one.
func scrub(res Result, secret string) Result {
	if secret == "" {
		return res
	}
	res.Output = strings.ReplaceAll(res.Output, secret, "[redacted]")
	res.Summary = strings.ReplaceAll(res.Summary, secret, "[redacted]")
	return res
}

// runPoc writes the template to disk and runs it at one target.
func runPoc(ctx context.Context, args map[string]any, workDir string) Result {
	tmpl := str(args, "template")
	if strings.TrimSpace(tmpl) == "" {
		return failed("poc: no template was supplied")
	}
	subjects := subjects(args, "url", "target")
	if len(subjects) == 0 {
		return failed("poc: no target to run against")
	}
	// One target, deliberately. A proof is a statement about one
	// host -- "this reproduces" means nothing spread across twelve,
	// and the exit code could not say which of them it was about.
	target := subjects[0]

	// An authenticating proof: the template holds a placeholder and
	// the credential is fetched now, from the server, over this
	// agent's own identity. See TaskSecret.
	secret := ""
	if boolArg(args, "needs_secret", false) {
		if TaskSecret == nil {
			return Result{
				Status: "done", ExitCode: PocUnknown,
				Output: pocJSON(target, PocUnknown, nil,
					"this proof presents a stored credential and this agent "+
						"has no way to fetch one, so nothing was sent"),
				Summary: "poc: could not be tested — no way to fetch the credential",
			}
		}
		v, err := TaskSecret(ctx, int64(intArg(args, TaskIDKey, 0)))
		// Deliberately not reported as a failure: the proof was never
		// run, so it proves nothing, and "could not test" is the
		// answer that says so. `err` is the agent's own plumbing and
		// cannot contain the credential -- the fetch failed.
		if err != nil || strings.TrimSpace(v) == "" {
			return Result{
				Status: "done", ExitCode: PocUnknown,
				Output: pocJSON(target, PocUnknown, nil,
					"the credential this proof presents could not be "+
						"fetched, so nothing was sent"),
				Summary: "poc: could not be tested — the credential was not released",
			}
		}
		secret = v
		// Substituted into the FILE, never into argv. A credential on
		// a command line is readable by every user on this box
		// through the process list, which is the same reason the
		// agent takes its own key from the environment rather than a
		// flag.
		tmpl = strings.ReplaceAll(tmpl, SecretPlaceholder, secret)
	}

	dir, err := os.MkdirTemp(workDir, "poc-")
	if err != nil {
		return failed("poc: no working directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// 0600 in a directory this process made and removes on the way
	// out. For an authenticating proof the file holds a live client
	// credential for the length of one nuclei run.
	tpath := filepath.Join(dir, "poc.yaml")
	if err := os.WriteFile(tpath, []byte(tmpl), 0o600); err != nil {
		return failed("poc: could not write the template: %v", err)
	}
	out := filepath.Join(dir, "poc.jsonl")

	// `-dast` is NOT passed and `-code` is NOT enabled. A code
	// template executes arbitrary commands on this host, which is
	// the one thing choosing nuclei was meant to rule out.
	argv := []string{
		"-t", tpath, "-u", target, "-jsonl", "-o", out,
		"-silent", "-duc", "-irr",
		// Validate before running: a template the model got slightly
		// wrong otherwise reports "no match", which reads as FIXED.
		// That is the single worst wrong answer this task can give.
		"-validate",
	}
	if v := runCmd(ctx, 30*time.Second, "nuclei", argv...); v.code != 0 {
		// Scrubbed too: a validation error quotes the offending
		// template, which at this point has the credential in it.
		return scrub(Result{
			Status: "done", ExitCode: PocUnknown,
			Output: pocJSON(target, PocUnknown, nil,
				"the template did not validate, so it was never run: "+
					tail(v.stderr, 400)),
			Summary: "poc: template invalid, nothing was sent",
		}, secret)
	}

	// Is the host even answering?
	//
	// **nuclei exits 0 when it cannot connect.** It finds no matches
	// and reports success, which is indistinguishable from a host
	// that has been patched -- so without this, a target that was
	// briefly down gets its live finding closed. That is the worst
	// wrong answer this task can give and it is the one it gave:
	// caught by running the tests against real nuclei in the agent
	// image rather than trusting them to skip on a laptop.
	//
	// Reachability is therefore established separately from the
	// match, exactly as the callback feature establishes it
	// separately from the hit. ANY HTTP response counts, 4xx and 5xx
	// included: the question is whether the host is there, not
	// whether it likes us.
	if why := pocUnreachable(ctx, target); why != "" {
		return Result{
			Status: "done", ExitCode: PocUnknown,
			Output:  pocJSON(target, PocUnknown, nil, why),
			Summary: "poc: could not be tested — " + target + " did not answer",
		}
	}

	argv = argv[:len(argv)-1] // drop -validate; now actually run it
	r := runCmd(ctx, timeout(args, PocTimeout), "nuclei", argv...)
	// `out` is filepath.Join of a MkdirTemp we created and a
	// constant; nothing from the task reaches it.
	body, _ := os.ReadFile(out) //nolint:gosec // G304: path is ours, not the caller's
	hits := pocHits(string(body))

	// Every return below goes through `scrub`, which is a no-op
	// unless this proof carried a credential. nuclei's stderr can
	// quote the template it was given, and `matched-at` can carry a
	// URL the credential went into -- so the redaction is applied
	// where the Result is built rather than at each source.
	switch {
	case len(hits) > 0:
		return scrub(Result{
			Status: "done", ExitCode: PocReproduced,
			Output:  pocJSON(target, PocReproduced, hits, ""),
			Summary: fmt.Sprintf("poc: reproduced on %s", target),
		}, secret)
	case r.code != 0:
		// nuclei itself failed. Not a clean run that found nothing.
		return scrub(Result{
			Status: "done", ExitCode: PocUnknown,
			Output: pocJSON(target, PocUnknown, nil,
				"nuclei exited "+fmt.Sprint(r.code)+": "+
					tail(r.stderr, 400)),
			Summary: "poc: could not be tested",
		}, secret)
	default:
		return scrub(Result{
			Status: "done", ExitCode: PocFixed,
			Output: pocJSON(target, PocFixed, nil,
				"the template ran and matched nothing"),
			Summary: fmt.Sprintf("poc: did not reproduce on %s", target),
		}, secret)
	}
}

// pocUnreachable -> why the host could not be reached, or "".
//
// Deliberately permissive about WHAT answers. A 403, a 500 and a
// redirect all prove the host is up and talking, and a proof that
// refused to run against anything but a 200 would report "could not
// test" for most of a real estate.
func pocUnreachable(ctx context.Context, target string) string {
	c := &http.Client{
		Timeout: 15 * time.Second,
		// Certificates inside a client's estate are routinely
		// self-signed or issued for another name, as every other
		// task here notes. A TLS error is not an absent host.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: the estate's own certs are routinely self-signed; see gobuster.go
		},
		// Not followed: a redirect is an answer. Following it would
		// test whatever it points at, which may be another host.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "the target is not a usable URL: " + err.Error()
	}
	res, err := c.Do(req)
	if err != nil {
		return ("the host did not answer, so the template was not run and " +
			"this proves nothing either way: " + tail(err.Error(), 200))
	}
	_ = res.Body.Close()
	return ""
}

// pocHits pulls the matched template ids out of nuclei's JSONL.
//
// Only what identifies the match: a nuclei result carries the whole
// request and response, and this goes into a database row that is
// read in a browser. The evidence is "it matched, here, at this
// time"; the bytes are already in the web tables.
func pocHits(jsonl string) []map[string]any {
	out := []map[string]any{}
	for _, line := range strings.Split(jsonl, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		keep := map[string]any{}
		for _, k := range []string{"template-id", "matched-at", "type",
			"host", "timestamp", "matcher-name"} {
			if v, ok := m[k]; ok {
				keep[k] = v
			}
		}
		out = append(out, keep)
	}
	return out
}

func pocJSON(target string, code int, hits []map[string]any,
	why string) string {
	return recon.JSON(map[string]any{
		"poc": map[string]any{
			"target": target,
			// The number AND the word. A reader of the raw result
			// should not have to remember which way round 0 and 1
			// go, and getting it backwards inverts the finding.
			"exit_code": code,
			"verdict": map[int]string{
				PocReproduced: "reproduced",
				PocFixed:      "not reproduced",
				PocUnknown:    "could not test",
			}[code],
			"hits": hits,
			"why":  why,
		},
	})
}
