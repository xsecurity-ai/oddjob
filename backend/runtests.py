#!/usr/bin/env python3
"""Run every suite, each against its own server and its own fresh database.

The suites assert on first-run behaviour (no users yet, settings at their
defaults), so they cannot share state and cannot be re-run against a dirty
database. Giving each one a private port and a private file is what makes
them repeatable; anything else passes once and then lies.
"""
from __future__ import annotations

import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
#: How long one suite may take before it is called hung. Generous, so
#: a slow runner is not mistaken for a deadlock.
SUITE_TIMEOUT = int(__import__("os").environ.get("ODDJOB_SUITE_TIMEOUT", 420))

TMP = pathlib.Path("/tmp")   # magictest reaches into /tmp/ms-m.db by name

# The suites take their base URL from ODDJOB_TEST_BASE, so the port is
# chosen here. A hard-coded port silently hands the suite to whatever else is
# already listening — a dev server, say — and the run then reports failures
# that belong to a different database entirely.
SUITES = [
    ("tests/apitest.py",      TMP / "ms-api.db"),
    ("tests/authtest.py",     TMP / "ms-auth.db"),
    ("tests/featuretest.py",  TMP / "ms-feat.db"),
    ("tests/settingstest.py", TMP / "ms-set.db"),
    ("tests/magictest.py",    TMP / "ms-m.db"),
    ("tests/projecttest.py",  TMP / "ms-proj.db"),
    ("tests/scantest.py",     TMP / "ms-scan.db"),
    ("tests/importtest.py",   TMP / "ms-imp.db"),
    ("tests/webtest.py",      TMP / "ms-web.db"),
    ("tests/reporttest.py",   TMP / "ms-rep.db"),
    ("tests/slacktest.py",    TMP / "ms-slack.db"),
    ("tests/agenttest.py",    TMP / "ms-agent.db"),
    ("tests/enumeratetest.py", TMP / "ms-enum.db"),
    ("tests/scopetest.py",     TMP / "ms-scope.db"),
    ("tests/mergetest.py",     TMP / "ms-merge.db"),
    ("tests/audittest.py",     TMP / "ms-audit.db"),
    ("tests/vulnfeedtest.py",  TMP / "ms-vuln.db"),
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_up(port: int, proc: subprocess.Popen, timeout: float = 25.0) -> bool:
    """Poll until the server answers, or it dies first."""
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            time.sleep(0.2)
            continue
        # Bound is not the same as serving, and no single route can be used as
        # a probe any more now that the gate refuses unauthenticated callers.
        # Any HTTP answer at all — including a 403 — means routing is live.
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read()
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.2)
    return False


def run(suite: str, db: pathlib.Path) -> tuple[int, int, str]:
    for p in (db, db.with_suffix(db.suffix + "-wal"), db.with_suffix(db.suffix + "-shm")):
        p.unlink(missing_ok=True)

    port = free_port()
    env = {**os.environ,
           "ODDJOB_DB": str(db),
           "ODDJOB_SECRET": "test-secret-not-for-use",
           "ODDJOB_TEST_BASE": f"http://127.0.0.1:{port}",
           "ODDJOB_TEST_SMTP_PORT": str(free_port())}
    # A fake Slack, so the suite can prove the events are WIRED rather
    # than just that the strings are formatted correctly.
    slack_port = free_port()
    env["ODDJOB_TEST_SLACK_PORT"] = str(slack_port)
    env["ODDJOB_SLACK_API"] = f"http://127.0.0.1:{slack_port}"
    # ODDJOB_DATABASE_URL beats ODDJOB_DB in app/db.py, so a shell that
    # has the production DSN exported — which is exactly the shell you
    # are in after sourcing pg.env to run the app — would silently point
    # every suite at the real database. It happened: eleven suites ran
    # against production and only stopped because /api/auth/setup
    # refuses once a user exists. Tests get their own SQLite file, and
    # nothing in the environment may override that.
    env.pop("ODDJOB_DATABASE_URL", None)
    srv = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--port", str(port), "--log-level", "warning"],
        cwd=HERE, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        if not wait_up(port, srv):
            out = ""
            if srv.poll() is not None and srv.stdout:
                out = srv.stdout.read()[-1500:]
            return 0, 1, f"server for {suite} never came up\n{out}"
        try:
            r = subprocess.run([sys.executable, suite], cwd=HERE, env=env,
                               capture_output=True, text=True, timeout=SUITE_TIMEOUT)
        except subprocess.TimeoutExpired as e:
            # A hung suite used to take the whole runner down: this
            # exception propagated, every other suite's result was lost,
            # and CI showed a 15-minute red job with nothing in it to
            # read. One suite hanging is one suite failing, and its
            # partial output is the only clue to why.
            partial = ((e.stdout or "") if isinstance(e.stdout, str)
                       else (e.stdout or b"").decode("utf-8", "replace"))
            tail = partial.strip().splitlines()[-25:]
            return 0, 1, (f"{suite} produced no result within "
                          f"{SUITE_TIMEOUT}s — treated as hung.\n"
                          + "\n".join(tail))
    finally:
        srv.send_signal(signal.SIGINT)
        try:
            srv.wait(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()

    body = r.stdout + r.stderr
    m = re.findall(r"(\d+) passed, (\d+) failed", body)
    if not m:
        return 0, 1, body[-2500:]
    p, f = int(m[-1][0]), int(m[-1][1])
    detail = "\n".join(ln for ln in body.splitlines() if "FAIL" in ln)
    return p, f, detail


def main() -> int:
    only = sys.argv[1:]
    tp = tf = 0
    bad: list[str] = []

    # A filter that matches nothing used to print "0 passed, 0 failed"
    # and exit 0, so a mistyped suite name was indistinguishable from a
    # clean run — including in CI, where nobody reads the zero.
    if only:
        known = {"migrationtest", "migrationtest.py"}
        for suite, _ in SUITES:
            n = suite.rsplit("/", 1)[-1]
            known |= {n, n.removesuffix(".py")}
        unknown = [a for a in only if a not in known]
        if unknown:
            print(f"no such suite: {', '.join(unknown)}")
            print("available: " + ", ".join(
                sorted(s.rsplit('/', 1)[-1].removesuffix('.py')
                       for s in [x[0] for x in SUITES]) + ["migrationtest"]))
            return 2

    # Runs first and without a server: if the migrations do not build the
    # models, every suite below is testing a schema no deployment will have.
    if not only or "migrationtest" in only or "migrationtest.py" in only:
        # Same isolation as every other suite: this one builds a SQLite
        # file from the migrations and inspects it, so an inherited
        # production DSN sends alembic somewhere else entirely and the
        # file comes back empty.
        mig_env = {k: v for k, v in os.environ.items()
                   if k != "ODDJOB_DATABASE_URL"}
        r = subprocess.run([sys.executable, "tests/migrationtest.py"], cwd=HERE,
                           env=mig_env, capture_output=True, text=True, timeout=600)
        out = r.stdout + r.stderr
        m = re.findall(r"(\d+) passed, (\d+) failed", out)
        p, f = (int(m[-1][0]), int(m[-1][1])) if m else (0, 1)
        tp += p
        tf += f
        print(f"  {'ok  ' if not f else 'FAIL'} {'migrationtest.py':<16} "
              f"{p:>3} passed, {f} failed")
        if f:
            bad.append("--- migrationtest.py ---\n"
                       + "\n".join(ln for ln in out.splitlines() if "FAIL" in ln))
    for suite, db in SUITES:
        name = suite.rsplit("/", 1)[-1]
        if only and name not in only and name.removesuffix(".py") not in only:
            continue
        import time as _t
        _t0 = _t.time()
        p, f, detail = run(suite, db)
        _el = _t.time() - _t0
        tp += p
        tf += f
        mark = "ok  " if f == 0 else "FAIL"
        print(f"  {mark} {name:<16} {p:>3} passed, {f} failed  ({_el:.0f}s)")
        if f and detail:
            bad.append(f"--- {name} ---\n{detail}")
    for b in bad:
        print("\n" + b)
    print(f"\n{'='*56}\n  TOTAL {tp} passed, {tf} failed\n{'='*56}")
    return 1 if tf else 0


if __name__ == "__main__":
    raise SystemExit(main())
