#!/usr/bin/env python3
"""Mirror every Faraday workspace into Oddjob, one project each.

    FARADAY_URL=… FARADAY_USER=… FARADAY_PASS=… \
    ODDJOB_URL=http://127.0.0.1:8000 ODDJOB_USER=… ODDJOB_PASS=… \
    uv run python faraday_sync.py [--only NAME,NAME] [--dry-run]

**Archived workspaces.** Faraday returns 403 on reads of an archived
workspace, so one has to be un-archived to be read. That is a change to
somebody else's system, so it is undone: each workspace's original `active`
flag is captured first and restored in a `finally`, and the restore also
runs on Ctrl-C and on an unhandled exception. The script prints the restore
so there is a record of it, and if a restore itself fails it says so loudly
rather than exiting quietly having left an archive open.

Idempotent. Oddjob's bulk import upserts on (host) and on the vuln's
external_id, so re-running reconciles rather than duplicating.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import sys
import urllib.error
import urllib.request

PAGE = 2000


class Api:
    def __init__(self, base: str, headers: dict):
        self.base = base.rstrip("/")
        self.headers = headers

    def req(self, path: str, method: str = "GET", body=None, timeout=300):
        r = urllib.request.Request(self.base + path, method=method)
        for k, v in self.headers.items():
            r.add_header(k, v)
        if body is not None:
            r.data = json.dumps(body).encode()
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r, timeout=timeout) as x:
                raw = x.read()
                return x.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw[:400].decode(errors="replace")


def env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if not v:
        sys.exit(f"{name} is not set")
    return v


# ------------------------------------------------------------- faraday
def workspaces(fd: Api) -> list[dict]:
    st, doc = fd.req("/_api/v3/ws")
    if st != 200:
        sys.exit(f"could not list workspaces: {st} {doc}")
    rows = doc if isinstance(doc, list) else doc.get("rows", [])
    return [r.get("value", r) for r in rows]


def set_active(fd: Api, name: str, active: bool) -> bool:
    st, _ = fd.req(f"/_api/v3/ws/{name}", "PATCH", {"active": active})
    return st in (200, 201, 204)


def fetch(fd: Api, ws: str) -> tuple[list, list, list]:
    def page(path: str, key: str) -> list:
        out, offset = [], 0
        while True:
            st, doc = fd.req(f"{path}?page_size={PAGE}&page={offset // PAGE + 1}")
            if st != 200 or not isinstance(doc, dict):
                if offset == 0:
                    print(f"      ! {path} -> {st}")
                break
            rows = doc.get(key) or []
            out += [r.get("value", r) for r in rows]
            total = doc.get("count") or len(out)
            offset += len(rows)
            if not rows or offset >= total:
                break
        return out

    return (page(f"/_api/v3/ws/{ws}/hosts", "rows"),
            page(f"/_api/v3/ws/{ws}/services", "services"),
            page(f"/_api/v3/ws/{ws}/vulns", "vulnerabilities"))


# ------------------------------------------------------------ transform
SEV = {"critical": "critical", "high": "high", "med": "medium",
       "medium": "medium", "low": "low", "info": "info",
       "informational": "info", "unclassified": "info"}


def name_for(h: dict) -> str | None:
    """Prefer a hostname over an address, matching the importers.

    Faraday keys hosts by IP, but a target called `api.corp.com` from a scan
    import and the same box called `10.0.0.5` here would otherwise be two
    rows. The hostname wins so they converge.
    """
    names = [str(n).strip().rstrip(".").lower()
             for n in (h.get("hostnames") or []) if str(n).strip()]
    good = [n for n in names if "." in n and "*" not in n and " " not in n]
    if good:
        return good[0]
    ip = str(h.get("ip") or "").strip()
    return ip or None


def _desc(v: dict) -> str | None:
    body = (v.get("desc") or v.get("description") or "").strip()
    ref = str(v.get("external_id") or "").strip()
    if ref:
        body = f"Faraday ref: {ref}\n\n{body}" if body else f"Faraday ref: {ref}"
    return body or None


def payload(code: str, hosts: list, services: list, vulns: list) -> dict:
    by_host_id: dict[int, str] = {}
    by_ip: dict[str, str] = {}
    targets, svcs, vs = [], [], []

    for h in hosts:
        n = name_for(h)
        if not n:
            continue
        hid = h.get("id") or h.get("_id")
        if hid is not None:
            by_host_id[int(hid)] = n
        ip = str(h.get("ip") or "").strip()
        if ip:
            by_ip.setdefault(ip, n)
        names = [str(x).strip().rstrip(".").lower()
                 for x in (h.get("hostnames") or []) if str(x).strip()]
        targets.append({
            "host": n,
            "ip_address": ip or None,
            "os": (h.get("os") or "").strip() or None,
            "notes": (h.get("description") or "").strip() or None,
            "tags": ",".join(x for x in names if x != n) or None,
        })

    for s in services:
        hid = s.get("host_id") or s.get("parent")
        host = by_host_id.get(int(hid)) if hid is not None else None
        if not host:
            continue
        port = s.get("port")
        if port is None:
            ports = s.get("ports")
            port = ports[0] if isinstance(ports, list) and ports else ports
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        nm = (s.get("name") or "").strip()
        # Faraday's `version` is the product string — "Laravel 5.4",
        # "Ivanti Connect Secure", "Plesk sw-cp-server (…)". Its
        # `description` is an operator's note. The first version of this
        # script used the description as the banner, which filled a column
        # whose job is "what software is listening" with "coverage gap"
        # and "Created by DEADEYE for T138 residue".
        version = (s.get("version") or "").strip() or None
        svcs.append({
            "host": host, "port": port,
            "protocol": (s.get("protocol") or "tcp").lower(),
            "state": (s.get("status") or "open").lower(),
            # Faraday's blank service name means nobody identified it, which
            # is exactly what UNKNOWN records.
            "name": nm if nm and nm.lower() != "unknown" else "UNKNOWN",
            "version": version,
            "banner": version,
            "notes": (s.get("description") or "").strip() or None,
        })

    for v in vulns:
        host = None
        hns = [str(x).strip().rstrip(".").lower() for x in (v.get("hostnames") or []) if x]
        good = [x for x in hns if "." in x and "*" not in x]
        if good:
            host = good[0]
        if not host:
            tgt = str(v.get("target") or "").strip()
            host = by_ip.get(tgt) or (tgt.lower() or None)
        if not host:
            continue
        svc = v.get("service") or {}
        port = svc.get("ports") if isinstance(svc, dict) else None
        if isinstance(port, list):
            port = port[0] if port else None
        try:
            port = int(port) if port is not None else None
        except (TypeError, ValueError):
            port = None
        vs.append({
            "host": host,
            "title": (v.get("name") or "untitled").strip()[:1000],
            "severity": SEV.get(str(v.get("severity") or "info").lower(), "info"),
            "status": (v.get("status") or "open").strip().lower(),
            # The native external_id is kept as provenance, since it is
            # how the finding is referred to elsewhere — just not as a key.
            "description": _desc(v),
            "remediation": (v.get("resolution") or "").strip() or None,
            # ALWAYS Faraday's row id, never its `external_id` field.
            # That field is a grouping TAG, not a key: in a real workspace
            # one value covers hundreds of findings (FALCON-T04-COVERAGE
            # is on 652 of them). Using it as the upsert key silently
            # collapses them all onto one row — 1,458 findings lost on the
            # first run of this script. The row id is unique by definition.
            "external_id": f"faraday-{code}-{v.get('id')}",
            "port": port,
            "protocol": (svc.get("protocol") or None) if isinstance(svc, dict) else None,
        })

    return {"project": code, "project_name": code.title(),
            "targets": targets, "services": svcs, "vulns": vs}


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated workspace names")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    fd = Api(env("FARADAY_URL"), {"Authorization": "Basic " + base64.b64encode(
        f"{env('FARADAY_USER')}:{env('FARADAY_PASS')}".encode()).decode()})

    ms_url = os.environ.get("ODDJOB_URL", "http://127.0.0.1:8000")
    ms = Api(ms_url, {})
    st, tok = ms.req("/api/auth/login", "POST",
                     {"username": env("ODDJOB_USER"),
                      "password": env("ODDJOB_PASS")})
    if st != 200:
        sys.exit(f"Oddjob login failed: {st} {tok}")
    ms.headers["Authorization"] = f"Bearer {tok['access_token']}"

    all_ws = workspaces(fd)
    wanted = {w.strip() for w in args.only.split(",")} if args.only else None
    todo = [w for w in all_ws if not wanted or w.get("name") in wanted]

    # Every workspace we un-archive, so the handler can put them all back
    # even if the process is interrupted halfway through the list.
    opened: dict[str, bool] = {}

    def restore():
        for nm, was_active in list(opened.items()):
            if was_active:
                continue
            ok = set_active(fd, nm, False)
            print(f"  {'restored' if ok else '!! FAILED TO RESTORE'} archive: {nm}")
            if not ok:
                print(f"     >>> {nm} IS STILL UN-ARCHIVED. Re-archive it by hand.")
            opened.pop(nm, None)

    def on_signal(signum, _frame):
        print(f"\ninterrupted ({signum}) — restoring archive state")
        restore()
        sys.exit(130)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    totals = {"targets": 0, "services": 0, "vulns": 0}
    try:
        for w in todo:
            name = w.get("name")
            active = bool(w.get("active"))
            stats = w.get("stats") or {}
            print(f"\n== {name} "
                  f"(faraday: {stats.get('hosts', '?')} hosts, "
                  f"{stats.get('total_vulns', '?')} vulns, "
                  f"{'active' if active else 'archived'})")

            if not active:
                if not set_active(fd, name, True):
                    print("   ! could not un-archive; skipping")
                    continue
                opened[name] = active
                print("   un-archived for reading")

            hosts, services, vulns = fetch(fd, name)
            print(f"   read: {len(hosts)} hosts, {len(services)} services, "
                  f"{len(vulns)} vulns")

            code = "".join(c if c.isalnum() or c in "-_" else "-"
                           for c in str(name)).upper().strip("-")
            body = payload(code, hosts, services, vulns)
            print(f"   mapped: {len(body['targets'])} targets, "
                  f"{len(body['services'])} services, {len(body['vulns'])} vulns")

            if args.dry_run:
                print("   (dry run — nothing written)")
            elif not (body["targets"] or body["vulns"]):
                print("   nothing to import")
            else:
                st, r = ms.req("/api/bulk", "POST", body, timeout=900)
                if st != 200:
                    print(f"   ! import failed: {st} {str(r)[:300]}")
                else:
                    c, u = r["created"], r["updated"]
                    print(f"   imported: +{c['targets']}/~{u['targets']} targets, "
                          f"+{c['services']}/~{u['services']} services, "
                          f"+{c['vulns']}/~{u['vulns']} vulns")
                    if r.get("errors"):
                        print(f"   {len(r['errors'])} row(s) rejected, e.g. "
                              f"{r['errors'][0][:120]}")
                    for k in totals:
                        totals[k] += c[k]

            # Re-archive this one immediately rather than at the end: the
            # window in which somebody else's workspace is open should be as
            # short as the work requires.
            if name in opened:
                restore_one = set_active(fd, name, False)
                print(f"   {'re-archived' if restore_one else '!! FAILED to re-archive'}")
                if restore_one:
                    opened.pop(name, None)
    finally:
        restore()

    print(f"\n{'='*58}\n  new: {totals['targets']} targets, "
          f"{totals['services']} services, {totals['vulns']} vulns\n{'='*58}")

    # Prove the archive flags are as we found them, rather than assuming.
    after = {w.get("name"): bool(w.get("active")) for w in workspaces(fd)}
    before = {w.get("name"): bool(w.get("active")) for w in all_ws}
    drift = [n for n in before if before[n] != after.get(n)]
    print("archive state unchanged" if not drift
          else f"!! ARCHIVE STATE DRIFTED for: {drift}")
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
