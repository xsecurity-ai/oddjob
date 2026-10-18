"""Findings that are already in the scan output, unread.

Every `-sV` the fleet runs carries `--script default,safe,vuln,
ssl-cert`, and the nmap importer has always stored each script's
output per service as JSON on `services.scripts`. Nothing read it.

So an engagement that scanned a host offering anonymous FTP has the
sentence "Anonymous FTP login allowed (FTP code 230)" in its
database and no finding anywhere. The packets were sent, the answer
came back, the evidence was stored, and the report did not mention
it. That is the same shape as `web_asset_endpoints` filling up with
nobody reading it.

**This adds no traffic.** It is a parser over data already
collected, which is why it is worth doing before any new tool: the
cheapest finding is the one already paid for.

# What is here, and what is deliberately not

A curated table, not "every script that produced output". Most NSE
output is inventory -- `ssh-hostkey` listing fingerprints,
`ssl-cert` naming an issuer -- and filing those as findings would
bury the four that matter under a hundred that do not. This repo
has a word for that: a long list copied wholesale brings along
entries that closed the hole years ago, and a false positive costs
an operator a morning.

So each entry names the script, what in its output constitutes a
finding, and at what severity. A script absent from this table is
still stored and still searchable; it simply does not become a
finding on its own.

# Severity is about the access, not the protocol

`ftp-anon` is `medium` because anonymous read of a directory is a
foothold, not a breach -- unless the output says the directory is
writable, which it sometimes does, and which is a different
finding. The `vuln` scripts carry nmap's own `State: VULNERABLE`
and those are `high`: nmap has already decided, and second-guessing
it here would be inventing a judgement from a string.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import lifecycle, manifest
from .models import Service, Target, Vuln

#: How these findings are attributed, and what a sweep of them is
#: matched against. NOT `nmap`: a run without the script arguments
#: reports no NSE output at all, and counting it as a look would
#: resolve every finding here the first time somebody ran a plain
#: port sweep.
SCANNER = "nse"


@dataclass(frozen=True)
class NseFinding:
    """One thing a script said that is worth filing."""
    script: str
    title: str
    severity: str
    #: The line (or lines) that justify it. A finding whose evidence
    #: is "the script ran" cannot be checked by its reader.
    evidence: str


#: nmap's own verdict line, whatever it says.
#:
#: The capture is the WHOLE state, not a match on the word
#: VULNERABLE, because nmap writes four different answers in this
#: one field and three of them contain that word:
#:
#:     State: VULNERABLE
#:     State: LIKELY VULNERABLE
#:     State: NOT VULNERABLE
#:     State: UNKNOWN (unable to test)
#:
#: Found by reading 187 services of real stored output, where
#: `http-slowloris-check` said LIKELY VULNERABLE and
#: `http-phpmyadmin-dir-traversal` said UNKNOWN (unable to test).
#: A regex for the word would have filed both of those and the NOT
#: as findings; a regex anchored on `State: VULNERABLE` filed none
#: of them, including the two that matter.
_STATE = re.compile(r"^\s*State:\s*(.+?)\s*$", re.M | re.I)

#: The same block's CVE reference, for the title.
_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I)


def nmap_state(text: str) -> str:
    """nmap's own verdict. -> vulnerable | likely | unknown | no | ''

    `''` means the output carries no state line at all, which is most
    NSE output and is not an answer about anything.
    """
    m = _STATE.search(text or "")
    if not m:
        return ""
    raw = m.group(1).strip().upper()
    # Order matters: NOT and LIKELY both contain VULNERABLE.
    if raw.startswith("NOT "):
        return "no"
    if raw.startswith("UNKNOWN"):
        return "unknown"
    if "LIKELY" in raw and "VULNERABLE" in raw:
        return "likely"
    if raw.startswith("VULNERABLE"):
        return "vulnerable"
    return ""


def _line_with(text: str, *needles: str) -> str:
    """The first line containing any needle, trimmed. '' if none."""
    low = [n.lower() for n in needles]
    for raw in (text or "").splitlines():
        s = raw.strip()
        if s and any(n in s.lower() for n in low):
            return s[:300]
    return ""


def _anon_ftp(script: str, text: str) -> NseFinding | None:
    # nmap says "Anonymous FTP login allowed (FTP code 230)" and then
    # lists the directory. The listing is the evidence.
    if "anonymous ftp login allowed" not in (text or "").lower():
        return None
    hit = re.search(r"^\s*(drwx[rwx-]*w[rwx-]*)\s.*$", text or "", re.M)
    # The writable entry goes IN the evidence, not just the title.
    # It is the whole reason this is high rather than medium, and a
    # severity whose justification is not in front of the reader is a
    # severity they have to take on trust.
    lead = (_line_with(text, "anonymous ftp login allowed")
            or (text or "").strip()[:300])
    return NseFinding(
        script,
        "Anonymous FTP login allowed"
        + (" — and a directory is world-writable" if hit else ""),
        "high" if hit else "medium",
        (lead + "\n" + hit.group(0).strip()[:200]) if hit else lead)


def _smtp_open_relay(script: str, text: str) -> NseFinding | None:
    low = (text or "").lower()
    # The script prints "Server is an open relay (N/16 tests)". It
    # also prints the same sentence shape when it is NOT, so the
    # count is what decides -- 0/16 is a pass.
    m = re.search(r"open relay \((\d+)/(\d+) tests\)", low)
    if not m or m.group(1) == "0":
        return None
    return NseFinding(script, "SMTP server is an open relay", "high",
                      _line_with(text, "open relay"))


def _snmp_public(script: str, text: str) -> NseFinding | None:
    # Reaching snmp-info at all means a community string worked. The
    # script does not name it, so the finding says what was proved
    # rather than guessing which string it was.
    if not (text or "").strip():
        return None
    return NseFinding(
        script, "SNMP responds to an unauthenticated query", "medium",
        _line_with(text, "snmpengineid", "enterprise", "software")
        or (text or "")[:300])


def _unauth_service(label: str, severity: str):
    """A service that answered an unauthenticated info request."""
    def judge(script: str, text: str) -> NseFinding | None:
        if not (text or "").strip():
            return None
        low = (text or "").lower()
        # These scripts print an error rather than staying quiet when
        # auth IS required, which is the case that must not file.
        if any(x in low for x in ("auth", "denied", "unauthorized",
                                  "requires password", "noauth")):
            return None
        return NseFinding(script, label, severity, (text or "").strip()[:300])
    return judge


#: What each of nmap's verdicts is worth as a finding.
#:
#: `unknown` is a finding, at `info`. That is the point of it: nmap
#: tried to test for a CVE and could not, and the thing a reader
#: must be able to tell is that nobody has established either way.
#: Dropping it would turn "could not determine" into "absent", which
#: is how a finding gets missed.
_STATE_SEVERITY = {"vulnerable": "high", "likely": "medium",
                   "unknown": "info"}

_STATE_TITLE = {
    "vulnerable": "nmap reports VULNERABLE",
    # nmap's own hedge, kept as a hedge. Promoting it to VULNERABLE
    # would be this file inventing confidence nmap declined to have.
    "likely": "nmap reports LIKELY VULNERABLE — not confirmed",
    "unknown": "nmap could not test for this — neither confirmed nor "
               "ruled out",
}


#: Protocol versions nobody should still be offering. SSLv2 and
#: SSLv3 are broken outright; TLS 1.0 and 1.1 are deprecated by RFC
#: 8996 and fail PCI. Written as nmap writes them in the block
#: header.
_DEAD_TLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")

#: `ssl-enum-ciphers` ends with its own grade for the port. nmap is
#: grading the weakest thing on offer, which is the right thing to
#: report: a server that also offers something strong is still a
#: server that will negotiate the weak one.
_LEAST = re.compile(r"least strength:\s*([A-F])", re.I)


def _ssl_ciphers(script: str, text: str) -> NseFinding | None:
    """What this port will actually negotiate.

    Three separate things, reported as one finding because they are
    one conversation with one server and three findings on one port
    is how a report becomes unreadable. The severity is the worst of
    them and the evidence names each.
    """
    t = text or ""
    if not t.strip():
        return None
    bad = [p for p in _DEAD_TLS if re.search(rf"^\s*{re.escape(p)}:", t, re.M)]
    grade = (_LEAST.search(t).group(1).upper() if _LEAST.search(t) else "")
    # nmap's own warnings, which it only emits when something is
    # wrong. Quoted rather than re-derived: it already decided.
    warns = [ln.strip() for ln in t.splitlines()
             if ln.strip() and ln.strip() not in ("warnings:",)
             and re.search(r"\b(SWEET32|BEAST|POODLE|broken|weak|insecure|"
                           r"forward secrecy|64-bit block|anonymous)\b",
                           ln, re.I)]
    if not bad and not warns and grade in ("", "A"):
        # A clean TLS configuration. Not a finding, and not silence
        # either -- the sweep records that this was looked at.
        return None
    bits = []
    if bad:
        bits.append("offers " + ", ".join(bad))
    if grade and grade != "A":
        bits.append(f"nmap grades the weakest offering {grade}")
    if warns:
        bits.append(warns[0][:160])
    # D/E/F and a dead protocol are different sizes of problem.
    sev = ("high" if (grade in ("D", "E", "F") or "SSLv2" in bad
                      or "SSLv3" in bad) else "medium")
    return NseFinding(script, "Weak TLS configuration — " + "; ".join(bits[:2]),
                      sev, "\n".join(([*bad] and ["Protocols: "
                                                  + ", ".join(bad)] or [])
                                      + ([f"Least strength: {grade}"]
                                         if grade else [])
                                      + warns[:4])[:300])


def _smb_signing(script: str, text: str) -> NseFinding | None:
    """SMB signing not required is what makes a relay attack work."""
    low = (text or "").lower()
    if not low.strip():
        return None
    # nmap words it two ways depending on the dialect, and both mean
    # the same thing: a client may negotiate signing away.
    weak = ("message signing enabled but not required" in low
            or "message_signing: disabled" in low
            or "signing disabled" in low)
    if not weak:
        return None
    return NseFinding(
        script, "SMB message signing is not required — relay attacks "
                "against this host will work", "medium",
        _line_with(text, "signing") or (text or "").strip()[:300])


def _smb_shares(script: str, text: str) -> NseFinding | None:
    """Shares this host offered to list.

    Only the ones whose access says we could actually read them.
    nmap enumerates shares it cannot open as well, and filing those
    would report every IPC$ in the estate as an exposure.
    """
    t = text or ""
    if not t.strip():
        return None
    readable = [ln.strip() for ln in t.splitlines()
                if re.search(r"Anonymous access:\s*(READ|READ/WRITE)", ln, re.I)]
    if not readable:
        return None
    writable = any("WRITE" in r.upper() for r in readable)
    return NseFinding(
        script,
        f"{len(readable)} SMB share(s) readable without credentials"
        + (" — and one is writable" if writable else ""),
        "high" if writable else "medium",
        "\n".join(readable[:6])[:300])


def _empty_password(label: str):
    """A database that admitted an empty password."""
    def judge(script: str, text: str) -> NseFinding | None:
        low = (text or "").lower()
        # The script prints the account it got in as. When it fails
        # it says so, and "no accounts" must not read as a finding.
        if not low.strip() or "no accounts" in low or "not vulnerable" in low:
            return None
        if "account" not in low and "login success" not in low:
            return None
        return NseFinding(script, label, "critical",
                          (text or "").strip()[:300])
    return judge


def _nmap_vuln(script: str, text: str) -> NseFinding | None:
    """Whatever nmap itself concluded, at the weight nmap gave it.

    Judged for ANY script, not only `*-vuln-*` named ones. The live
    estate had `http-slowloris-check` and
    `http-phpmyadmin-dir-traversal` carrying real verdicts, and
    neither name contains `vuln`: nmap's conclusion is nmap's
    conclusion whatever it called the script that reached it.
    """
    state = nmap_state(text)
    sev = _STATE_SEVERITY.get(state)
    if sev is None:
        # "no" lands here along with "". A NOT VULNERABLE is nmap
        # answering the question, and the answer is nothing to file.
        return None
    cve = _CVE.search(text or "")
    title = f"{script}: {_STATE_TITLE[state]}"
    if cve:
        title += f" ({cve.group(1).upper()})"
    return NseFinding(script, title, sev,
                      _line_with(text, "state:", "ids:", "risk factor")
                      or (text or "")[:300])


#: script id -> how to judge its output.
#:
#: Ordered by how often it earns its place on a real engagement
#: rather than alphabetically, so the list reads as a priority.
JUDGES: dict[str, object] = {
    "ftp-anon": _anon_ftp,
    "smtp-open-relay": _smtp_open_relay,
    "snmp-info": _snmp_public,
    "snmp-sysdescr": _snmp_public,
    # Data stores that should never answer a stranger. Each prints an
    # auth error instead of data when it is configured properly,
    # which `_unauth_service` keys on.
    "redis-info": _unauth_service(
        "Redis answers without authentication", "high"),
    "mongodb-info": _unauth_service(
        "MongoDB answers without authentication", "high"),
    "mongodb-databases": _unauth_service(
        "MongoDB lists its databases without authentication", "high"),
    "memcached-info": _unauth_service(
        "Memcached answers without authentication", "high"),
    "cassandra-info": _unauth_service(
        "Cassandra answers without authentication", "high"),
    "rsync-list-modules": _unauth_service(
        "rsync lists its modules without authentication", "medium"),
    "nfs-showmount": _unauth_service(
        "NFS exports are listable", "medium"),
    "ldap-rootdse": _unauth_service(
        "LDAP answers an anonymous root DSE query", "low"),

    # ---- added once the script set was widened to collect them ----
    #: What this port will actually negotiate. Until `ssl-enum-ciphers`
    #: was named in the ghost's script set this could never fire:
    #: nmap files it under `discovery, intrusive` and neither
    #: `default` nor `safe` includes it.
    "ssl-enum-ciphers": _ssl_ciphers,
    "smb-security-mode": _smb_signing,
    "smb2-security-mode": _smb_signing,
    "smb-enum-shares": _smb_shares,
    "mysql-empty-password": _empty_password(
        "MySQL accepts an empty password"),
    "ms-sql-empty-password": _empty_password(
        "Microsoft SQL Server accepts an empty password"),
}

#: Kept for the name-based half of the rule, though the verdict
#: block is now read for every script regardless. A `*-vuln-*` name
#: is still a signal, and having it here documents the set that was
#: originally covered.
VULN_PATTERN = re.compile(r"(^|-)vuln(-|$)")


def judge(script: str, text: str) -> NseFinding | None:
    """One script's output. -> a finding, or None.

    None is the overwhelmingly common answer and is not a failure:
    most NSE output is inventory.
    """
    script = (script or "").strip().lower()
    if not script:
        return None
    fn = JUDGES.get(script)
    if fn is not None:
        return fn(script, text or "")       # type: ignore[operator]
    # nmap's own verdict block, from ANY script. This used to be
    # gated on a `*-vuln-*` name and missed every script that
    # reaches a verdict without saying so in its name -- which, on a
    # real estate, was all of them: 24 stored results carried a
    # state line and the parser filed none.
    return _nmap_vuln(script, text or "")


def findings_for(scripts_json: str | None) -> list[NseFinding]:
    """Every finding in one service's stored script output.

    Sorted by severity then script id, so two runs over an unchanged
    service produce an identical list.
    """
    try:
        blob = json.loads(scripts_json) if scripts_json else {}
    except (ValueError, TypeError):
        return []
    if not isinstance(blob, dict):
        return []
    out = [f for f in (judge(k, v if isinstance(v, str) else str(v))
                       for k, v in blob.items()) if f is not None]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(out, key=lambda f: (rank.get(f.severity, 5), f.script))


# ------------------------------------------------------------ recording
#
# Two call sites, for the two ways script output arrives:
#
#   * the import, for everything from here on;
#   * a sweep at startup, for the output already in the database --
#     which is the whole point. `services.scripts` has been filled
#     since the nmap importer was written, so the backlog is not an
#     edge case, it is most of the data.
#
# Both go through `record` and both are idempotent, keyed on
# `external_id` the same way `_file_vuln` is. Re-importing a scan
# amends its findings; it does not grow a second copy of each.


def external_id(port: int | None, protocol: str | None, script: str) -> str:
    """The upsert key: this script, on this port, on this host.

    Carries the port because the same script fires on every instance
    of a service and two FTP daemons on one host are two findings.
    """
    return f"nse:{protocol or 'tcp'}/{port or 0}:{script}"[:128]


async def record(session: AsyncSession, target_id: int, port: int | None,
                 protocol: str | None, f: NseFinding,
                 seen_at: datetime | None = None,
                 run_manifest: str | None = None) -> bool:
    """Write one finding. -> True if it is new.

    The severity is re-asserted on an existing row but the triage is
    not: a person who marked this a false positive has made a
    judgement that a re-run of the same parser does not get to undo.

    `scanner` is `nse` and not `nmap`: an nmap run WITHOUT the script
    arguments reports no NSE output at all, and letting it count as a
    look would resolve every anonymous-FTP finding in the estate the
    first time somebody ran a plain port sweep.
    """
    seen_at = seen_at or datetime.now(UTC)
    eid = external_id(port, protocol, f.script)
    row = (await session.execute(select(Vuln).where(
        Vuln.target_id == target_id,
        Vuln.external_id == eid))).scalar_one_or_none()
    body = (f"nmap's {f.script} script reported:\n\n{f.evidence}\n\n"
            f"Found by NSE during service detection — no additional "
            f"traffic was sent to confirm it.")
    if row is not None:
        row.title, row.severity, row.description = (
            f.title[:1000], f.severity, body[:8000])
        row.last_seen_at = seen_at
        if row.first_seen_at is None:
            row.first_seen_at = seen_at
        if not row.scanner:
            row.scanner = SCANNER
        row.found_by_manifest = run_manifest
        return False
    session.add(Vuln(
        target_id=target_id, title=f.title[:1000], severity=f.severity,
        status="open", port=port, protocol=protocol,
        description=body[:8000], external_id=eid,
        scanner=SCANNER, first_seen_at=seen_at, last_seen_at=seen_at,
        found_by_manifest=run_manifest))
    return True


def manifest_detail(args: str | None) -> dict:
    """The selectors behind `manifest_for`, for storing alongside.

    A hash that cannot be explained is a hash nobody will trust when
    it says two runs differ, and "the script set changed" is only
    actionable if somebody can see which scripts.
    """
    sel = manifest.selectors("nmap", args)
    keep = {k: v for k, v in sel.items()
            if k in ("--script", "--script-args", "-sC", "-A")}
    return manifest.build(SCANNER, None, keep)[1]


def manifest_for(args: str | None) -> str:
    """The run identity for NSE findings, from an nmap command line.

    The SCRIPT SET and nothing else. A port range changes which
    services get looked at, which the sweep already records per
    host; the script list changes what the scripts could find, and
    that is the only thing `resolved` turns on here.

    A scan whose arguments were not recorded yields the manifest of
    the bare scanner name, which compares equal to other such runs
    and to nothing with a known script set. That is the honest
    answer: two runs we know nothing about are not demonstrably
    different, and one we know about is not demonstrably the same.
    """
    sel = manifest.selectors("nmap", args)
    keep = {k: v for k, v in sel.items()
            if k in ("--script", "--script-args", "-sC", "-A")}
    return manifest.build(SCANNER, None, keep)[0]


async def record_service(session: AsyncSession, target_id: int,
                         port: int | None, protocol: str | None,
                         scripts: dict[str, str] | str | None,
                         seen_at: datetime | None = None,
                         run_manifest: str | None = None) -> int:
    """Every finding in one service's script output. -> how many are new.

    A service that HAS script output is a service nmap ran scripts
    against, so this also records the sweep -- including when the
    output holds nothing worth filing. That is the case that makes
    `resolved` possible: the scripts ran, the anonymous FTP is gone,
    and nothing but a recorded look can tell that apart from nobody
    having checked.
    """
    blob = scripts if isinstance(scripts, str) else json.dumps(scripts or {})
    try:
        looked = bool(json.loads(blob)) if blob else False
    except (ValueError, TypeError):
        looked = False
    new = 0
    seen_at = seen_at or datetime.now(UTC)
    for f in findings_for(blob):
        if await record(session, target_id, port, protocol, f, seen_at,
                        run_manifest):
            new += 1
    if looked:
        t = await session.get(Target, target_id)
        if t is not None:
            await lifecycle.record_sweep(session, t.project_id, target_id,
                                         SCANNER, seen_at, run_manifest)
    return new


async def sweep(session: AsyncSession, project_id: int | None = None,
                limit: int = 20000) -> tuple[int, int]:
    """Read stored script output across a project. -> (services, new).

    `limit` is a ceiling on services examined, not on findings: this
    runs at startup and must not hold the application there. A
    project with more services than the ceiling finishes on the next
    start, and the caller logs the number either way rather than
    reporting a partial sweep as a complete one.
    """
    q = (select(Service.target_id, Service.port, Service.protocol,
                Service.scripts)
         .join(Target, Target.id == Service.target_id)
         .where(Service.scripts.is_not(None))
         .order_by(Service.id)
         .limit(limit))
    if project_id is not None:
        q = q.where(Target.project_id == project_id)
    seen = new = 0
    for target_id, port, protocol, scripts in (await session.execute(q)).all():
        seen += 1
        new += await record_service(session, target_id, port, protocol, scripts)
    return seen, new
