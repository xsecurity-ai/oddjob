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

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Service, Target, Vuln


@dataclass(frozen=True)
class NseFinding:
    """One thing a script said that is worth filing."""
    script: str
    title: str
    severity: str
    #: The line (or lines) that justify it. A finding whose evidence
    #: is "the script ran" cannot be checked by its reader.
    evidence: str


#: nmap's own verdict, which several `*-vuln-*` scripts emit in a
#: standard block. When nmap says VULNERABLE it has matched a version
#: AND usually probed; that is a stronger claim than anything this
#: file could derive from prose.
_VULNERABLE = re.compile(r"^\s*State:\s*VULNERABLE", re.M | re.I)

#: The same block's CVE reference, for the title.
_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.I)


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


def _nmap_vuln(script: str, text: str) -> NseFinding | None:
    """Anything nmap itself marked VULNERABLE."""
    if not _VULNERABLE.search(text or ""):
        return None
    cve = _CVE.search(text or "")
    title = f"{script}: nmap reports VULNERABLE"
    if cve:
        title += f" ({cve.group(1).upper()})"
    return NseFinding(script, title, "high",
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
}

#: Every `*-vuln-*` script, plus the named ones that use the same
#: VULNERABLE block. Matched by pattern because the set grows with
#: nmap's own script library and pinning a list here would mean a new
#: nmap shipped findings nobody reads.
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
    if VULN_PATTERN.search(script):
        return _nmap_vuln(script, text or "")
    return None


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
                 protocol: str | None, f: NseFinding) -> bool:
    """Write one finding. -> True if it is new.

    The severity is re-asserted on an existing row but the triage is
    not: a person who marked this a false positive has made a
    judgement that a re-run of the same parser does not get to undo.
    """
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
        return False
    session.add(Vuln(
        target_id=target_id, title=f.title[:1000], severity=f.severity,
        status="open", port=port, protocol=protocol,
        description=body[:8000], external_id=eid))
    return True


async def record_service(session: AsyncSession, target_id: int,
                         port: int | None, protocol: str | None,
                         scripts: dict[str, str] | str | None) -> int:
    """Every finding in one service's script output. -> how many are new."""
    blob = scripts if isinstance(scripts, str) else json.dumps(scripts or {})
    new = 0
    for f in findings_for(blob):
        if await record(session, target_id, port, protocol, f):
            new += 1
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
