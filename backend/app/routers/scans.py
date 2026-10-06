"""Importing scanner and C2 output.

Every supported tool is parsed into one intermediate representation (see
`app/importers/model.py`) and ingested through a single path, so the upsert
keys, the scope checks and the timeline writing exist once rather than per
format. Adding a tool is a parser module and a registry line.

Upserts throughout — target by host, service by (target, port, protocol),
vuln by external_id else (host, title), implant by (target, framework, id).
Re-running a scan updates what is there; a wider scan next week adds to it.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime
import json
import os
import secrets
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from .. import importers
from ..db import get_session
from ..events import broker
from ..hosts import InvalidHost, normalise_host
from ..importers.policy import Decision, Policy, survey
from ..importers.model import (ImportError_, ParsedCredential, ParsedHost,
                               ParsedImplant, ParsedScan, ParsedService,
                               ParsedVuln, ParsedWebAddress)
from ..models import (Credential, Implant, Project, Service, Target, User,
                      Vuln, WebAddress, implies_alive, ImportJob)
from ..scopegate import index_for
from ..weburl import BadUrl, merge_sources
from ..weburl import parse as parse_url
from ..weburl import exchange_key, url_key
from .. import slack
from ..security import get_current_user, require_project
from ..db import SessionLocal
from ..importers import jobs as import_jobs
from ..timeline import record

router = APIRouter(prefix="/api/scans", tags=["scans"])

#: Ceiling for a format that has to be parsed as one document.
MAX_BYTES = 64 * 1024 * 1024

#: Ceiling for a streamed upload. Not a memory limit -- streaming holds
#: a few hundred MB regardless of file size -- just a backstop against
#: filling the disk with a spooled temp file.
HARD_MAX_BYTES = 16 * 1024 * 1024 * 1024


def _decisions_from(raw: str) -> dict:
    """Parse the `decisions` query parameter of an upload.

    It rides in the query string rather than the body because the body
    is the file. Bad JSON is rejected rather than ignored: silently
    treating it as "no decisions" would reject every unknown host and
    look like a successful import that dropped most of the data.
    """
    if not (raw or "").strip():
        return {}
    try:
        obj = json.loads(raw)
    except ValueError as e:
        raise HTTPException(422, f"decisions is not valid JSON: {e}")
    if not isinstance(obj, dict):
        raise HTTPException(422, "decisions must be a JSON object")
    try:
        return {k: HostDecision(**v) if isinstance(v, dict) else HostDecision(action=v)
                for k, v in obj.items()}
    except Exception as e:
        raise HTTPException(422, f"decisions entry is not usable: {e}")


class UnknownHostOut(BaseModel):
    host: str
    ip: str | None = None
    services: int = 0
    web: int = 0
    vulns: int = 0
    credentials: int = 0
    implants: int = 0
    notes: int = 0
    total: int = 0


class ImportResult(BaseModel):
    project: str
    format: str
    tool: str
    command: str | None = None
    hosts_seen: int = 0
    targets_created: int = 0
    targets_updated: int = 0
    services_created: int = 0
    services_updated: int = 0
    services_unknown: int = Field(
        0, description="Open ports whose service could not be identified")
    vulns_created: int = 0
    vulns_updated: int = 0
    credentials_created: int = 0
    implants_created: int = 0
    implants_updated: int = 0
    urls_created: int = 0
    urls_updated: int = 0
    hosts_flagged: int = Field(0, description="Targets newly marked compromised")
    scripts_captured: int = 0
    notes_recorded: int = 0
    errors: list[str] = []
    #: Set when strict mode found hosts the project does not have. Nothing
    #: was written; the caller decides and posts again.
    needs_decision: bool = False
    #: Names the uploaded file, kept server-side while the caller decides.
    #: Send it to /api/scans/import/resume instead of uploading again.
    upload_id: str | None = None
    #: Set when the import was queued instead of run inline. Nothing is
    #: written yet; poll /api/scans/import/jobs/{job_id}.
    job_id: int | None = None
    unknown_hosts: list[UnknownHostOut] = []
    #: Hosts whose rows were dropped because nobody asked for them.
    rejected_hosts: dict[str, int] = {}
    #: host -> why the project's scope refused it. A different answer
    #: from `rejected_hosts`: nobody asked for those, while these were
    #: asked for and are not permitted. Named individually, because "14
    #: hosts were out of scope" is not something an operator can check.
    barred_hosts: dict[str, str] = {}
    #: host -> the existing target its data was attached to.
    mapped_hosts: dict[str, str] = {}
    created_hosts: list[str] = []


class HostDecision(BaseModel):
    action: str = Field(description="add | map | reject")
    target: str | None = Field(
        None, description="For 'map', the existing target to attach the data to")


class ImportBody(BaseModel):
    content: str = Field(description="The report text: XML, JSON or JSONL")
    format: str = Field("auto", description="Tool name, or 'auto' to detect")
    mode: str = Field(
        "strict",
        description="strict: write only for hosts the project already has, and "
                    "report the rest for a decision. open: create whatever the "
                    "file names.")
    decisions: dict[str, HostDecision] = Field(
        default_factory=dict,
        description="Answers for the hosts a previous strict attempt reported. "
                    "A host left out is rejected, not created.")


class FormatOut(BaseModel):
    name: str
    label: str


def _j(v) -> str | None:
    return json.dumps(v) if v else None


# --------------------------------------------------------------- services
async def _service(session: AsyncSession, target: Target, ps: ParsedService,
                   res: ImportResult) -> list[str]:
    row = (await session.execute(
        select(Service).where(Service.target_id == target.id,
                              Service.port == ps.port,
                              Service.protocol == ps.protocol))).scalar_one_or_none()
    fields = dict(
        state=ps.state, name=ps.name, product=ps.product, version=ps.version,
        extrainfo=ps.extrainfo, tunnel=ps.tunnel, method=ps.method,
        confidence=ps.confidence, reason=ps.reason,
        cpe=_j(ps.cpe), scripts=_j(ps.scripts), banner=ps.banner or None,
    )
    res.scripts_captured += len(ps.scripts)
    if ps.state == "open" and ps.name == "UNKNOWN":
        res.services_unknown += 1
    # A service that answered is proof the host is up, whatever the host
    # record says. Scanners routinely report ports without ever setting a
    # liveness flag — the Faraday import left 1,185 hosts marked "never
    # probed" while carrying 1,509 of their services.
    if implies_alive(ps.state) and target.alive is not True:
        target.alive = True

    if row is None:
        session.add(Service(target_id=target.id, port=ps.port,
                            protocol=ps.protocol, **fields))
        res.services_created += 1
        label = f"{ps.port}/{ps.protocol} {ps.name}"
        return [f"found {label}" + (f" — {ps.banner}" if ps.banner else "")]

    changes = []
    for key, new in fields.items():
        old = getattr(row, key)
        # A tool that did not look at this field must not erase what another
        # one found: masscan reporting a port says nothing about its banner.
        if new is None and old is not None:
            continue
        if key == "name" and new == "UNKNOWN" and old not in (None, "", "UNKNOWN"):
            continue
        if old != new:
            if key in ("state", "name", "version", "banner"):
                changes.append(f"{ps.port}/{ps.protocol} {key}: {old or 'none'} → {new}")
            setattr(row, key, new)
    if changes:
        res.services_updated += 1
    return changes


# ----------------------------------------------------------------- hosts
async def _host(session: AsyncSession, project: Project, ph: ParsedHost,
                scan: ParsedScan, res: ImportResult, source: str,
                policy: Policy) -> Target | None:
    # The policy decides whether this host may be written at all, and
    # whether its data belongs on a different target entirely. The
    # address goes with the name: a scope document written as ranges can
    # only recognise `web01.acme.example` by the address the scan found
    # it at.
    allowed = policy.resolve(ph.host, ph.ip_address or ph.ipv6_address)
    if allowed is None:
        return None
    try:
        host = normalise_host(allowed)
    except InvalidHost as e:
        res.errors.append(f"{ph.host!r}: {e}")
        return None

    target = (await session.execute(
        select(Target).where(Target.project_id == project.id,
                             Target.host == host))).scalar_one_or_none()
    fields = dict(
        ip_address=ph.ip_address or ph.ipv6_address,
        alive=ph.alive, os=ph.os, os_accuracy=ph.os_accuracy,
        mac_address=ph.mac_address, mac_vendor=ph.mac_vendor,
        hostnames=_j(ph.hostnames), extra=_j(ph.extra),
    )
    actor = scan.tool

    if target is None:
        target = Target(project_id=project.id, host=host,
                        notes=ph.notes, hacked=bool(ph.hacked), **fields)
        session.add(target)
        await session.flush()
        res.targets_created += 1
        if ph.hacked:
            res.hosts_flagged += 1
        await record(session, target.id, "discovered",
                     f"discovered by {scan.label}"
                     + (f" as {ph.ip_address}" if ph.ip_address else ""),
                     detail=scan.args, actor=actor, source=source)
    else:
        changed = []
        for key, new in fields.items():
            old = getattr(target, key)
            if new is None and old is not None:
                continue
            if old != new:
                if key in ("ip_address", "alive", "os"):
                    changed.append(f"{key}: {old if old is not None else 'none'} → {new}")
                setattr(target, key, new)
        # Compromise is one-way here. Losing a beacon, or a later scan that
        # saw nothing, is not evidence the access is gone.
        if ph.hacked and not target.hacked:
            target.hacked = True
            res.hosts_flagged += 1
            changed.append("hacked: no → yes")
        if changed:
            res.targets_updated += 1
            await record(session, target.id, "change", "; ".join(changed),
                         actor=actor, source=source)

    if ph.os:
        acc = f" ({ph.os_accuracy}% confidence)" if ph.os_accuracy else ""
        await record(session, target.id, "scan", f"OS fingerprint: {ph.os}{acc}",
                     detail=json.dumps(ph.extra.get("os_matches"), indent=2)
                     if ph.extra.get("os_matches") else None,
                     actor=actor, source=source)

    svc_changes: list[str] = []
    for ps in ph.services:
        svc_changes += await _service(session, target, ps, res)
        if ps.scripts:
            await record(
                session, target.id, "scan",
                f"NSE on {ps.port}/{ps.protocol}: {', '.join(sorted(ps.scripts))}",
                detail="\n\n".join(f"--- {k} ---\n{v}"
                                   for k, v in sorted(ps.scripts.items())),
                actor=actor, source=source)

    if hostscripts := ph.extra.get("hostscripts"):
        await record(session, target.id, "scan",
                     f"host NSE: {', '.join(sorted(hostscripts))}",
                     detail="\n\n".join(f"--- {k} ---\n{v}"
                                        for k, v in sorted(hostscripts.items())),
                     actor=actor, source=source)

    if svc_changes:
        opened = len([c for c in svc_changes if c.startswith("found ")])
        head = (f"{scan.label}: {opened} service(s) found" if opened
                else f"{scan.label}: service details changed")
        await record(session, target.id, "service", head,
                     detail="\n".join(svc_changes), actor=actor, source=source)
    return target


# ----------------------------------------------------------------- vulns
async def _vuln(session: AsyncSession, target: Target, pv: ParsedVuln,
                scan: ParsedScan, res: ImportResult, source: str,
                announce: list | None = None) -> None:
    row = None
    if pv.external_id:
        row = (await session.execute(
            select(Vuln).where(Vuln.target_id == target.id,
                               Vuln.external_id == pv.external_id))).scalar_one_or_none()
    if row is None:
        row = (await session.execute(
            select(Vuln).where(Vuln.target_id == target.id,
                               Vuln.title == pv.title,
                               Vuln.port == pv.port))).scalar_one_or_none()
    if row is None:
        session.add(Vuln(target_id=target.id, title=pv.title[:1000],
                         severity=pv.severity, status=pv.status,
                         port=pv.port, protocol=pv.protocol,
                         description=pv.description, remediation=pv.remediation,
                         external_id=pv.external_id))
        res.vulns_created += 1
        # Findings are one of only two things that reach Slack. Gathered
        # here and posted after the commit: a finding announced and then
        # rolled back is worse than one announced late.
        if announce is not None:
            announce.append((pv.severity, target.host, pv.title, pv.port,
                             pv.protocol, pv.description))
        await record(session, target.id, "vuln",
                     f"{pv.severity.upper()}: {pv.title}"[:400],
                     detail=pv.description, actor=scan.tool, source=source)
        return
    changed = []
    if row.severity != pv.severity:
        changed.append(f"severity: {row.severity} → {pv.severity}")
        row.severity = pv.severity
    if pv.description and row.description != pv.description:
        changed.append("description updated")
        row.description = pv.description
    if pv.remediation and row.remediation != pv.remediation:
        changed.append("remediation updated")
        row.remediation = pv.remediation
    if changed:
        res.vulns_updated += 1
        await record(session, target.id, "vuln", f"{pv.title}: {'; '.join(changed)}"[:400],
                     actor=scan.tool, source=source)


# ------------------------------------------------------------ credentials
async def _credential(session: AsyncSession, project: Project,
                      pc: ParsedCredential, target: Target | None,
                      scan: ParsedScan, res: ImportResult, source: str) -> None:
    if not (pc.username or pc.secret):
        return
    dup = (await session.execute(
        select(Credential).where(Credential.project_id == project.id,
                                 Credential.host == pc.host,
                                 Credential.username == pc.username,
                                 Credential.secret == pc.secret))).scalar_one_or_none()
    if dup is not None:
        return
    session.add(Credential(
        project_id=project.id, host=pc.host, service=pc.service, port=pc.port,
        username=pc.username, secret=pc.secret, kind=pc.kind,
        source=pc.source or f"{scan.label} import", validated=pc.validated,
        notes=pc.notes))
    res.credentials_created += 1
    if target is not None:
        await record(session, target.id, "credential",
                     f"credential for {pc.username or '(no user)'}"
                     + (f" on {pc.service}" if pc.service else ""),
                     actor=scan.tool, source=source)


# --------------------------------------------------------------- implants
async def _implant(session: AsyncSession, target: Target, pi: ParsedImplant,
                   scan: ParsedScan, res: ImportResult, source: str) -> None:
    # A framework that gave us no id still needs a stable key, or every
    # export would insert the same callback again.
    ident = pi.implant_id or f"{pi.process or 'agent'}:{pi.pid or 'nopid'}"
    row = (await session.execute(
        select(Implant).where(Implant.target_id == target.id,
                              Implant.framework == pi.framework,
                              Implant.implant_id == ident))).scalar_one_or_none()
    fields = dict(
        listener=pi.listener, user=pi.user, domain=pi.domain, process=pi.process,
        pid=pi.pid, arch=pi.arch, integrity=pi.integrity,
        internal_ip=pi.internal_ip, external_ip=pi.external_ip, os=pi.os,
        first_seen=pi.first_seen, last_seen=pi.last_seen, active=pi.active,
        note=pi.note, extra=_j(pi.extra),
    )
    who = " as " + (f"{pi.domain}\\{pi.user}" if pi.domain and pi.user
                    else pi.user) if pi.user else ""
    integ = f" ({pi.integrity})" if pi.integrity else ""

    if row is None:
        session.add(Implant(target_id=target.id, framework=pi.framework,
                            implant_id=ident, **fields))
        res.implants_created += 1
        await record(session, target.id, "implant",
                     f"{pi.framework} callback {ident}{who}{integ}",
                     detail="\n".join(f"{k}: {v}" for k, v in [
                         ("listener", pi.listener), ("process", pi.process),
                         ("pid", pi.pid), ("arch", pi.arch), ("os", pi.os),
                         ("internal", pi.internal_ip), ("external", pi.external_ip),
                         ("first seen", pi.first_seen), ("last seen", pi.last_seen),
                     ] if v) or None,
                     actor=pi.framework, source=source)
        return

    changed = []
    for key, new in fields.items():
        old = getattr(row, key)
        if new is None and old is not None:
            continue
        if old != new:
            if key in ("user", "integrity", "active", "last_seen"):
                changed.append(f"{key}: {old if old is not None else 'none'} → {new}")
            setattr(row, key, new)
    if changed:
        res.implants_updated += 1
        await record(session, target.id, "implant",
                     f"{pi.framework} {ident}: {'; '.join(str(c) for c in changed)}"[:400],
                     actor=pi.framework, source=source)


# ------------------------------------------------------------ web addresses
async def _weburl(session: AsyncSession, target: Target, pw: ParsedWebAddress,
                  scan: ParsedScan, res: ImportResult) -> str | None:
    try:
        u = parse_url(pw.url, base_host=pw.host or target.host,
                      base_scheme=pw.scheme, base_port=pw.port)
    except BadUrl as e:
        res.errors.append(str(e))
        return None

    svc = (await session.execute(
        select(Service).where(Service.target_id == target.id,
                              Service.port == u.port,
                              Service.protocol == "tcp"))).scalar_one_or_none()
    method = (pw.method or "").upper()[:12]
    xk = exchange_key(method, u.url, pw.request, pw.response)

    # Identity is the EXCHANGE, not the address: the same endpoint hit
    # ten different ways is ten pieces of evidence, and the differences
    # between the responses are usually the finding. Keying on the URL
    # alone kept only the last one.
    row = (await session.execute(
        select(WebAddress).where(WebAddress.target_id == target.id,
                                 WebAddress.exchange_hash == xk))).scalar_one_or_none()

    if row is None and (pw.request or pw.response):
        # A tool that reports no traffic (httpx, nuclei) leaves a row
        # with the URL and nothing else. The first capture for that URL
        # fills it in rather than sitting beside it as a near-duplicate;
        # later captures are their own rows.
        row = (await session.execute(
            select(WebAddress).where(
                WebAddress.target_id == target.id,
                WebAddress.url_hash == url_key(u.url),
                WebAddress.request.is_(None),
                WebAddress.response.is_(None),
                WebAddress.method.in_(("", method))))).scalars().first()
        if row is not None:
            row.method = method or row.method
            row.request = pw.request
            row.response = pw.response
            row.exchange_hash = xk

    if row is None:
        session.add(WebAddress(
            target_id=target.id, service_id=svc.id if svc else None,
            url=u.url, url_hash=url_key(u.url), exchange_hash=xk,
            scheme=u.scheme, port=u.port, path=u.path,
            method=method, status_code=pw.status_code, title=pw.title,
            content_type=pw.content_type, content_length=pw.content_length,
            webserver=pw.webserver, tech=_j(pw.tech),
            sources=scan.tool, crawled=pw.crawled, notes=pw.notes,
            request=pw.request, response=pw.response,
            truncated=bool(pw.truncated)))
        res.urls_created += 1
        return u.url
    changed = False
    for key, new in (("status_code", pw.status_code), ("title", pw.title),
                     ("content_type", pw.content_type),
                     ("content_length", pw.content_length),
                     ("webserver", pw.webserver),
                     # A later import that carries the exchange fills in
                     # what an earlier metadata-only one could not.
                     ("request", pw.request), ("response", pw.response)):
        if new is not None and getattr(row, key) != new:
            setattr(row, key, new)
            changed = True
    if pw.tech and not row.tech:
        row.tech = _j(pw.tech)
        changed = True
    if pw.truncated and not row.truncated:
        row.truncated = True
    # Two tools agreeing is worth recording; it is also the only way to
    # tell a guessed path from one something actually fetched.
    before = row.sources
    row.sources = merge_sources(row.sources, scan.tool)
    if pw.crawled and not row.crawled:
        row.crawled = True
        changed = True
    if row.sources != before:
        changed = True
    if svc and row.service_id is None:
        row.service_id = svc.id
    if changed:
        res.urls_updated += 1
    return None


# ---------------------------------------------------------------- ingest
async def ingest(session: AsyncSession, project: Project, scan: ParsedScan,
                 fmt: str, source: str, policy: Policy) -> ImportResult:
    #: (severity, host, title, port, protocol, detail) for each finding
    #: this import creates, posted to Slack once the write succeeds.
    new_findings: list = []
    res = ImportResult(project=project.code, format=fmt, tool=scan.label,
                       command=scan.args, hosts_seen=len(scan.hosts),
                       errors=list(scan.errors))

    targets: dict[str, Target] = {}
    for ph in scan.hosts:
        t = await _host(session, project, ph, scan, res, source, policy)
        if t is not None:
            # Keyed on the name as the FILE spelled it, so children that
            # reference it resolve — even when it was mapped elsewhere.
            targets[ph.host.strip().rstrip(".").lower()] = t

    async def resolve(name: str | None) -> Target | None:
        """Children name their host as a string; attach them to its row.

        A child whose host never appeared as a host record still deserves a
        target — a credential found for a box nobody scanned is exactly the
        kind of thing that must not be dropped on the floor. In strict mode
        the policy still gets the final say.
        """
        if not name:
            return None
        key = name.strip().rstrip(".").lower()
        if key in targets:
            return targets[key]
        t = await _host(session, project, ParsedHost(host=name), scan, res,
                        source, policy)
        if t is not None:
            targets[key] = t
        return t

    for pv in scan.vulns:
        t = await resolve(pv.host)
        if t is not None:
            await _vuln(session, t, pv, scan, res, source, new_findings)

    for pc in scan.credentials:
        t = await resolve(pc.host) if pc.host else None
        await _credential(session, project, pc, t, scan, res, source)

    for pi in scan.implants:
        t = await resolve(pi.host)
        if t is not None:
            await _implant(session, t, pi, scan, res, source)

    web_by_host: dict[str, list[str]] = {}
    for pw in scan.web:
        t = await resolve(pw.host) if pw.host else None
        if t is None:
            continue
        found = await _weburl(session, t, pw, scan, res)
        if found:
            web_by_host.setdefault(t.host, []).append(found)
    for hostname, urls in web_by_host.items():
        t = targets.get(hostname)
        if t is not None:
            await record(session, t.id, "web",
                         f"{scan.label}: {len(urls)} web address(es) found",
                         detail="\n".join(sorted(urls)[:200]),
                         actor=scan.tool, source=source)

    for pn in scan.notes:
        t = await resolve(pn.host)
        if t is not None:
            await record(session, t.id, pn.kind, pn.summary, detail=pn.detail,
                         actor=scan.tool, source=source)
            res.notes_recorded += 1

    res.rejected_hosts = dict(policy.rejected)
    res.barred_hosts = dict(policy.barred)
    res.mapped_hosts = dict(policy.mapped)
    res.created_hosts = list(policy.created)
    await session.commit()
    for ch in ("targets", "services", "vulns", "credentials", "web"):
        await broker.publish(ch, action="import", project=project.code)

    # After the commit, so nothing is announced that did not land. An
    # import of a large scan can create thousands of findings and
    # posting all of them would make the channel useless — and Slack
    # would rate-limit it anyway — so only the ones worth waking
    # someone for go out, and the rest are summarised.
    await _announce_findings(session, project, new_findings)
    return res


#: Severities that reach Slack from a bulk import. An import is not a
#: person triaging; it is a tool producing hundreds of INFO records,
#: and a channel that receives them stops being read.
ANNOUNCE_AT = ("critical", "high")
#: Beyond this, the channel gets a count instead of the findings.
ANNOUNCE_CAP = 10


async def _announce_findings(session, project, findings: list) -> None:
    worth = [f for f in findings if (f[0] or "").lower() in ANNOUNCE_AT]
    if not worth:
        return
    for sev, host, title, port, proto, detail in worth[:ANNOUNCE_CAP]:
        await slack.announce_finding(session, project, severity=sev, host=host,
                                     title=title, port=port, protocol=proto,
                                     detail=detail)
    if len(worth) > ANNOUNCE_CAP:
        await slack.announce(
            session, project,
            f":warning: …and {len(worth) - ANNOUNCE_CAP} more "
            f"{'/'.join(ANNOUNCE_AT)} findings from this import. See Oddjob.")


async def _known(session: AsyncSession, project: Project) -> set[str]:
    return {h for (h,) in (await session.execute(
        select(Target.host).where(Target.project_id == project.id))).all()}


#: Counters that simply add up when a streamed import is assembled from
#: many chunks. Derived from the model so a new counter cannot be added
#: and silently left out of the total, which is how a streamed import
#: starts under-reporting what it wrote.
_SUM_FIELDS = tuple(
    n for n, f in ImportResult.model_fields.items()
    if f.annotation is int and n != "hosts_seen")


def _merge(agg: ImportResult, part: ImportResult) -> None:
    for n in _SUM_FIELDS:
        setattr(agg, n, getattr(agg, n) + getattr(part, n))
    for e in part.errors:
        if e not in agg.errors:
            agg.errors.append(e)
    agg.mapped_hosts.update(part.mapped_hosts)
    agg.barred_hosts.update(part.barred_hosts)
    for h, c in part.rejected_hosts.items():
        agg.rejected_hosts[h] = agg.rejected_hosts.get(h, 0) + c


async def _run_stream(session: AsyncSession, project: Project, path: str,
                      detected: str, source: str, mode: str,
                      decisions: dict | None,
                      on_progress=None) -> ImportResult:
    """Import a file too large to hold in memory, a chunk at a time.

    Used for the formats in `importers.STREAMABLE`. The shape is the
    same as `_run`, with two differences forced by the size:

    * The strict-mode survey comes from the importer's cheap host pass
      rather than from a parsed scan, because building the scan just to
      ask the question would decode every body in the file for nothing.
    * Each chunk is committed as it is written. A single transaction
      across a 2.5 GB file would hold a write lock for the whole import
      and lose everything on one bad record near the end. The trade is
      real and worth naming: an import that fails halfway leaves the
      first half imported, and the counts returned say how far it got.
    """
    stream, hosts_fn = importers.streamer(detected)
    known = await _known(session, project)
    policy = Policy(mode=("open" if mode == "open" else "strict"),
                    known=set(known),
                    scope=await index_for(session, project.id),
                    decisions={k.strip().rstrip(".").lower():
                               Decision(action=v.action, target=v.target)
                               for k, v in (decisions or {}).items()})

    if policy.mode == "strict":
        try:
            counts = hosts_fn(path)
        except ImportError_ as e:
            raise HTTPException(422, str(e))
        # A host scope will refuse is not offered as a decision; see
        # policy.survey for why asking about one is worse than not.
        unknown = [UnknownHostOut(host=h, web=c, total=c)
                   for h, c in sorted(counts.items(), key=lambda kv: -kv[1])
                   if h not in known and policy.scope_allows_new(h)]
        if [u for u in unknown if u.host not in policy.decisions]:
            return ImportResult(
                project=project.code, format=detected, tool="burp-history",
                hosts_seen=len(counts), needs_decision=True,
                unknown_hosts=unknown, barred_hosts=dict(policy.barred))

    agg = ImportResult(project=project.code, format=detected, tool=detected)
    seen: set[str] = set()
    # A commit expires every ORM object the session is holding, so the
    # next chunk touches an expired `project` and SQLAlchemy tries to
    # reload it from a non-async context -- MissingGreenlet, which is
    # what killed the second attempt at this import after ~450 rows.
    # Committing many times is the entire point here, so expiry is
    # turned off for the duration: the only object that outlives a chunk
    # is `project`, and nothing in this path mutates it.
    was_expiring = session.sync_session.expire_on_commit
    session.sync_session.expire_on_commit = False
    try:
        for part_scan in stream(path):
            seen.update(h.host for h in part_scan.hosts)
            agg.tool = part_scan.label or agg.tool
            part = await _write_chunk(session, project, part_scan, detected,
                                      f"{detected}:{source}", policy)
            _merge(agg, part)
            if on_progress is not None:
                await on_progress(agg.urls_created + agg.urls_updated, len(seen))
    except ImportError_ as e:
        raise HTTPException(422, str(e))
    finally:
        session.sync_session.expire_on_commit = was_expiring
    agg.hosts_seen = len(seen)
    # The survey above refuses hosts before the first chunk is read, so
    # those reasons are not in any part result. Carried over here, or a
    # streamed import would silently drop the one thing it most needs to
    # say.
    agg.barred_hosts.update(policy.barred)
    return agg


#: How many times a chunk is retried when SQLite reports the database
#: locked, and the backoff between attempts.
_LOCK_TRIES = 6
_LOCK_BACKOFF = 0.25


async def _write_chunk(session: AsyncSession, project: Project, scan,
                       detected: str, source: str, policy: Policy
                       ) -> ImportResult:
    """Ingest and commit one chunk, retrying while the database is locked.

    SQLite takes one writer at a time. The agent's remediation worker is
    a second one, and it is what broke the first full-size import of the
    2.5 GB history: a chunk commit lost the race, `busy_timeout` ran out
    and the whole upload died with a 500 after about 6,000 rows.

    Retrying is safe because ingest is an upsert keyed on
    (target, url, method) -- replaying a chunk that half-applied
    converges on the same rows rather than duplicating them.
    """
    delay = _LOCK_BACKOFF
    for attempt in range(_LOCK_TRIES):
        try:
            part = await ingest(session, project, scan, detected, source, policy)
            await session.commit()
            return part
        except OperationalError as e:
            if "locked" not in str(e).lower() and "busy" not in str(e).lower():
                raise
            await session.rollback()
            # A rollback expires every loaded object, `project` included,
            # so the retry's first touch of `project.code` would try to
            # reload it from sync context and raise MissingGreenlet --
            # turning a recoverable lock into a 500. Reload it here,
            # inside async context, before trying again.
            with contextlib.suppress(Exception):
                await session.refresh(project)
            if attempt == _LOCK_TRIES - 1:
                raise HTTPException(
                    503,
                    f"the database stayed locked by another writer through "
                    f"{_LOCK_TRIES} attempts. Anything imported before this "
                    f"point is committed; re-running the import will resume "
                    f"rather than duplicate.")
            await asyncio.sleep(delay)
            delay *= 2
    raise AssertionError("unreachable")


async def _run(session: AsyncSession, project: Project, text: str, fmt: str,
               source: str, mode: str = "strict",
               decisions: dict | None = None) -> ImportResult:
    try:
        detected, scan = importers.parse(text, fmt)
    except ImportError_ as e:
        raise HTTPException(422, str(e))

    known = await _known(session, project)
    policy = Policy(mode=("open" if mode == "open" else "strict"), known=set(known),
                    scope=await index_for(session, project.id),
                    decisions={k.strip().rstrip(".").lower():
                               Decision(action=v.action, target=v.target)
                               for k, v in (decisions or {}).items()})

    if policy.mode == "strict":
        unknown = survey(scan, known, policy)
        undecided = [u for u in unknown
                     if u.host not in policy.decisions]
        if undecided:
            # Nothing is written. The caller shows the list, collects an
            # answer for each, and posts the same file again.
            return ImportResult(
                project=project.code, format=detected, tool=scan.label,
                command=scan.args, hosts_seen=len(scan.hosts),
                needs_decision=True,
                unknown_hosts=[UnknownHostOut(**{**u.__dict__, "total": u.total})
                               for u in unknown],
                barred_hosts=dict(policy.barred),
                errors=list(scan.errors))

    return await ingest(session, project, scan, detected,
                        f"{detected}:{source}", policy)



# ------------------------------------------------- held uploads
#: A strict-mode upload that is waiting for the operator to say what to
#: do about its unknown hosts. The spooled file is kept so answering the
#: question does not mean sending it again -- for a 2.5 GB proxy history
#: that second upload is most of the cost, and the browser has to hold
#: the File handle open across the whole decision to manage it.
#:
#: In-process and deliberately so: it is a scratch file belonging to one
#: upload, and surviving a restart is not worth a table. A restart drops
#: them, and the UI falls back to re-uploading.
class _Held:
    __slots__ = ("path", "project_id", "user_id", "fmt", "name", "size", "at")

    def __init__(self, path, project_id, user_id, fmt, name, size):
        self.path = path
        self.project_id = project_id
        self.user_id = user_id
        self.fmt = fmt
        self.name = name
        self.size = size
        self.at = time.time()


_HELD: dict[str, _Held] = {}

#: How long a held upload survives unanswered. Long enough to work
#: through several hundred hosts, short enough that an abandoned 2.5 GB
#: file is not left on disk indefinitely.
HELD_TTL = 60 * 60


#: Prefix for the spooled upload files, so orphans are identifiable.
HELD_PREFIX = "oddjob-import-"


def sweep_orphan_uploads() -> int:
    """Delete spooled upload files left by a previous process.

    The `finally` that removes a temp file does not run when the process
    is killed, and a held file is deliberately kept past the request. A
    2.5 GB history abandoned that way sits in the temp directory until
    someone notices -- one did, after an interrupted import. Called at
    startup, when by definition nothing is held in memory.
    """
    removed = 0
    with contextlib.suppress(OSError):
        for name in os.listdir(tempfile.gettempdir()):
            if not name.startswith(HELD_PREFIX):
                continue
            path = os.path.join(tempfile.gettempdir(), name)
            with contextlib.suppress(OSError):
                os.unlink(path)
                removed += 1
    return removed


def _reap_held() -> None:
    for key, h in list(_HELD.items()):
        if time.time() - h.at > HELD_TTL:
            _HELD.pop(key, None)
            with contextlib.suppress(OSError):
                os.unlink(h.path)


def _drop_held(key: str) -> None:
    h = _HELD.pop(key, None)
    if h is not None:
        with contextlib.suppress(OSError):
            os.unlink(h.path)


def _hold(path, project, user, fmt, name, size) -> str:
    """Keep `path` for a follow-up call. -> the token naming it."""
    _reap_held()
    key = secrets.token_urlsafe(24)
    _HELD[key] = _Held(path, project.id, user.id, fmt, name, size)
    return key


def _take_held(key: str, project: Project, user: User) -> _Held:
    """The held upload for `key`, or a 404/403.

    Bound to the user who uploaded it and the project it was uploaded
    for: the token is the only thing naming a file full of someone's
    proxy history, so it is not enough on its own.
    """
    _reap_held()
    h = _HELD.get(key or "")
    if h is None:
        raise HTTPException(
            404, "that upload is no longer held — it expired or the server "
                 "restarted. Upload the file again.")
    if h.user_id != user.id or h.project_id != project.id:
        raise HTTPException(403, "that upload belongs to someone else")
    if not os.path.exists(h.path):
        _HELD.pop(key, None)
        raise HTTPException(404, "the held file is gone; upload it again")
    return h


# ----------------------------------------------------------------- routes
@router.get("/formats", response_model=list[FormatOut])
async def formats(_: User = Depends(get_current_user)):
    """What can be imported. The UI builds its picker from this."""
    return [FormatOut(name=k, label=v[0]) for k, v in importers.REGISTRY.items()]


@router.post("/import", response_model=ImportResult)
async def import_report(body: ImportBody,
                        project: Project = Depends(require_project("user")),
                        _: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Import any supported report, detecting the format when not told.

    Targets, services, findings, credentials and C2 callbacks all land in
    one pass, and every change is written to the target's timeline. An open
    port whose service could not be identified is recorded as UNKNOWN.
    """
    return await _run(session, project, body.content, body.format, "inline",
                      mode=body.mode, decisions=body.decisions)


@router.post("/import/upload", response_model=ImportResult)
async def upload_report(file: UploadFile = File(...),
                        format: str = Query("auto"),
                        mode: str = Query("strict"),
                        decisions_json: str = Query(
                            "", alias="decisions",
                            description="JSON object of host -> {action, target}, "
                                        "answering a previous strict-mode survey"),
                        project: Project = Depends(require_project("user")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Same, as a file upload.

    The body is spooled to disk in fixed-size blocks and never held whole
    in memory. `await file.read()`, which this did before, would need as
    much RAM as the file is big -- a 2.5 GB Burp history took the process
    down rather than importing.

    From there the format decides the route: one in `importers.STREAMABLE`
    is read from the file a chunk at a time with no size limit, and
    anything else is loaded as text under `MAX_BYTES`.
    """
    decisions = _decisions_from(decisions_json)
    _reap_held()
    tmp = tempfile.NamedTemporaryFile(prefix=HELD_PREFIX, delete=False)
    keep = False
    size = 0
    try:
        while buf := await file.read(1024 * 1024):
            size += len(buf)
            if size > HARD_MAX_BYTES:
                raise HTTPException(
                    413, f"file exceeds {HARD_MAX_BYTES // (1024**3)} GB")
            tmp.write(buf)
        tmp.close()
        if not size:
            raise HTTPException(422, "the uploaded file was empty")

        if format in ("", "auto", None):
            detected = importers.detect_file(tmp.name)
            if not detected:
                raise HTTPException(422, importers.unknown_format_message())
        else:
            detected = format
        if detected not in importers.REGISTRY:
            raise HTTPException(422, f"unknown format {detected!r}")

        name = file.filename or "upload"
        # Announced before the work, not after: a 2.5 GB import runs for
        # a long time and "started" is the message that explains why the
        # numbers are moving.
        await slack.announce(session, project, slack.import_started(detected, name))

        res = await _from_file(session, project, tmp.name, detected,
                               name, mode, decisions, size)
        if not res.needs_decision:
            # Only when something was actually written. A strict-mode
            # survey writes nothing and is not a completed import.
            await slack.announce(session, project, slack.import_completed(
                detected, name,
                f"(+{res.targets_created} targets, +{res.services_created} "
                f"services, +{res.vulns_created} findings)"))
        if res.needs_decision:
            # Hold the file rather than making the browser send it twice.
            keep = True
            res.upload_id = _hold(tmp.name, project, user, detected,
                                  file.filename or "upload", size)
        return res
    finally:
        tmp.close()
        if not keep:
            with contextlib.suppress(OSError):
                os.unlink(tmp.name)


async def _from_file(session: AsyncSession, project: Project, path: str,
                     detected: str, name: str, mode: str, decisions: dict,
                     size: int, on_progress=None) -> ImportResult:
    """Run an import from a file on disk, streaming it where we can."""
    if importers.streamer(detected):
        return await _run_stream(session, project, path, detected,
                                 name, mode, decisions, on_progress)
    if size > MAX_BYTES:
        raise HTTPException(
            413,
            f"a {detected} report has to be read whole, and this one is "
            f"{size // (1024*1024)} MB against a {MAX_BYTES // (1024*1024)} MB "
            f"limit. Streaming is supported for: "
            f"{', '.join(importers.STREAMABLE)}.")
    text = Path(path).read_bytes().decode("utf-8", errors="replace")
    return await _run(session, project, text, detected, name,
                      mode=mode, decisions=decisions)


class ImportJobOut(BaseModel):
    id: int
    project: str
    filename: str
    format: str
    status: str
    rows_done: int = 0
    rows_total: int | None = None
    hosts_seen: int = 0
    error: str | None = None
    result: dict | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime | None = None

    @staticmethod
    def of(row: ImportJob, code: str) -> "ImportJobOut":
        return ImportJobOut(
            id=row.id, project=code, filename=row.filename, format=row.fmt,
            status=row.status, rows_done=row.rows_done,
            rows_total=row.rows_total, hosts_seen=row.hosts_seen,
            error=row.error,
            result=json.loads(row.result) if row.result else None,
            started_at=row.started_at, finished_at=row.finished_at,
            created_at=row.created_at)


class ResumeBody(BaseModel):
    upload_id: str = Field(description="From a strict-mode import's result")
    decisions: dict[str, HostDecision] = Field(
        default_factory=dict,
        description="Answers for the hosts the survey reported. A host left "
                    "out is rejected, not created.")
    mode: str = Field("strict", description="strict or open")
    background: bool = Field(
        False,
        description="Queue it and return immediately. The import then "
                    "survives navigating away; poll /api/scans/import/jobs.")


@router.post("/import/resume", response_model=ImportResult)
async def resume_import(body: ResumeBody,
                        project: Project = Depends(require_project("user")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Finish an import whose file the server is still holding.

    The strict-mode survey answers "which hosts in this file are new?"
    and writes nothing. Answering it used to mean uploading the whole
    file a second time -- for the 2.5 GB history that is another
    multi-gigabyte POST to import data the server has already read once.

    The file from that first upload is kept for `HELD_TTL`, and this
    runs the import straight off it. It is consumed either way: a
    success or a failure both release the disk, and a caller that wants
    to try different decisions uploads again.
    """
    h = _take_held(body.upload_id, project, user)

    if body.background:
        # Queue it. The response is the job, not the import: the point
        # is that the caller can close the tab.
        job = ImportJob(project_id=project.id, requested_by=user.id,
                        filename=h.name, fmt=h.fmt, mode=body.mode,
                        status="queued",
                        rows_total=_expected_rows(h))
        session.add(job)
        await session.commit()
        await session.refresh(job)
        _JOB_WORK[job.id] = (body.upload_id, dict(body.decisions), body.mode)
        import_jobs.schedule(job.id)
        return ImportResult(project=project.code, format=h.fmt, tool=h.fmt,
                            job_id=job.id, upload_id=body.upload_id)

    try:
        res = await _from_file(session, project, h.path, h.fmt, h.name,
                               body.mode, body.decisions, h.size)
    except Exception:
        _drop_held(body.upload_id)
        raise
    if res.needs_decision:
        # Still unanswered hosts: keep holding, same token.
        res.upload_id = body.upload_id
        h.at = time.time()
        return res
    _drop_held(body.upload_id)
    return res


#: job id -> (upload token, decisions, mode). The decisions can be a few
#: hundred entries, which belongs in memory next to the held file rather
#: than serialised into the row; losing it to a restart is fine, because
#: a restart fails the job anyway.
_JOB_WORK: dict[int, tuple[str, dict, str]] = {}


def _expected_rows(h: _Held) -> int | None:
    """How many rows the job should produce, where the format can say.

    Only the streaming formats can answer cheaply, and only by reading
    the file again -- which for the host survey has already happened
    once. Returning None is honest; a progress bar against a guessed
    total is worse than one that just counts up.
    """
    return None


async def run_job_body(job_id: int) -> dict:
    """The actual work of a queued import. Called by the jobs runner."""
    from ..importers import jobs as import_jobs_mod

    work = _JOB_WORK.get(job_id)
    if work is None:
        raise RuntimeError("the queued import lost its decisions; re-upload")
    token, decisions, mode = work
    async with SessionLocal() as session:
        job = await session.get(ImportJob, job_id)
        project = await session.get(Project, job.project_id)
        user = await session.get(User, job.requested_by) if job.requested_by else None
        if project is None or user is None:
            raise RuntimeError("the import's project or user no longer exists")
        h = _take_held(token, project, user)

        async def on_progress(rows: int, hosts: int) -> None:
            await import_jobs_mod.progress(job_id, rows, hosts)

        try:
            res = await _from_file(
                session, project, h.path, h.fmt, h.name, mode,
                {k: HostDecision(**v) if isinstance(v, dict) else v
                 for k, v in decisions.items()},
                h.size, on_progress)
        finally:
            _drop_held(token)
            _JOB_WORK.pop(job_id, None)
        return json.loads(res.model_dump_json())


@router.get("/import/jobs", response_model=list[ImportJobOut])
async def list_jobs(project: Project = Depends(require_project("readonly")),
                    _: User = Depends(get_current_user),
                    session: AsyncSession = Depends(get_session)):
    """Imports queued, running or finished for this project, newest first."""
    rows = (await session.execute(
        select(ImportJob).where(ImportJob.project_id == project.id)
        .order_by(ImportJob.id.desc()).limit(50))).scalars().all()
    return [ImportJobOut.of(r, project.code) for r in rows]


@router.get("/import/jobs/{job_id}", response_model=ImportJobOut)
async def get_job(job_id: int,
                  project: Project = Depends(require_project("readonly")),
                  _: User = Depends(get_current_user),
                  session: AsyncSession = Depends(get_session)):
    row = await session.get(ImportJob, job_id)
    if row is None or row.project_id != project.id:
        raise HTTPException(404, "no such import job")
    return ImportJobOut.of(row, project.code)


@router.delete("/import/held/{upload_id}", status_code=204)
async def discard_held(upload_id: str,
                       project: Project = Depends(require_project("user")),
                       user: User = Depends(get_current_user)):
    """Release a held upload when the operator cancels the decision."""
    _take_held(upload_id, project, user)
    _drop_held(upload_id)


@router.post("/nmap", response_model=ImportResult)
async def import_nmap(body: dict,
                      project: Project = Depends(require_project("user")),
                      _: User = Depends(get_current_user),
                      session: AsyncSession = Depends(get_session)):
    """nmap XML. Kept as its own route because it predates the generic one
    and scripts point at it; `/import` does the same thing for every tool."""
    xml = body.get("xml")
    if not isinstance(xml, str) or not xml.strip():
        raise HTTPException(422, "body must be {\"xml\": \"<nmaprun …>\"}")
    return await _run(session, project, xml, "nmap", "inline", mode="open")
