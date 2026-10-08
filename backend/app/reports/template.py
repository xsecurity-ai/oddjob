"""Turning engagement data into a report document.

The three kinds share their section builders, so a change to how findings
are presented lands in all of them:

    full        Executive Summary · Scope · Findings · Appendix A: Targets Found
    executive   Executive Summary · Top Findings (max 10)
    findings    Findings · Appendix A: Targets Found

**The executive summary is generated from the numbers, not written by a
model.** It has to be correct and it has to exist whether or not an agent
is configured, so it is assembled from counts with the qualifications
attached — "47 hosts did not respond" is only meaningful next to "and 112
were never probed". The agentic pass, when asked for, revises this prose
afterwards; it does not supply it.

Nothing here invents a severity or a count. Where the data is absent the
report says the data is absent, because a report that quietly omits its
gaps is worse than one that is honest about them.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Implant, Project, ProjectScope, Service, Target, Vuln, WebAddress
from .model import SEVERITY_ORDER, Block, Finding, ReportDoc, Section, TargetRow

TOP_N = 10


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one}" if n == 1 else f"{n} {many or one + 's'}"


async def gather(session: AsyncSession, project: Project) -> dict:
    """Every number the report needs, in one place."""
    pid = project.id

    async def count(stmt) -> int:
        return int((await session.execute(stmt)).scalar_one())

    t_base = select(func.count()).select_from(Target).where(Target.project_id == pid)

    def child(model):
        return (select(func.count()).select_from(model)
                .join(Target, Target.id == model.target_id)
                .where(Target.project_id == pid))

    sev = {s: await count(child(Vuln).where(Vuln.severity == s))
           for s in SEVERITY_ORDER}

    return {
        "targets": await count(t_base),
        "alive": await count(t_base.where(Target.alive.is_(True))),
        "down": await count(t_base.where(Target.alive.is_(False))),
        "unprobed": await count(t_base.where(Target.alive.is_(None))),
        "compromised": await count(t_base.where(Target.hacked.is_(True))),
        "services": await count(child(Service)),
        "open_ports": await count(child(Service).where(Service.state == "open")),
        "unknown_ports": await count(child(Service).where(
            Service.state == "open", Service.name == "UNKNOWN")),
        "web": await count(child(WebAddress)),
        "implants": await count(child(Implant)),
        "by_severity": sev,
        "findings": sum(sev.values()),
        "actionable": sum(v for k, v in sev.items() if k != "info"),
    }


async def _findings(session: AsyncSession, project: Project,
                    limit: int | None = None,
                    min_severity: str = "low") -> list[Finding]:
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    cutoff = rank.get(min_severity, rank["low"])
    keep = {s for s in SEVERITY_ORDER if rank[s] <= cutoff}
    rows = (await session.execute(
        select(Vuln, Target.host).join(Target, Target.id == Vuln.target_id)
        .where(Target.project_id == project.id,
               Vuln.severity.in_(keep)))).all()
    # Worst first, then by host so the same host's findings sit together.
    rows.sort(key=lambda r: (rank.get(r[0].severity, 9), r[1], r[0].title))
    out = [Finding(severity=v.severity, host=h, title=v.title,
                   description=v.description, remediation=v.remediation,
                   port=v.port, protocol=v.protocol, external_id=v.external_id)
           for v, h in rows]
    return out[:limit] if limit else out


async def _targets(session: AsyncSession, project: Project) -> list[TargetRow]:
    rows = (await session.execute(
        select(
            Target,
            select(func.count()).select_from(Service)
            .where(Service.target_id == Target.id,
                   Service.state == "open").scalar_subquery(),
            select(func.count()).select_from(Vuln)
            .where(Vuln.target_id == Target.id).scalar_subquery(),
        ).where(Target.project_id == project.id).order_by(Target.host))).all()
    return [TargetRow(host=t.host, ip=t.ip_address, os=t.os, alive=t.alive,
                      compromised=t.hacked, open_ports=int(p or 0),
                      findings=int(v or 0)) for t, p, v in rows]


# ------------------------------------------------------------- sections
def _executive_summary(project: Project, s: dict) -> Section:
    sev = s["by_severity"]
    bits: list[str] = []

    scope_line = (
        f"This assessment covered {_plural(s['targets'], 'host')} in "
        f"{project.code}" + (f" for {project.client}" if project.client else "") + ".")
    bits.append(scope_line)

    # The qualification is the point. "47 did not respond" without "and 112
    # were never probed" reads as coverage that was not achieved.
    coverage = []
    if s["alive"]:
        coverage.append(f"{s['alive']} responded")
    if s["down"]:
        coverage.append(f"{s['down']} did not respond when probed")
    if s["unprobed"]:
        coverage.append(f"{s['unprobed']} were never probed")
    if coverage:
        bits.append("Of those, " + ", ".join(coverage) + ".")

    if s["open_ports"]:
        line = (f"{_plural(s['open_ports'], 'open port')} were found across "
                f"{_plural(s['services'], 'recorded service')}.")
        if s["unknown_ports"]:
            line += (f" {s['unknown_ports']} of those answered but could not be "
                     f"identified, and remain unexplained.")
        bits.append(line)

    if s["actionable"]:
        order = [f"{sev[k]} {k}" for k in SEVERITY_ORDER if k != "info" and sev[k]]
        bits.append(
            f"{_plural(s['actionable'], 'finding')} were raised that warrant "
            f"action: " + ", ".join(order) + ". "
            + f"A further {sev['info']} informational "
              f"{'entry was' if sev['info'] == 1 else 'entries were'} recorded "
              f"for coverage." if sev["info"] else
            f"{_plural(s['actionable'], 'finding')} were raised: "
            + ", ".join(order) + ".")
    else:
        bits.append(
            "No findings above informational severity were raised. That is a "
            "statement about what was tested, not an assurance about what was "
            "not — see the coverage figures above.")

    if s["compromised"]:
        bits.append(
            f"{_plural(s['compromised'], 'host')} were compromised during the "
            f"engagement" + (f", with {_plural(s['implants'], 'agent')} "
                             f"recorded as having checked in."
                             if s["implants"] else "."))

    crit_high = sev["critical"] + sev["high"]
    if crit_high:
        bits.append(
            f"The {_plural(crit_high, 'critical or high-severity finding')} "
            f"should be treated as the priority; they are listed first in the "
            f"Findings section with the recommended remediation for each.")

    sec = Section("Executive Summary")
    sec.blocks.append(Block(kind="para", text=" ".join(bits)))
    sec.blocks.append(Block(kind="kv", pairs=[
        ("Hosts in scope", str(s["targets"])),
        ("Responded / silent / unprobed",
         f"{s['alive']} / {s['down']} / {s['unprobed']}"),
        ("Open ports", str(s["open_ports"])),
        ("Findings requiring action", str(s["actionable"])),
        ("Critical", str(sev["critical"])),
        ("High", str(sev["high"])),
        ("Medium", str(sev["medium"])),
        ("Low", str(sev["low"])),
        ("Informational", str(sev["info"])),
        ("Hosts compromised", str(s["compromised"])),
    ]))
    return sec


async def _scope(session: AsyncSession, project: Project, s: dict) -> Section:
    sec = Section("Scope")
    entries = (await session.execute(
        select(ProjectScope).where(ProjectScope.project_id == project.id)
        .order_by(ProjectScope.kind, ProjectScope.value))).scalars().all()

    included = [e for e in entries if e.included]
    excluded = [e for e in entries if not e.included]

    if included:
        sec.blocks.append(Block(kind="para", text=(
            f"The engagement was scoped to the following "
            f"{_plural(len(included), 'entry', 'entries')}.")))
        by_kind: dict[str, list[str]] = {}
        for e in included:
            by_kind.setdefault(e.kind, []).append(e.value)
        sec.blocks.append(Block(
            kind="table", headers=["Type", "Entries", "Values"],
            rows=[[k.upper(), str(len(v)), ", ".join(sorted(v)[:40])
                   + (f" …and {len(v) - 40} more" if len(v) > 40 else "")]
                  for k, v in sorted(by_kind.items())]))
    else:
        # Say so rather than printing an empty heading.
        sec.blocks.append(Block(kind="para", text=(
            "No formal scope was recorded against this engagement in the "
            f"platform. The {_plural(s['targets'], 'host')} in Appendix A are "
            "the assets actually examined, and should be read as the effective "
            "scope.")))

    if excluded:
        sec.blocks.append(Block(kind="para", text="The following were excluded:"))
        sec.blocks.append(Block(kind="bullets",
                                items=[f"{e.value} ({e.kind})" for e in excluded]))
    return sec


def _findings_section(findings: list[Finding], *, heading: str,
                      note: str | None = None, excluded: int = 0,
                      min_severity: str = "low") -> Section:
    sec = Section(heading, page_break_before=True)
    if note:
        sec.blocks.append(Block(kind="para", text=note))
    if excluded:
        # Never silently drop data from a deliverable. On a real estate
        # the informational entries are coverage records — one per host
        # per task — and including them turned this report into 9,000
        # pages. Say what was left out and where it still lives.
        sec.blocks.append(Block(kind="para", text=(
            f"{_plural(excluded, 'informational entry', 'informational entries')} "
            f"{'is' if excluded == 1 else 'are'} omitted from this section. "
            f"Those are coverage records — what was tested, when, and with "
            f"what result — rather than findings requiring action, and they "
            f"remain in full in the platform. This section lists everything "
            f"at {min_severity} severity and above.")))
    if not findings:
        sec.blocks.append(Block(kind="para", text=(
            "No findings were recorded for this engagement.")))
        return sec
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    sec.blocks.append(Block(kind="para", text=(
        _plural(len(findings), 'finding') + ", ordered by severity: "
        + ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]) + ".")))
    sec.blocks.append(Block(kind="findings", findings=findings))
    return sec


def _appendix_targets(targets: list[TargetRow]) -> Section:
    sec = Section("Appendix A: Targets Found", page_break_before=True)
    sec.blocks.append(Block(kind="para", text=(
        "Every host recorded during the engagement. "
        "“Alive” distinguishes a host that responded from one that was "
        "probed and stayed silent; a blank means it was never probed, "
        "which is a gap in coverage rather than a finding about the host.")))
    sec.blocks.append(Block(
        kind="table",
        headers=["Host", "IP", "OS", "Alive", "Pwned", "Open", "Findings"],
        rows=[[t.host, t.ip or "—", (t.os or "—")[:40],
               "yes" if t.alive else ("no" if t.alive is False else "—"),
               "yes" if t.compromised else "",
               str(t.open_ports), str(t.findings)] for t in targets]))
    return sec


# ---------------------------------------------------------------- build
async def build(session: AsyncSession, project: Project, kind: str,
                requested_by: str, min_severity: str = "low") -> ReportDoc:
    stats = await gather(session, project)
    now = datetime.now(UTC)

    titles = {"full": "Security Assessment Report",
              "executive": "Executive Summary",
              "findings": "Findings Report"}
    doc = ReportDoc(
        title=titles.get(kind, "Security Assessment Report"),
        subtitle=(f"{project.client} — {project.name}" if project.client
                  else project.name),
        project=project.code, client=project.client, generated_at=now,
        generated_by=requested_by, kind=kind, stats=stats)

    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    excluded = sum(v for k, v in stats["by_severity"].items()
                   if rank[k] > rank.get(min_severity, rank["low"]))
    doc.stats["min_severity"] = min_severity
    doc.stats["excluded_below_threshold"] = excluded

    if kind == "executive":
        doc.sections.append(_executive_summary(project, stats))
        top = await _findings(session, project, limit=TOP_N,
                              min_severity=min_severity)
        eligible = stats["findings"] - excluded
        note = (f"The {len(top)} most severe of {_plural(eligible, 'finding')} "
                f"at {min_severity} severity and above. The full set, with "
                f"remediation for each, is in the Findings report."
                if eligible > len(top) else None)
        doc.sections.append(_findings_section(
            top, heading="Top Findings", note=note, excluded=excluded,
            min_severity=min_severity))

    elif kind == "findings":
        doc.sections.append(_findings_section(
            await _findings(session, project, min_severity=min_severity),
            heading="Findings", excluded=excluded, min_severity=min_severity))
        doc.sections.append(_appendix_targets(await _targets(session, project)))

    else:   # full
        doc.sections.append(_executive_summary(project, stats))
        doc.sections.append(await _scope(session, project, stats))
        doc.sections.append(_findings_section(
            await _findings(session, project, min_severity=min_severity),
            heading="Findings", excluded=excluded, min_severity=min_severity))
        doc.sections.append(_appendix_targets(await _targets(session, project)))

    return doc


def summary_json(doc: ReportDoc) -> str:
    return json.dumps({
        "kind": doc.kind,
        "sections": [s.heading for s in doc.sections],
        "stats": doc.stats,
        "agent_edited": doc.agent_edited,
    })
