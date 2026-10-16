"""Report generation and download."""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import slack
from ..db import get_session
from ..events import broker
from ..models import REPORT_KINDS, Project, Report, User
from ..reports import ReportDoc, filename, render
from ..reports.runner import schedule
from ..security import get_current_user, require_project

router = APIRouter(prefix="/api/reports", tags=["reports"])

KIND_LABEL = {
    "executive": "Executive Summary",
    "findings": "Findings Report",
    "full": "Full Report",
}
KIND_SECTIONS = {
    "executive": ["Executive Summary", "Top Findings (max 10)"],
    "findings": ["Findings", "Appendix A: Targets Found"],
    "full": ["Executive Summary", "Scope", "Findings",
             "Appendix A: Targets Found"],
}


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    project_code: str = ""
    kind: str
    title: str
    status: str
    requested_by_name: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    size_bytes: int | None = None
    error: str | None = None
    emailed_to: str | None = None
    email_error: str | None = None
    agent_edited: bool = False
    agent_note: str | None = None

    @property
    def ready(self) -> bool:
        return self.status == "ready"


class CreateReport(BaseModel):
    kind: str = Field(description="executive | findings | full")
    agentic: bool = Field(
        False, description="Have the agent revise the prose before it is ready")
    min_severity: str = Field(
        "low",
        description="Lowest severity to list. Default excludes informational "
                    "entries, which on a real estate are coverage records and "
                    "run to thousands of pages. The report states how many "
                    "were omitted.")

    def clean_severity(self) -> str:
        v = (self.min_severity or "low").strip().lower()
        if v not in ("critical", "high", "medium", "low", "info"):
            raise HTTPException(422, "min_severity must be a severity name")
        return v

    def clean_kind(self) -> str:
        k = (self.kind or "").strip().lower()
        if k not in REPORT_KINDS:
            raise HTTPException(
                422, f"kind must be one of {', '.join(REPORT_KINDS)}")
        return k


class KindInfo(BaseModel):
    name: str
    label: str
    sections: list[str]


def _out(row: Report, code: str, who: str | None) -> ReportOut:
    summary = {}
    try:
        summary = json.loads(row.summary) if row.summary else {}
    except ValueError:
        summary = {}
    return ReportOut(
        id=row.id, project_code=code, kind=row.kind, title=row.title,
        status=row.status, requested_by_name=who,
        created_at=row.created_at, started_at=row.started_at,
        finished_at=row.finished_at, size_bytes=row.size_bytes,
        error=row.error, emailed_to=row.emailed_to, email_error=row.email_error,
        agent_edited=bool(summary.get("agent_edited")),
        agent_note=_agent_note(row))


def _agent_note(row: Report) -> str | None:
    if not row.content:
        return None
    try:
        return json.loads(row.content).get("agent_note")
    except ValueError:
        return None


@router.get("/kinds", response_model=list[KindInfo])
async def kinds(_: User = Depends(get_current_user)):
    """What can be produced, and what each one contains."""
    return [KindInfo(name=k, label=KIND_LABEL[k], sections=KIND_SECTIONS[k])
            for k in REPORT_KINDS]


@router.get("", response_model=list[ReportOut])
async def list_reports(project: str = Query(...),
                       pr: Project = Depends(require_project("readonly")),
                       session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(Report, User.username)
        .outerjoin(User, User.id == Report.requested_by)
        .where(Report.project_id == pr.id)
        .order_by(Report.created_at.desc()))).all()
    return [_out(r, pr.code, who) for r, who in rows]


@router.post("", response_model=ReportOut, status_code=202)
async def create_report(body: CreateReport, project: str = Query(...),
                        pr: Project = Depends(require_project("readonly")),
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    """Queue a report. Returns immediately with the row in `queued`.

    202, not 201: the thing you asked for does not exist yet. The row does,
    which is what lets the table show it as in progress rather than
    showing nothing until it finishes.

    Readonly is enough: a report contains only what the caller can already
    read, and refusing it would mean the person who most often writes the
    client deliverable cannot produce one.
    """
    kind = body.clean_kind()
    sev = body.clean_severity()
    row = Report(project_id=pr.id, kind=kind, fmt="pdf",
                 title=f"{KIND_LABEL[kind]} — {pr.client or pr.name}",
                 status="queued", requested_by=user.id)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    await broker.publish("reports", action="queued", id=row.id, project=pr.code)
    await slack.announce(session, pr, slack.report_requested(KIND_LABEL[kind]))
    # After the commit, so the row is visible to the task's own session.
    schedule(row.id, body.agentic, sev)
    return _out(row, pr.code, user.username)


@router.get("/{report_id}/download")
async def download(report_id: int, format: str = Query("pdf"),
                   user: User = Depends(get_current_user),
                   session: AsyncSession = Depends(get_session)):
    """Render the stored document to PDF or DOCX.

    Rendering happens here rather than at generation time so both formats
    come from one build — the PDF and the DOCX a client receives are the
    same report, not two that were produced separately.
    """
    fmt = (format or "pdf").lower()
    if fmt not in ("pdf", "docx"):
        raise HTTPException(422, "format must be pdf or docx")

    row = await session.get(Report, report_id)
    if row is None:
        raise HTTPException(404, "no such report")
    pr = await session.get(Project, row.project_id)
    if pr is None:
        raise HTTPException(404, "no such report")

    # Same rule as reading the project it describes.
    from ..security import effective_role
    if await effective_role(session, user, pr.id) is None:
        raise HTTPException(404, "no such report")

    if row.status != "ready" or not row.content:
        raise HTTPException(
            409, f"this report is {row.status}"
                 + (f": {row.error}" if row.error else
                    "; it is not ready to download yet"))

    doc = ReportDoc.from_json(json.loads(row.content))
    data, media = render(doc, fmt)
    return Response(
        content=data, media_type=media,
        headers={"Content-Disposition":
                 f'attachment; filename="{filename(doc, fmt)}"',
                 "Content-Length": str(len(data))})


@router.delete("/{report_id}", status_code=204)
async def delete_report(report_id: int,
                        user: User = Depends(get_current_user),
                        session: AsyncSession = Depends(get_session)):
    row = await session.get(Report, report_id)
    if row is None:
        raise HTTPException(404, "no such report")
    from ..models import ROLE_ORDER
    from ..security import effective_role
    role = await effective_role(session, user, row.project_id)
    if role is None:
        raise HTTPException(404, "no such report")
    if ROLE_ORDER.get(role, -1) < ROLE_ORDER["user"]:
        raise HTTPException(403, "user or admin is required to delete a report")
    pr = await session.get(Project, row.project_id)
    code = pr.code if pr else None
    await session.delete(row)
    await session.commit()
    await broker.publish("reports", action="delete", id=report_id, project=code)
