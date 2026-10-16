"""The shape of a report, independent of how it is rendered.

One structured document, two renderers. The alternative — build HTML and
convert it to PDF, then separately to DOCX — needs a headless browser or
WeasyPrint's system libraries, and produces a DOCX that is a screenshot of
a web page rather than a document anyone can edit. A client who receives a
DOCX will edit it; that is the entire reason they asked for one.

Keeping the document as data also means the agentic pass operates on
content rather than on a rendered file. "Read the PDF and revise it" would
mean extracting text out of a layout we just created, losing the structure
on the way out and guessing it back on the way in. The agent gets the same
information with the structure intact.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Print colours per severity. Deliberately darker than the UI palette —
#: a report is read on paper and in Word, not on a dark background.
SEVERITY_COLOUR = {
    "critical": "#B00020", "high": "#C64600", "medium": "#9A6700",
    "low": "#1A5FB4", "info": "#5A5A5A",
}


@dataclass
class Finding:
    severity: str
    host: str
    title: str
    description: str | None = None
    remediation: str | None = None
    port: int | None = None
    protocol: str | None = None
    external_id: str | None = None
    #: Set when the agentic pass rewrote this entry's prose, so a reader
    #: can tell machine-edited text from what the scanner said.
    edited: bool = False


@dataclass
class TargetRow:
    host: str
    ip: str | None
    os: str | None
    alive: bool | None
    compromised: bool
    open_ports: int
    findings: int


@dataclass
class Block:
    """One piece of a section. `kind` drives how each renderer treats it."""
    kind: str                       # para | bullets | table | findings | kv
    text: str | None = None
    items: list[str] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pairs: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Section:
    heading: str
    blocks: list[Block] = field(default_factory=list)
    page_break_before: bool = False


@dataclass
class ReportDoc:
    title: str
    subtitle: str
    project: str
    client: str | None
    generated_at: datetime
    generated_by: str
    kind: str
    sections: list[Section] = field(default_factory=list)
    #: Counts the report was built from, recorded so a reader months later
    #: can tell whether the numbers still describe the estate.
    stats: dict[str, Any] = field(default_factory=dict)
    #: True when an LLM revised any prose in this document. Surfaced in the
    #: rendered output, because a client deliverable that was partly
    #: machine-written should say so.
    agent_edited: bool = False
    agent_note: str | None = None

    def to_json(self) -> dict:
        d = asdict(self)
        d["generated_at"] = self.generated_at.isoformat()
        return d

    @staticmethod
    def from_json(d: dict) -> ReportDoc:
        secs = [
            Section(
                heading=s["heading"],
                page_break_before=s.get("page_break_before", False),
                blocks=[
                    Block(
                        kind=b["kind"], text=b.get("text"),
                        items=b.get("items", []), headers=b.get("headers", []),
                        rows=b.get("rows", []),
                        pairs=[tuple(p) for p in b.get("pairs", [])],
                        findings=[Finding(**f) for f in b.get("findings", [])],
                    ) for b in s.get("blocks", [])
                ],
            ) for s in d.get("sections", [])
        ]
        return ReportDoc(
            title=d["title"], subtitle=d.get("subtitle", ""),
            project=d["project"], client=d.get("client"),
            generated_at=datetime.fromisoformat(d["generated_at"]),
            generated_by=d.get("generated_by", ""), kind=d.get("kind", "full"),
            sections=secs, stats=d.get("stats", {}),
            agent_edited=d.get("agent_edited", False),
            agent_note=d.get("agent_note"),
        )

    def plain_text(self, limit: int = 60000) -> str:
        """A flat rendering, for handing to the agent.

        Deliberately not the PDF: extracting text back out of a layout we
        just built loses the structure and gains nothing.
        """
        out: list[str] = [f"# {self.title}", f"{self.subtitle}", ""]
        for s in self.sections:
            out.append(f"\n## {s.heading}")
            for b in s.blocks:
                if b.kind == "para" and b.text:
                    out.append(b.text)
                elif b.kind == "bullets":
                    out += [f"  - {i}" for i in b.items]
                elif b.kind == "kv":
                    out += [f"  {k}: {v}" for k, v in b.pairs]
                elif b.kind == "table":
                    out.append("  " + " | ".join(b.headers))
                    out += ["  " + " | ".join(r) for r in b.rows[:50]]
                    if len(b.rows) > 50:
                        out.append(f"  …and {len(b.rows) - 50} more rows")
                elif b.kind == "findings":
                    for f in b.findings:
                        out.append(f"  [{f.severity.upper()}] {f.host} — {f.title}")
        return "\n".join(out)[:limit]
