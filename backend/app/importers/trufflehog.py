"""Trufflehog JSON output — secret scanning with live verification.

Trufflehog emits a JSON array (or JSONL) of findings. Each object has:
  - `detector_name`: e.g. "aws-access-token", "github-pat"
  - `raw` / `raw_v2`: the secret value
  - `source`: where it was found ("git", "filesystem", etc.)
  - `verification_result`: {"verified": true/false, ...}
  - `commit`: git commit SHA (for git sources)
  - `file`: file path within the repo
  - `line`: line number
  - `entropy`: Shannon entropy of the secret
  - `extra_data`: detector-specific fields (e.g. account ID)

We map each finding to a ParsedVuln (the detection) + optionally a
ParsedCredential (the actual secret value, for the FindingSecret model).

Severity: verified secrets are "high" (they work); unverified are "medium"
(likely but not confirmed). The operator triages from there.
"""
from __future__ import annotations

import json

from .model import (
    ImportError_,
    ParsedCredential,
    ParsedScan,
    ParsedVuln,
)


def looks_like(text: str) -> bool:
    """True if this looks like trufflehog JSON output."""
    head = text.lstrip()[:2048]
    # Trufflehog findings have distinctive keys.
    return ('"detector_name"' in head and '"raw"' in head) or \
           ('"detector_name"' in head and '"raw_v2"' in head)


def parse(text: str, *, target_host: str | None = None) -> ParsedScan:
    """Parse trufflehog JSON output into the IR."""
    stripped = text.strip()
    if not stripped:
        return ParsedScan(tool="trufflehog")

    # Try array first, then JSONL.
    items: list[dict] = []
    try:
        doc = json.loads(stripped)
        if isinstance(doc, list):
            items = [x for x in doc if isinstance(x, dict)]
        elif isinstance(doc, dict):
            items = [doc]
    except json.JSONDecodeError:
        # JSONL: one object per line.
        for line in stripped.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError:
                continue

    if not items:
        raise ImportError_("no trufflehog findings found in input")

    host = (target_host or "unknown").lower().strip()
    scan = ParsedScan(tool="trufflehog", summary=f"{len(items)} secrets found")

    for item in items:
        detector = item.get("detector_name", "unknown-detector")
        raw = item.get("raw") or item.get("raw_v2") or ""
        source = item.get("source", "")
        commit = (item.get("commit") or "")[:8]
        file_path = item.get("file")
        line = item.get("line")
        try:
            line_number = int(line) if line is not None else None
        except (ValueError, TypeError):
            line_number = None

        # Verification status.
        verif = item.get("verification_result", {})
        verified = False
        if isinstance(verif, dict):
            verified = bool(verif.get("verified"))
        elif isinstance(verif, bool):
            verified = verif

        severity = "high" if verified else "medium"

        # Title: human-readable detector name.
        title = f"{detector}" + (" (verified)" if verified else "")

        # Description with context.
        desc_parts = [f"Detector: {detector}"]
        if source:
            desc_parts.append(f"Source: {source}")
        if commit:
            desc_parts.append(f"Commit: {commit}")
        extra = item.get("extra_data", {})
        if isinstance(extra, dict):
            for k, v in list(extra.items())[:6]:
                if v and k not in ("secret", "raw"):
                    desc_parts.append(f"{k}: {v}")
        description = "\n".join(desc_parts)

        # External ID for dedupe: detector + file + line + commit.
        ext_id = f"trufflehog:{detector}"
        if file_path:
            ext_id += f":{file_path}"
        if line_number:
            ext_id += f":{line_number}"
        if commit:
            ext_id += f":{commit}"

        scan.vulns.append(ParsedVuln(
            host=host,
            title=title[:1000],
            severity=severity,
            description=description,
            external_id=ext_id[:128],
            file_path=file_path,
            line_number=line_number,
        ))

        # The actual secret value goes into a Credential row.
        if raw:
            scan.credentials.append(ParsedCredential(
                host=host,
                username=None,
                secret=raw[:4096],  # cap for storage sanity
                kind="token",
                source=f"trufflehog:{detector}",
                notes=f"file={file_path} line={line_number} commit={commit}",
                validated="works" if verified else "none",
            ))

    scan.summary = f"{len(scan.vulns)} secrets ({sum(1 for v in scan.vulns if v.severity == 'high')} verified)"
    return scan
