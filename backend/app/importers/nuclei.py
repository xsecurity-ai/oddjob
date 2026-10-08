"""Nuclei `-jsonl` (and the legacy `-json` array).

One object per match: `template-id`, `info{name,severity,description,tags,
reference}`, `host`, `ip`, `matched-at`, `type`, `extracted-results`,
`curl-command`.

Nuclei's own severity is authoritative here — unlike most scanners it is set
per template by someone who looked at the check, so it is used as-is.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from .model import (
    ImportError_,
    ParsedScan,
    ParsedService,
    ParsedVuln,
    ParsedWebAddress,
    norm_severity,
)


def looks_like(text: str) -> bool:
    head = text.lstrip()[:4000]
    return '"template-id"' in head or '"template_id"' in head


def iter_json(text: str):
    """Yield objects from JSONL, a JSON array, or concatenated objects.

    Tools disagree about which they emit and change their minds between
    releases, so accepting all three costs little and saves the operator
    finding out the hard way that their file was the other kind.
    """
    stripped = text.strip()
    if not stripped:
        return
    if stripped.startswith("["):
        try:
            doc = json.loads(stripped)
        except ValueError as e:
            raise ImportError_(f"not valid JSON: {e}") from e
        for x in doc:
            if isinstance(x, dict):
                yield x
        return
    ok = False
    for line in stripped.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            ok = True
            yield obj
    if not ok:
        raise ImportError_("no JSON objects found — expected one per line (JSONL)")


def parse(text: str) -> ParsedScan:
    scan = ParsedScan(tool="nuclei")
    seen = False
    for o in iter_json(text):
        info = o.get("info") or {}
        if "template-id" not in o and "template_id" not in o and not info:
            continue
        seen = True
        target = str(o.get("host") or o.get("matched-at") or o.get("matched_at") or "")
        parts = urlsplit(target if "//" in target else f"//{target}")
        name = (parts.hostname or target).strip().lower()
        if not name:
            continue

        host = scan.host_for(name)
        host.alive = True
        ip = o.get("ip")
        if ip and not host.ip_address:
            host.ip_address = str(ip)
        port = parts.port or (443 if parts.scheme == "https" else
                              80 if parts.scheme == "http" else None)
        if port and not any(s.port == port for s in host.services):
            host.services.append(ParsedService(
                port=port, protocol="tcp", state="open",
                name=parts.scheme or "http",
                tunnel="ssl" if parts.scheme == "https" else None))

        tid = o.get("template-id") or o.get("template_id") or "nuclei"
        matched = o.get("matched-at") or o.get("matched_at")
        if matched and str(matched).startswith(("http://", "https://")):
            scan.web.append(ParsedWebAddress(
                url=str(matched), host=name, scheme=parts.scheme or "http",
                port=port, crawled=True,
                notes=f"matched by nuclei template {tid}"))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        extracted = o.get("extracted-results") or o.get("extracted_results") or []

        scan.vulns.append(ParsedVuln(
            host=name,
            title=str(info.get("name") or tid),
            severity=norm_severity(info.get("severity")),
            description="\n\n".join(x for x in [
                info.get("description"),
                f"Matched: {matched}" if matched else None,
                ("Extracted: " + ", ".join(map(str, extracted))) if extracted else None,
                ("Tags: " + ", ".join(info.get("tags") or []))
                if isinstance(info.get("tags"), list) and info.get("tags") else None,
                ("References:\n" + "\n".join(f"  {r}" for r in refs)) if refs else None,
                f"Template: {tid}",
            ] if x) or None,
            remediation=info.get("remediation") or None,
            external_id=f"nuclei-{tid}-{_slug(str(matched or name))}",
            port=port,
            protocol="tcp",
        ))
    if not seen:
        raise ImportError_("no nuclei results in this file "
                           "(expected objects with a `template-id`)")
    return scan


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "x"
