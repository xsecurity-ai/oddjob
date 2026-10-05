"""Nikto `-Format json` and `-Format xml`.

JSON is one object per scanned target: `{host, ip, port, banner,
vulnerabilities: [{id, OSVDB, method, url, msg}]}`. Some builds emit a bare
array of those; both are accepted.

Nikto has no severity field at all. Everything it reports would be "info" if
taken literally, which makes the import useless for triage, so findings are
banded by what the check actually is — an exposed config file is not the
same as a missing `X-Frame-Options` header. The banding is a heuristic and
is labelled as one in the description, so nobody mistakes it for the tool's
own rating.
"""
from __future__ import annotations

import json
import re
from xml.etree.ElementTree import Element, ParseError  # nosemgrep: use-defused-xml

from .safexml import fromstring

from .model import (ImportError_, ParsedScan, ParsedService, ParsedVuln,
                    ParsedWebAddress, norm_severity)

# Ordered: first match wins.
_BANDS: list[tuple[str, re.Pattern]] = [
    ("high", re.compile(
        r"\b(remote file inclusion|rfi\b|sql injection|command execution|"
        r"shell|backdoor|default (admin )?(account|password|credential)|"
        r"authentication bypass|directory traversal|\.\./|arbitrary file)", re.I)),
    ("medium", re.compile(
        r"\b(phpinfo|\.git|\.svn|\.env|web\.config|backup|password file|"
        r"admin (interface|console|panel)|directory indexing|"
        r"outdated|end of life|eol\b|vulnerable|cve-)", re.I)),
    ("low", re.compile(
        r"\b(x-frame-options|x-content-type-options|strict-transport|"
        r"content-security-policy|cookie.*(httponly|secure)|"
        r"trace|track method|allowed http methods|etag|banner)", re.I)),
]

_BAND_NOTE = ("Severity was assigned by Oddjob from the check text — Nikto "
              "does not rate its findings. Re-rate before reporting.")


def looks_like(text: str) -> bool:
    head = text.lstrip()[:4000]
    if "<niktoscan" in head.lower():
        return True
    return ('"niktoscan"' in head
            or ('"vulnerabilities"' in head and '"banner"' in head)
            or ('"vulnerabilities"' in head and '"nikto"' in head.lower()))


def _band(msg: str) -> str:
    for sev, rx in _BANDS:
        if rx.search(msg or ""):
            return sev
    return "info"


def parse(text: str) -> ParsedScan:
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return _xml(text)
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise ImportError_(f"not valid Nikto JSON or XML: {e}") from e

    scan = ParsedScan(tool="nikto")
    blocks = doc if isinstance(doc, list) else [doc]
    # Some builds wrap everything in {"niktoscan": [...]}
    if isinstance(doc, dict) and isinstance(doc.get("niktoscan"), list):
        blocks = doc["niktoscan"]

    for b in blocks:
        if not isinstance(b, dict):
            continue
        if isinstance(b.get("niktoscan"), list):
            blocks.extend(b["niktoscan"])
            continue
        _block(scan, b)
    return scan


def _block(scan: ParsedScan, b: dict) -> None:
    name = str(b.get("host") or b.get("targethostname")
               or b.get("ip") or b.get("targetip") or "").strip().lower()
    if not name:
        return
    ip = b.get("ip") or b.get("targetip")
    port = _int(b.get("port") or b.get("targetport"))
    banner = b.get("banner")

    host = scan.host_for(name)
    host.alive = True
    if ip and not host.ip_address:
        host.ip_address = str(ip)
    if port:
        if not any(s.port == port for s in host.services):
            host.services.append(ParsedService(
                port=port, protocol="tcp", state="open",
                name="https" if port in (443, 8443) else "http",
                banner_override=str(banner) if banner else None))

    for v in b.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        msg = str(v.get("msg") or v.get("description") or "").strip()
        url = str(v.get("url") or v.get("uri") or "").strip()
        oid = str(v.get("id") or v.get("OSVDB") or v.get("osvdb") or "").strip()
        title = (msg.split("\n")[0][:300] or f"Nikto {oid}") if msg else f"Nikto {oid}"
        if url:
            scheme = "https" if port in (443, 8443) else "http"
            scan.web.append(ParsedWebAddress(
                url=url, host=name, scheme=scheme, port=port, crawled=True,
                notes=f"Nikto: {title[:200]}"))
        scan.vulns.append(ParsedVuln(
            host=name,
            title=f"{title}{f' ({url})' if url and url not in title else ''}",
            severity=norm_severity(v.get("severity"), default=_band(msg + " " + url)),
            description="\n\n".join(x for x in [
                msg or None,
                f"Method: {v.get('method')}" if v.get("method") else None,
                f"URL: {url}" if url else None,
                f"OSVDB: {oid}" if oid and oid != "0" else None,
                _BAND_NOTE if not v.get("severity") else None,
            ] if x) or None,
            external_id=f"nikto-{oid}-{_slug(url)}" if oid and oid != "0" else None,
            port=port,
            protocol="tcp",
        ))


def _xml(text: str) -> ParsedScan:
    try:
        root = fromstring(text)
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    scan = ParsedScan(tool="nikto", version=root.get("version"))
    for sd in root.iter("scandetails"):
        b = {
            "host": sd.get("targethostname") or sd.get("targetip"),
            "ip": sd.get("targetip"),
            "port": sd.get("targetport"),
            "banner": sd.get("targetbanner") or sd.get("sitename"),
            "vulnerabilities": [
                {"id": it.get("id"),
                 "OSVDB": it.get("osvdbid") or it.get("OSVDBID"),
                 "method": it.get("method"),
                 "url": (it.findtext("uri") or it.get("uri") or "").strip(),
                 "msg": (it.findtext("description") or "").strip()}
                for it in sd.findall("item")
            ],
        }
        _block(scan, b)
    if not scan.hosts:
        raise ImportError_("no <scandetails> in the document — is this a Nikto XML report?")
    return scan


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:50] or "root"
