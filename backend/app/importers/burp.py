"""Burp Suite issue export (Scanner → Report issues → XML).

`<issues><issue>` with `<serialNumber>`, `<type>`, `<name>`, `<host ip="…">`,
`<path>`, `<severity>`, `<confidence>`, `<issueDetail>`, `<issueBackground>`,
`<remediationBackground>` and base64 `<requestresponse>` blobs.

The request/response pair is deliberately **not** imported. It is the bulk of
the file, it routinely contains session cookies and credentials, and a
findings database is not where raw captured traffic belongs. The path, the
detail and the confidence are what make the issue actionable; the traffic
stays in the Burp project where it is already stored.
"""
from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError  # nosemgrep: use-defused-xml

from .safexml import fromstring
from .safexml import stream as safe_stream
from urllib.parse import urlsplit

from .model import (ImportError_, ParsedScan, ParsedVuln,
                    ParsedWebAddress, norm_severity)


def looks_like(text: str) -> bool:
    head = text[:4000]
    return "<issues" in head and ("burpVersion" in head or "<serialNumber>" in head)


def parse(xml: str | bytes) -> ParsedScan:
    try:
        root = fromstring(xml.encode() if isinstance(xml, str) else xml)
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    if root.tag != "issues":
        raise ImportError_(
            f"expected a Burp issue export (<issues>), got <{root.tag}>. "
            f"Export with Scanner → Report issues → XML.")

    scan = ParsedScan(tool="burp", version=root.get("burpVersion"))
    scan.summary = root.get("exportTime")

    for issue in root.findall("issue"):
        _one(issue, scan)

    return scan


def _t(el: Element, tag: str) -> str | None:
    c = el.find(tag)
    if c is None or not c.text:
        return None
    return c.text.strip() or None


def _html(s: str | None) -> str | None:
    """Burp writes HTML fragments. Flatten them; this is a plain-text field."""
    if not s:
        return None
    import re
    out = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    out = re.sub(r"</(p|li|div|h\d)>", "\n", out, flags=re.I)
    out = re.sub(r"<li[^>]*>", "  - ", out, flags=re.I)
    out = re.sub(r"<[^>]+>", "", out)
    from html import unescape
    out = unescape(out)
    return "\n".join(l.rstrip() for l in out.splitlines() if l.strip()) or None


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "root"


def _one(issue: Element, scan: ParsedScan) -> bool:
    """Fold one `<issue>` into `scan`. -> whether it counted.

    Shared by `parse` and `stream` so a Burp export cannot mean two
    different things depending on how big it was.
    """
    host_el = issue.find("host")
    url = (host_el.text or "").strip() if host_el is not None else ""
    ip = host_el.get("ip") if host_el is not None else None
    parts = urlsplit(url if "//" in url else f"//{url}")
    name = (parts.hostname or "").lower()
    if not name:
        return False

    host = scan.host_for(name)
    if ip and not host.ip_address:
        host.ip_address = ip
    host.alive = True
    # A URL without an explicit port still names one by its scheme;
    # dropping the service because :443 was implicit loses the whole
    # record of what Burp was talking to.
    port = parts.port or (443 if parts.scheme == "https" else
                          80 if parts.scheme == "http" else None)
    if port:
        # Burp only ever talks to things that answered.
        if not any(s.port == port for s in host.services):
            from .model import ParsedService
            host.services.append(ParsedService(
                port=port, protocol="tcp", state="open",
                name="https" if parts.scheme == "https" else "http",
                tunnel="ssl" if parts.scheme == "https" else None))

    path = _t(issue, "path") or "/"
    # Burp only reports an issue for something it requested.
    scan.web.append(ParsedWebAddress(
        url=f"{url.rstrip('/')}{path}", host=name,
        scheme=parts.scheme or "http", port=port, crawled=True,
        notes=f"Burp issue: {_t(issue, 'name') or 'unnamed'}"))
    conf = _t(issue, "confidence")
    detail = _html(_t(issue, "issueDetail"))
    background = _html(_t(issue, "issueBackground"))
    remedy = _html(_t(issue, "remediationBackground"))
    remedy_detail = _html(_t(issue, "remediationDetail"))
    scan.vulns.append(ParsedVuln(
        host=name,
        title=f"{_t(issue, 'name') or 'Burp issue'} at {path}",
        severity=norm_severity(_t(issue, "severity")),
        description="\n\n".join(x for x in [
            f"URL: {url}{path}",
            f"Confidence: {conf}" if conf else None,
            detail,
            background,
        ] if x) or None,
        remediation="\n\n".join(x for x in [remedy, remedy_detail] if x) or None,
        # serialNumber is per-export, not stable across scans; the issue
        # type plus its path is what identifies the same finding again.
        external_id=f"burp-{_t(issue, 'type')}-{_slug(path)}"
                    if _t(issue, "type") else None,
        port=port,
        protocol="tcp",
    ))
    return True


#: Issues per yielded chunk. An issue carries flattened HTML detail
#: rather than raw traffic, so they are smaller than history items and a
#: bigger chunk is still cheap.
CHUNK = 1000


def stream(path: str, chunk: int = CHUNK):
    """Yield `ParsedScan` chunks from an issue export, in bounded memory.

    Same reason as the history reader: a real export of this is
    gigabytes — one here was 2,232 MB — and `fromstring` has to build
    the whole document before anything can look at it. Without this the
    import is refused outright against the whole-document size limit.
    """
    total = 0
    try:
        scan = ParsedScan(tool="burp")
        n = 0
        for issue, root in safe_stream(path, "issue", "issues"):
            if scan.version is None:
                scan.version = root.get("burpVersion")
            if _one(issue, scan):
                n += 1
                total += 1
            issue.clear()
            root.clear()          # both, or the root retains every issue
            if n >= chunk:
                yield scan
                scan = ParsedScan(tool="burp", version=scan.version)
                n = 0
        if n:
            yield scan
    except ParseError as e:
        if "expected <issues>" in str(e):
            raise ImportError_(
                "expected a Burp issue export (<issues>). Export with "
                "Scanner -> Report issues -> XML.") from e
        raise ImportError_(f"not valid XML: {e}") from e
    if not total:
        raise ImportError_("no <issue> entries in this export")


def hosts_in(path: str) -> dict[str, int]:
    """`{hostname: issues}` without flattening a single HTML block.

    Strict mode needs the host list before it writes anything, and
    running the real parse to get it would decode and flatten every
    issue body in a multi-gigabyte file for a result that is thrown
    away.
    """
    out: dict[str, int] = {}
    try:
        for issue, root in safe_stream(path, "issue", "issues"):
            el = issue.find("host")
            url = (el.text or "").strip() if el is not None else ""
            h = (urlsplit(url if "//" in url else f"//{url}").hostname or "").lower()
            if h:
                out[h] = out.get(h, 0) + 1
            issue.clear()
            root.clear()
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    return out
