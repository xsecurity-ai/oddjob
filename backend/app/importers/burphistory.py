"""Burp proxy HTTP history — the `<items>` export.

**You cannot read a `.burp` file directly.** It is an undocumented
proprietary container (a 1.1 GB one in this engagement), with no magic
bytes, not zip, not SQLite, and nothing that scrapes strings out of it
could honestly claim to have parsed it. Burp's own REST API on :1337 does
not expose proxy history either — only scan launching and issue
definitions. So the supported route is Burp's export, which is what this
reads:

    Proxy -> HTTP history -> select all (Ctrl-A)
          -> right-click -> "Save items"  ->  history.xml

That produces `<items><item>` with `<url>`, `<host ip=…>`, `<port>`,
`<protocol>`, `<method>`, `<path>`, `<status>`, `<responselength>`,
`<mimetype>` and base64 `<request>`/`<response>` blobs.

**The exchange is imported, capped.** An earlier version of this stored
only metadata, on the reasoning that bodies are bulk and carry session
cookies. The reasoning was sound but the conclusion was wrong: reading
the actual request and response is most of why a proxy history is worth
having, and sending someone back to Burp to see it defeats the import.

So both sides are kept up to REQ_CAP / RESP_CAP, with `truncated` set
when either was cut. That bounds a 200,000-item history to something a
database can hold while keeping the headers and the first screen of body,
which is what a reader actually looks at. They still contain credentials;
the packet view says so, and the list endpoint never returns them.
"""
from __future__ import annotations

import base64
import binascii
import re
from xml.etree.ElementTree import Element, ParseError  # nosemgrep: use-defused-xml

from .model import ImportError_, ParsedScan, ParsedService, ParsedWebAddress
from .safexml import fromstring
from .safexml import stream as safe_stream

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_SERVER = re.compile(rb"^server:\s*(.+?)\r?$", re.I | re.M)

#: Responses can be megabytes; only the head is needed for title + headers,
#: and decoding whole bodies for a 200k-item history is pure waste.
REQ_CAP = 16 * 1024
RESP_CAP = 48 * 1024
_PEEK = RESP_CAP


def looks_like(text: str) -> bool:
    head = text[:4000]
    return "<items" in head and "<item>" in head and "<issues" not in head


def _t(el: Element, tag: str) -> str | None:
    c = el.find(tag)
    if c is None or c.text is None:
        return None
    v = c.text.strip()
    return v or None


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _blob(el: Element, tag: str, cap: int) -> tuple[bytes, bool]:
    """-> (bytes, was_truncated). Decodes at most `cap`. Never raises."""
    c = el.find(tag)
    if c is None or not c.text:
        return b"", False
    raw = c.text.strip()
    if (c.get("base64") or "").lower() == "true":
        # base64 is 4 chars per 3 bytes; take one extra group so the
        # truncation test is not fooled by padding.
        want = ((cap * 4) // 3) + 4
        try:
            out = base64.b64decode(raw[:want], validate=False)
        except (binascii.Error, ValueError):
            return b"", False
        return out[:cap], len(raw) > want or len(out) > cap
    data = raw.encode(errors="replace")
    return data[:cap], len(data) > cap


def _text(data: bytes) -> str | None:
    """Readable form of a captured side, or None if there was nothing.

    Decoded leniently: a response body may be gzip, an image, or any
    encoding at all, and a packet viewer showing mojibake for the body is
    still showing usable headers.
    """
    if not data:
        return None
    return data.decode("utf-8", errors="replace")


def _one(item: Element, scan: ParsedScan) -> bool:
    """Fold one `<item>` into `scan`. -> whether it counted.

    Split out of `parse` so the streaming reader below works from the
    same code. Two readers of one format that drift apart is how an
    import silently starts meaning something different depending on how
    the file arrived.
    """
    url = _t(item, "url")
    host_el = item.find("host")
    host = ((host_el.text or "").strip().lower() if host_el is not None else "")
    ip = host_el.get("ip") if host_el is not None else None
    if not host and url:
        from urllib.parse import urlsplit
        host = (urlsplit(url).hostname or "").lower()
    if not host:
        return False

    proto = (_t(item, "protocol") or "http").lower()
    port = _int(_t(item, "port")) or (443 if proto == "https" else 80)
    path = _t(item, "path") or "/"
    if not url:
        url = f"{proto}://{host}:{port}{path}"

    target = scan.host_for(host)
    target.alive = True          # something answered, or it is not here
    if ip and not target.ip_address:
        target.ip_address = ip
    if not any(s.port == port and s.protocol == "tcp" for s in target.services):
        target.services.append(ParsedService(
            port=port, protocol="tcp", state="open", name=proto,
            tunnel="ssl" if proto == "https" else None))

    resp, resp_cut = _blob(item, "response", RESP_CAP)
    req, req_cut = _blob(item, "request", REQ_CAP)
    title = None
    if (m := _TITLE.search(resp)):
        title = (m.group(1).decode("utf-8", "replace")
                 .strip().replace("\n", " ")[:512]) or None
    server = None
    if (m := _SERVER.search(resp)):
        server = m.group(1).decode("utf-8", "replace").strip()[:255] or None

    method = _t(item, "method")
    mime = _t(item, "mimetype")
    comment = _t(item, "comment")
    scan.web.append(ParsedWebAddress(
        url=url, host=host, scheme=proto, port=port,
        method=(method or "").upper()[:12] or None,
        request=_text(req), response=_text(resp),
        truncated=req_cut or resp_cut,
        status_code=_int(_t(item, "status")),
        title=title,
        content_type=mime,
        content_length=_int(_t(item, "responselength")),
        webserver=server,
        # It is in the proxy history because it was actually requested
        # and answered. That is the definition of crawled.
        crawled=True,
        # The method has its own column now; the note is for what a
        # person wrote, not for metadata with a home.
        notes=comment or None,
    ))
    return True


_WRONG_ROOT = ("expected a Burp HTTP-history export (<items>), got <{tag}>. "
               "In Burp: Proxy -> HTTP history -> select all -> right-click "
               "-> Save items.")


def _new_scan(version=None, exported=None) -> ParsedScan:
    scan = ParsedScan(tool="burp-history", version=version)
    scan.summary = exported
    return scan


def parse(xml: str | bytes) -> ParsedScan:
    """Whole-document read, for a history small enough to hold in memory.

    `stream` below is the one to use for a file; this stays for pasted
    text and for callers that already have the bytes.
    """
    try:
        root = fromstring(xml.encode() if isinstance(xml, str) else xml)
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    if root.tag != "items":
        raise ImportError_(_WRONG_ROOT.format(tag=root.tag))

    scan = _new_scan(root.get("burpVersion"), root.get("exportTime"))
    seen = sum(1 for item in root.findall("item") if _one(item, scan))
    if not seen:
        raise ImportError_("no <item> entries in this export")
    return scan


#: Items per yielded chunk. 500 items is a few tens of MB of decoded
#: request/response at the caps above — small enough that a chunk can be
#: written and released, large enough that the per-chunk database round
#: trips are not what dominates.
CHUNK = 500


def stream(path: str, chunk: int = CHUNK):
    """Yield `ParsedScan` chunks from a history file, in bounded memory.

    A 2.5 GB export holds 357,276 items; materialising that as one
    `ParsedScan` would mean every capped request and response resident
    at once, which is tens of gigabytes. The caller writes each chunk
    and drops it.

    Each chunk repeats whichever hosts appear in it, so `host_for` state
    does not have to survive across chunks — the ingest side merges
    hosts by name anyway.
    """
    try:
        it = safe_stream(path, "item", "items")
        scan = _new_scan()
        n = total = 0
        for item, root in it:
            if _one(item, scan):
                n += 1
                total += 1
            item.clear()
            root.clear()         # both, or the root retains everything
            if n >= chunk:
                yield scan
                scan = _new_scan()
                n = 0
        if n:
            yield scan
    except ParseError as e:
        if "expected <items>" in str(e):
            raise ImportError_(_WRONG_ROOT.format(tag="something else")) from e
        raise ImportError_(f"not valid XML: {e}") from e
    if not total:
        raise ImportError_("no <item> entries in this export")


def hosts_in(path: str) -> dict[str, int]:
    """`{hostname: transactions}` without decoding a single body.

    Strict mode has to know which hosts a file names before it writes
    anything. Doing that by running the real parse and throwing the
    result away would decode 2.5 GB of base64 for nothing; this reads
    the same file in about six seconds and touches only `<host>`.
    """
    out: dict[str, int] = {}
    try:
        for item, root in safe_stream(path, "item", "items"):
            el = item.find("host")
            h = ((el.text or "").strip().lower() if el is not None else "")
            if not h:
                u = item.findtext("url") or ""
                from urllib.parse import urlsplit
                h = (urlsplit(u).hostname or "").lower()
            if h:
                out[h] = out.get(h, 0) + 1
            item.clear()
            root.clear()
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    return out
