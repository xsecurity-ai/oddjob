"""The web traffic that goes through the Ghost proxy, kept as evidence.

An operator browsing a client's application through a Ghost is doing
the same work a scanner does, by hand, and producing the same thing:
requests and responses against hosts in scope. Until this, none of
it was recorded. The proxy wrote one `ProxyConnection` row saying
somebody had CONNECTed to a host and relayed the bytes without
looking at them, so an afternoon of manual testing left a line per
connection and no evidence at all.

Captures land in `web_addresses`, the same table the Burp and httpx
importers write to, keyed the same way -- `exchange_hash` over
method, URL, request and response. A page reached by hand and the
same page reached by a crawler are the same kind of fact and belong
in one place.

# What this CANNOT see, which matters more than what it can

**A CONNECT to port 443 is an opaque TLS stream.** The client and
the target negotiate a session this server has no key for, and the
bytes crossing the relay are ciphertext. There is no parsing it and
nothing here pretends otherwise: an HTTPS request through the proxy
is recorded as a `ProxyConnection` -- who, where, when -- and its
contents are not captured.

Reading it would mean terminating TLS here with our own CA and
re-originating the connection: a man-in-the-middle against the
operator's own browser, a certificate to install, and a server that
holds the plaintext of everything anybody proxies through it. That
is a decision about the product, not a parser, and it has not been
made. See `tls_opaque()`, which is what the UI shows rather than
leaving the gap to be discovered.

So in practice this captures:

    http://  through the proxy      fully
    https:// through the proxy      metadata only, in proxy_connections

# Scope

Every destination is already ruled on by `proxyauth.decide` before a
single byte is relayed, so anything reaching this module is in scope
by construction. It is checked again at write time anyway, for the
same reason the task gate is checked twice: a connection can outlive
the list that permitted it, and a long-lived keep-alive session is
exactly where that happens.

# What is NOT stored

Bodies that are not text. A proxied browser pulls images, fonts and
video, and a megabyte of JPEG in a Text column is neither evidence
nor searchable -- the headers are kept and the body is recorded as
omitted, which is a fact about the capture rather than a silence.

NUL bytes, which Postgres rejects in text and SQLite accepts
happily. This project has been bitten by exactly that difference
before.
"""
from __future__ import annotations

import logging
import re

from sqlalchemy import select

from .db import SessionLocal
from .hosts import normalise_host
from .models import Target, WebAddress
from .weburl import exchange_key, merge_sources, url_key

#: Hard ceiling on what one exchange may contribute, per direction.
#: A proxied browser will happily pull a 40 MB bundle, and the
#: evidence value of the first quarter-megabyte is the same as the
#: whole thing while the cost is not.
CAP = 256 * 1024

#: Beyond this, a connection that has produced no parseable HTTP is
#: not going to. Stops a long TLS session accumulating ciphertext in
#: memory on the chance it turns into a request.
SNIFF = 8 * 1024

#: Content types whose body is worth keeping. Everything else has
#: its headers stored and its body recorded as omitted.
TEXTY = re.compile(
    r"^(?:text/|application/(?:json|xml|javascript|x-javascript|"
    r"ecmascript|x-www-form-urlencoded|graphql|xhtml\+xml|"
    r"[a-z0-9.+-]*\+json|[a-z0-9.+-]*\+xml)\b)", re.I)

#: The request line of HTTP/1.x. Deliberately strict: this is also
#: the test for "is this HTTP at all", and a loose pattern would
#: start parsing a TLS ClientHello as a request whose method is two
#: bytes of a random nonce.
_REQUEST = re.compile(
    rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|PROPFIND|"
    rb"MKCOL|COPY|MOVE|LOCK|UNLOCK|REPORT|SEARCH) "
    rb"(\S{1,8000}) HTTP/1\.[01]\r?\n")

_STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")


def tls_opaque(port: int | None) -> bool:
    """Is this destination one whose contents we cannot see?

    By port, because that is all a CONNECT gives us before the
    handshake. Imperfect in both directions -- plaintext HTTP on 443
    exists, and TLS on 8080 exists -- and it is only used to EXPLAIN
    a missing capture, never to decide whether to try parsing. The
    parser decides that by looking at the bytes.
    """
    return port in (443, 8443, 9443, 4443, 10443, 993, 995, 465, 636, 989,
                    990, 992, 5061)


def strip_nul(s: str) -> str:
    """Postgres will not store a NUL in a text column. SQLite will.

    Which is how an 8,221-character URL lived in a `String(2048)` for
    months here. Captured HTTP responses carry NUL whenever a server
    sends something that is not really text, so this is not an edge
    case on a proxy that sees whatever a browser asks for.
    """
    return s.replace("\x00", "") if s else s


def headers_of(raw: bytes) -> tuple[bytes, bytes]:
    """-> (head, rest). `head` includes the blank line that ends it."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i != -1:
            return raw[:i + len(sep)], raw[i + len(sep):]
    return b"", raw


def header_value(head: bytes, name: str) -> str:
    """One header out of a head block, case-insensitively. '' if absent."""
    m = re.search(rb"^" + re.escape(name.encode()) + rb":[ \t]*(.*?)\r?$",
                  head, re.I | re.M)
    return m.group(1).decode("latin-1").strip() if m else ""


def looks_http(raw: bytes) -> bool:
    """Is this the start of an HTTP/1.x request?

    False for TLS, for SSH, for a raw socket and for the second half
    of anything. Used to decide whether to keep accumulating: a
    connection that is not HTTP is dropped from capture immediately
    rather than buffered in the hope that it becomes HTTP.
    """
    return bool(_REQUEST.match(raw))


def decode(raw: bytes) -> str:
    """Bytes to text, losing nothing and inventing nothing.

    `surrogateescape` so that a body which is not valid UTF-8 round
    trips rather than raising or being silently replaced with
    question marks -- the bytes are the artefact.
    """
    return strip_nul(raw.decode("utf-8", "surrogateescape"))


class Exchange:
    """One request and its response, accumulated off a relayed stream.

    Bounded in both directions and in total. An exchange that exceeds
    the cap is still recorded -- truncated, and saying so -- because
    a 3 MB response is usually the most interesting thing on a host
    and reporting nothing about it would be the worse answer.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        self.req = bytearray()
        self.resp = bytearray()
        self.req_truncated = False
        self.resp_truncated = False

    def add_request(self, data: bytes) -> None:
        room = CAP - len(self.req)
        if room <= 0:
            self.req_truncated = True
            return
        self.req += data[:room]
        if len(data) > room:
            self.req_truncated = True

    def add_response(self, data: bytes) -> None:
        room = CAP - len(self.resp)
        if room <= 0:
            self.resp_truncated = True
            return
        self.resp += data[:room]
        if len(data) > room:
            self.resp_truncated = True

    # -- reading it back ------------------------------------------
    @property
    def method(self) -> str:
        m = _REQUEST.match(bytes(self.req))
        return m.group(1).decode() if m else ""

    @property
    def request_target(self) -> str:
        m = _REQUEST.match(bytes(self.req))
        return m.group(2).decode("latin-1") if m else ""

    @property
    def status(self) -> int | None:
        m = _STATUS.match(bytes(self.resp))
        return int(m.group(1)) if m else None

    @property
    def url(self) -> str:
        """The absolute URL this exchange was for.

        A proxied request may carry either form: an origin-form path
        (`GET /x`), which is what a CONNECT tunnel contains, or an
        absolute-form URL (`GET http://h/x`), which is what a plain
        HTTP proxy request contains. Both occur on this socket and
        both have to produce the same answer.
        """
        t = self.request_target
        if t.startswith(("http://", "https://")):
            return t
        host = header_value(headers_of(bytes(self.req))[0], "Host") or self.host
        scheme = "https" if self.port in (443, 8443) else "http"
        default = 443 if scheme == "https" else 80
        hostpart = host if (":" in host or self.port == default) \
            else f"{host}:{self.port}"
        return f"{scheme}://{hostpart}{t or '/'}"

    def response_text(self) -> tuple[str, bool]:
        """-> (what to store, whether the body was dropped).

        A non-text body is dropped and its absence recorded. A
        proxied browser pulls images, fonts and video, and a
        megabyte of JPEG in a Text column is neither evidence nor
        searchable.
        """
        head, body = headers_of(bytes(self.resp))
        if not head:
            return decode(bytes(self.resp)), False
        ctype = header_value(head, "Content-Type")
        if ctype and not TEXTY.match(ctype):
            return (decode(head)
                    + f"[body not stored: {ctype} is not text, "
                      f"{len(body)} bytes]"), True
        return decode(head) + decode(body), False

    def complete(self) -> bool:
        """Has a whole response arrived?

        Content-Length when it is given, the terminating chunk when
        the transfer is chunked, and otherwise never -- a response
        delimited by the connection closing is emitted when it
        closes, which the caller does.
        """
        if not self.resp:
            return False
        head, body = headers_of(bytes(self.resp))
        if not head:
            return False
        if "chunked" in header_value(head, "Transfer-Encoding").lower():
            return body.rstrip().endswith(b"0")
        n = header_value(head, "Content-Length")
        if n.isdigit():
            return len(body) >= int(n)
        # A HEAD response and a 204/304 carry no body whatever the
        # headers imply.
        return self.method == "HEAD" or self.status in (204, 304)

    def worth_storing(self) -> bool:
        """A request we could actually read, with something back."""
        return bool(self.method and self.resp)


# ------------------------------------------------------- recording
#
# Separated from the parsing above so the parser can be tested
# without a database, and so a failure to write can never take down
# a relay: an operator's browser must not stall because a capture
# could not be stored.

log = logging.getLogger("oddjob.proxycapture")

#: What these rows say about where they came from, so a report can
#: tell a page somebody opened by hand from one a crawler reached.
SOURCE = "proxy"


async def store(project_id: int, ex: Exchange) -> bool:
    """Write one captured exchange. -> True if a row was added.

    Opens its own session: this is called from a relay task that has
    none, and borrowing the request's would tie a browser's
    connection to a database transaction for as long as the page
    takes to load.

    Scope is re-checked here. `proxyauth.decide` already ruled on the
    destination before a byte was relayed, so this is the second
    gate rather than the first -- and the one that matters for a
    keep-alive session that outlives the list which permitted it.
    """
    if not ex.worth_storing():
        return False
    from .scopegate import index_for  # late: avoids a cycle

    url = ex.url
    method = ex.method
    request = decode(bytes(ex.req))
    response, body_dropped = ex.response_text()
    host = normalise_host(ex.host)

    async with SessionLocal() as session:
        idx = await index_for(session, project_id)
        if idx.defined and not idx.check(host).allowed:
            # Refused rather than written. Not an error and not
            # silent: the connection was permitted when it opened
            # and the list has moved since, which is a fact worth a
            # line.
            log.info("proxy capture for %s discarded: no longer in scope",
                     host)
            return False

        t = (await session.execute(select(Target).where(
            Target.project_id == project_id,
            Target.host == host))).scalar_one_or_none()
        if t is None:
            # Created, because the operator deliberately browsed it
            # through this project's own Ghost and the scope gate
            # allowed it. A capture with nowhere to hang is a capture
            # discarded, which is how `web_asset_endpoints` filled up
            # with rows nothing read.
            t = Target(project_id=project_id, host=host, kind="host",
                       notes="first seen through the Ghost proxy")
            session.add(t)
            await session.flush()

        head = headers_of(bytes(ex.resp))[0]
        xk = exchange_key(method, url, request, response)
        existing = (await session.execute(select(WebAddress).where(
            WebAddress.target_id == t.id,
            WebAddress.exchange_hash == xk))).scalar_one_or_none()
        if existing is not None:
            # The identical exchange, seen again. A reload is not new
            # evidence, and the source is merged so a row first
            # recorded by a crawler says the proxy saw it too.
            existing.sources = merge_sources(existing.sources, SOURCE)
            await session.commit()
            return False

        path = (url.split("://", 1)[-1].split("/", 1) + ["/"])[1]
        session.add(WebAddress(
            target_id=t.id, url=url, url_hash=url_key(url),
            exchange_hash=xk,
            scheme="https" if url.startswith("https") else "http",
            port=ex.port, path=("/" + path)[:1024], method=method,
            status_code=ex.status,
            content_type=(header_value(head, "Content-Type") or None),
            webserver=(header_value(head, "Server") or None),
            request=request, response=response,
            truncated=(ex.req_truncated or ex.resp_truncated or body_dropped),
            sources=SOURCE))
        await session.commit()
        return True


async def store_safely(project_id: int, ex: Exchange) -> None:
    """`store`, but a failure here never reaches the relay.

    The operator's browser is the thing being protected. A capture
    that cannot be written is a lost piece of evidence and is said
    so in the log; a capture that raises into the pump would be a
    page that does not load.
    """
    try:
        await store(project_id, ex)
    except Exception:                                 # noqa: BLE001
        log.warning("could not store a proxy capture for %s", ex.host,
                    exc_info=True)
