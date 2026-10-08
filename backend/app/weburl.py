"""Normalising a URL so the same page is one row however it was found.

httpx reports `https://shop.corp.local`, Burp reports
`https://shop.corp.local:443/` and nuclei reports
`https://SHOP.corp.local/` — three spellings of one address. Without a
canonical form the web table becomes a list of spellings rather than a list
of pages, which is exactly the thing it exists to prevent.

The rules are deliberately conservative. Case and the default port are not
meaningful, so they are normalised away. A trailing slash on a non-root path
and a query string *are* potentially meaningful, so they are kept: `/admin`
and `/admin/` can be different handlers, and dropping `?id=2` would collapse
every parameterised page into one row.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass
class Url:
    url: str
    scheme: str
    host: str
    port: int
    path: str


class BadUrl(ValueError):
    pass


def parse(raw: str, *, base_host: str | None = None,
          base_scheme: str = "http", base_port: int | None = None) -> Url:
    """-> Url, or raise BadUrl.

    `base_*` let a relative path from a tool that only reports paths (Nikto
    gives `/admin/`, not a URL) be resolved against the host it was found
    on, rather than being dropped for not being absolute.
    """
    s = (raw or "").strip()
    if not s:
        raise BadUrl("empty URL")

    if s.startswith("//"):
        s = f"{base_scheme}:{s}"
    elif "://" not in s:
        if s.startswith("/"):
            if not base_host:
                raise BadUrl(f"{raw!r} is a path with no host to attach it to")
            port = base_port or DEFAULT_PORTS.get(base_scheme, 80)
            s = f"{base_scheme}://{base_host}:{port}{s}"
        else:
            s = f"{base_scheme}://{s}"

    parts = urlsplit(s)
    scheme = (parts.scheme or base_scheme).lower()
    if scheme not in ("http", "https"):
        raise BadUrl(f"{raw!r} is not an http(s) URL")
    host = (parts.hostname or "").strip().rstrip(".").lower()
    if not host:
        raise BadUrl(f"{raw!r} has no host")

    try:
        port = parts.port or base_port or DEFAULT_PORTS[scheme]
    except ValueError as e:
        raise BadUrl(f"{raw!r} has an invalid port") from e

    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # Keep the query; drop the fragment, which never reaches the server and
    # so can never distinguish two responses.
    full_path = path + (f"?{parts.query}" if parts.query else "")

    netloc = host if port == DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    return Url(url=urlunsplit((scheme, netloc, path, parts.query, "")),
               scheme=scheme, host=host, port=port, path=full_path[:1024])


def merge_sources(existing: str | None, new: str) -> str:
    """Union of tool names, order preserved, comma separated.

    A URL that both httpx and Burp reported is stronger evidence than one
    only a wordlist guessed at, so the set is worth keeping rather than
    overwriting with whichever tool ran last.
    """
    have = [x for x in (existing or "").split(",") if x]
    if new and new not in have:
        have.append(new)
    return ",".join(have)[:255]


def url_key(url: str) -> str:
    """The value uniqueness and upserts are keyed on, for a URL.

    sha256 hex. Two reasons it is not the URL itself:

    * Postgres caps a btree index entry near 2.7 KB. A proxy history in
      this engagement carried an 8,221-character URL, so the column
      simply cannot be indexed directly — the INSERT fails, not the
      query.
    * Every row of an import does one equality lookup on it. Comparing
      a fixed 64-character digest is cheaper than comparing kestrelbytes
      of query string 290,000 times.

    Hashed over UTF-8 bytes of the exact stored URL, so the key changes
    if and only if the URL does.
    """
    import hashlib
    return hashlib.sha256((url or "").encode("utf-8", "surrogatepass")).hexdigest()


def exchange_key(method: str | None, url: str,
                 request: str | None, response: str | None) -> str:
    """Identity of one captured exchange.

    sha256 over the four things that make a hit distinct: the verb, the
    URL, what was sent and what came back. Hashed rather than compared
    directly because a request and a response are each up to 48 KB, and
    Postgres cannot index that — the same reason the URL is hashed.

    A record with no captured traffic hashes over two empty strings, so
    a metadata-only sighting from httpx has a stable identity of its
    own and does not collide with a real exchange for the same URL.

    The response is hashed exactly as it was given. For a capture read
    out of a file that is right — the bytes are the artefact. For a
    response this server has just fetched itself it is not, because the
    text it builds carries the clock; see `stable_response`, which the
    replay route puts in front of this.
    """
    import hashlib
    h = hashlib.sha256()
    for part in ((method or "").upper(), url or "", request or "", response or ""):
        h.update(part.encode("utf-8", "surrogatepass"))
        h.update(b"\x1f")          # separator: "ab"+"c" must not equal "a"+"bc"
    return h.hexdigest()


#: Response headers whose value moves on its own, with nothing about the
#: server or about the answer having changed. Hashing them makes every
#: repeat of a request look like a different answer.
#:
#: Every entry here has to earn its place, because the cost of the two
#: mistakes is not symmetric. Leaving a volatile header IN costs a
#: duplicate row — the behaviour that is already there today, so a header
#: this list has never heard of fails no worse than the status quo.
#: Taking a meaningful header OUT costs a finding: two responses that
#: genuinely differ collapse into one row and the difference is never
#: seen again. So the rule is to exclude only headers that cannot carry
#: a security property, and to keep anything arguable.
_VOLATILE_RESPONSE_HEADERS = frozenset({
    "date",          # the wall clock to the second. The whole reason for this.
    "age",           # seconds spent in a cache; counts up by itself.
    "expires",       # in practice `date` plus a constant, so it moves with it.
    "keep-alive",    # `timeout=5, max=99` — connection bookkeeping, counts down.
    "server-timing",                    # per-request durations.
    "x-timer",                          # Fastly's, likewise.
    "x-envoy-upstream-service-time",    # milliseconds spent upstream.
    "cf-ray",        # Cloudflare's per-request id, not named like one.
    "x-amz-id-2",    # S3's second per-request id, likewise.
    "traceparent",   # W3C trace context: a fresh span id per request.
    "tracestate",
})

#: ...and anything whose NAME says it identifies this one request.
#: A denylist of vendor spellings never finishes — `x-amzn-RequestId`,
#: `x-github-request-id`, `ocp-apim-request-id`, `x-vcap-request-id` —
#: but they all end the same way, and a header that calls itself a
#: request id has told us it is per-request and therefore carries
#: nothing about the response. Anchored at the end so that a header
#: merely *mentioning* one of these words is left alone.
_REQUEST_ID = re.compile(r"(?:^|-)(?:request-?id|correlation-?id|trace-?id)$")


def _cookie_without_value(value: str) -> str:
    """`sessionid=9f3a...; Path=/; HttpOnly` -> `sessionid=; Path=/; HttpOnly`.

    Set-Cookie is the awkward one. Its value is usually a fresh session
    identifier on every single response, so hashing it defeats dedup as
    thoroughly as Date does — but dropping the header wholesale would
    hide the thing we actually care about, which is the attributes. "The
    session cookie stopped being HttpOnly between these two responses"
    is a finding; "the session cookie has a different random value" is
    not. Blanking just the value keeps the first and discards the second.
    """
    name, eq, rest = value.partition("=")
    if not eq:
        return value
    _val, semi, attrs = rest.partition(";")
    return name + "=" + (";" + attrs if semi else "")


def stable_response(response: str | None) -> str | None:
    """A response text with the clock taken out of it, for hashing only.

    The replay route builds the text it stores as the status line, every
    response header, and the body. Essentially every HTTP response in
    existence carries a `Date`, which has one-second resolution, so two
    byte-identical replays that straddle a second boundary produced two
    different `exchange_key`s and therefore two rows. That made the
    documented "an identical replay does not duplicate" behaviour dead
    code against any real server — it only ever fired when both replays
    landed inside the same second, which on a fast test runner they
    usually do and on a loaded one they do not. It was found as an
    intermittent CI failure, not as a theory.

    Three ways out were on the table:

    1. Hash the request plus the status code plus the body, and ignore
       response headers entirely. Simple, and wrong for this tool: a
       header-only difference is frequently the entire finding. A
       missing `HttpOnly`, a `Server` banner that changes between two
       otherwise identical answers, a CSP that is present on one path
       and absent on another — collapsing those into one row throws
       away the evidence the web table exists to hold.
    2. Normalise the response into a canonical form (sort the headers,
       lowercase the names, re-wrap the body) and hash that. Too strong
       in the other direction: header ORDER and case are themselves
       fingerprinting signal, and nothing about the bug requires
       discarding them.
    3. Hash everything except the parts that are volatile by
       construction. That is this.

    What it gives up, stated plainly:

    * A response that differs only in a header on the exclusion list is
      now the same exchange. If a cache's `Age` or a server's `Expires`
      is itself the finding, this will not record it as new evidence.
      `Cache-Control`, which carries the same policy in nearly every
      modern response, is still hashed.
    * The list is a denylist, so a vendor header that rotates per
      request and is not named like a request id — there will be some —
      still defeats dedup. That is the behaviour we already have; it is
      not made worse, it is merely not fixed everywhere.
    * Volatility inside the BODY is untouched. An app that embeds a CSRF
      token or a rendered timestamp in its HTML will still produce a new
      row per replay. Stripping that would mean parsing the body, which
      is a guess about content rather than a fact about the protocol.

    Hash-only: the row still stores the response exactly as it came back,
    `Date` and all. This changes which exchanges are considered the same,
    never what is kept as evidence of one.
    """
    if not response:
        return response
    head, sep, body = response.partition("\r\n\r\n")
    if not sep:
        # A response capped mid-headers by RESP_CAP has no blank line at
        # all, and some captures use bare LF. Neither is a reason to give
        # up and hash the volatile form.
        head, sep, body = response.partition("\n\n")
    lines = head.splitlines()
    kept = lines[:1]                    # the status line is never volatile
    dropping = False
    for line in lines[1:]:
        if line[:1] in (" ", "\t"):
            # An obs-fold continuation belongs to the header above it, so
            # it goes wherever that one went.
            if not dropping:
                kept.append(line)
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        dropping = key in _VOLATILE_RESPONSE_HEADERS or bool(_REQUEST_ID.search(key))
        if dropping:
            continue
        kept.append(f"{name}:{_cookie_without_value(value)}"
                    if key == "set-cookie" else line)
    return "\r\n".join(kept) + ("\r\n\r\n" + body if sep else "")
