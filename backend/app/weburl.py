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
    """
    import hashlib
    h = hashlib.sha256()
    for part in ((method or "").upper(), url or "", request or "", response or ""):
        h.update(part.encode("utf-8", "surrogatepass"))
        h.update(b"\x1f")          # separator: "ab"+"c" must not equal "a"+"bc"
    return h.hexdigest()
