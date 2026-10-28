"""URLs a site used to serve, from public archives, behind a gate.

Oddjob learns URLs three ways and all three need the path to be
reachable NOW: gobuster guesses them, katana follows links to them,
httpx confirms them. Every one of those misses the same thing -- the
endpoint that was linked in 2019, removed from the navigation, and
left answering.

Public archives have those. The Wayback Machine and Common Crawl
between them hold what a site served over years, including the admin
panel that was unlinked rather than deleted and the API version
nobody retired. On an external engagement that is routinely where
the interesting path comes from, and nothing here could see it.

# Why this is off by default, and stays off until somebody says

This is the same decision `app/ctlogs.py` documents, and the answer
is the same.

Asking an archive "what URLs do you have for acme.example" **sends
the client's domain to a third party**. It is a query, logged at the
other end, naming who we are testing and when we started.

Semgrep's policy is that customer data does not go to an external
service before that service is approved, and an engagement signoff
covers testing the client, not onboarding a vendor. So
`archive.enabled` defaults to False, the source is named rather than
defaulted because choosing it IS the decision, and the help text
says what leaves and where it goes in the place somebody turns it
on.

There is no OPSEC-clean version of this the way there is for CT --
the Common Crawl index could in principle be pulled in bulk and
filtered locally, but it is petabytes and an engagement tool is not
where that pipeline belongs. Saying so is better than shipping a
half version.

# What comes back is a proposal, not an estate

Archived URLs are **reported, never crawled**. Three reasons, and
the third is the one that has actually bitten this project:

  1. An archive records what a crawler saw, not what anybody
     authorised. A host in the result may belong to someone else.
  2. A URL that existed in 2019 may 404 now, and filing a dead path
     as a finding is noise.
  3. `webtargets.crawl_seeds` keeps a deliberate one-way edge --
     gobuster feeds katana, a crawl never feeds itself -- because a
     crawl that produces more crawling took one project from 1,109
     queued tasks to 97,959 in under an hour. These URLs come from
     outside that cycle and must not be allowed to restart it.

Everything goes through `scopegate`, and anything it refuses is
listed for a person rather than dropped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

import httpx

#: Where a lookup may be sent. Named rather than defaulted, so
#: turning this on is a choice about a specific third party.
#:
#: `{domain}` is substituted with the registrable domain. Both
#: sources are asked for a flat list and nothing else -- no
#: timestamps, no snapshots, no content. We want the paths.
SOURCES: dict[str, str] = {
    "web.archive.org": (
        "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        "&output=json&fl=original&collapse=urlkey&limit=10000"),
    "urlscan.io": (
        "https://urlscan.io/api/v1/search/?q=domain%3A{domain}&size=1000"),
}

#: A lookup is one HTTP request to somebody else's service and they
#: are frequently slow. Long enough to be useful, short enough that
#: a UI is not left hanging.
TIMEOUT = 45.0

#: Hard ceiling on what one lookup contributes. An archive can hold
#: a million URLs for a large domain and a list that size is not a
#: proposal anybody can rule on.
MAX_URLS = 5000

_HOST = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

#: Paths not worth proposing. An archive is full of the site's own
#: static assets, and a list where the interesting path is buried
#: under four thousand images is a list nobody reads.
_BORING = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|avif|bmp|tiff?|"
    r"woff2?|ttf|otf|eot|"
    r"mp4|webm|avi|mov|mp3|wav|ogg|"
    r"css|map)(?:$|\?)", re.I)


class Disabled(RuntimeError):
    """Archive lookups are off, or no source has been chosen."""


@dataclass
class Found:
    domain: str
    source: str
    urls: list[str] = field(default_factory=list)
    #: Entries that were in the answer and are not usable URLs, or
    #: are static assets. Counted rather than listed: the number is
    #: what says whether the useful part is the whole answer.
    skipped: int = 0
    #: True when the archive had more than `MAX_URLS`. A truncated
    #: list that does not say so reads as a complete one.
    truncated: bool = False
    error: str | None = None


def enabled(cfg: dict) -> bool:
    """Whether archive lookups may be made at all.

    Default False, and the default is the point: an installation
    that has never thought about this sends nothing.
    """
    return bool(cfg.get("archive.enabled"))


def source_url(cfg: dict) -> tuple[str, str] | None:
    """-> (source name, url template), or None if not configured."""
    name = str(cfg.get("archive.source") or "").strip()
    if name not in SOURCES:
        return None
    return name, SOURCES[name]


def host_of(url: str) -> str:
    """The hostname in a URL, lowercased and without a port. '' if none."""
    try:
        h = (urlsplit(url).hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return ""
    return h if _HOST.match(h) else ""


def clean(raw, domain: str) -> tuple[list[str], int, bool]:
    """Archive rows -> usable URLs. -> (urls, skipped, truncated).

    Both sources answer in their own shape and neither is trusted to
    be well formed: the CDX API returns a list of one-element lists
    with a header row, urlscan returns an object of results. A row
    that is not a URL on a host under the domain asked about is
    skipped and counted.

    Deduplicated on the whole URL INCLUDING its query, because
    `?id=1` and `?id=2` are the same endpoint reached two ways and
    both are worth proposing -- the parameter names are the point.
    """
    out: list[str] = []
    seen: set[str] = set()
    skipped = 0
    d = (domain or "").strip().lower().rstrip(".")

    def take(value) -> None:
        nonlocal skipped
        u = str(value or "").strip()
        if not u or not u.lower().startswith(("http://", "https://")):
            skipped += 1
            return
        h = host_of(u)
        # Only the domain we asked about. An archive answering with
        # someone else's host is an archive we must not turn into a
        # target proposal.
        if not h or not (h == d or h.endswith("." + d)):
            skipped += 1
            return
        if _BORING.search(u):
            skipped += 1
            return
        u = unquote(u).strip()
        if len(u) > 2000:
            skipped += 1
            return
        if u not in seen:
            seen.add(u)
            out.append(u)

    rows = raw
    if isinstance(raw, dict):
        # urlscan: {"results": [{"page": {"url": ...}}, ...]}
        rows = raw.get("results") or []
        for r in rows:
            page = (r or {}).get("page") if isinstance(r, dict) else None
            take((page or {}).get("url") if isinstance(page, dict) else None)
    elif isinstance(raw, list):
        # CDX: [["original"], ["https://..."], ...] -- the first row
        # is the field header and is not a result.
        for i, r in enumerate(rows):
            if isinstance(r, list):
                if i == 0 and r and str(r[0]).lower() == "original":
                    continue
                take(r[0] if r else None)
            else:
                take(r)
    else:
        return [], 0, False

    truncated = len(out) > MAX_URLS
    return sorted(out)[:MAX_URLS], skipped, truncated


async def lookup(cfg: dict, domain: str) -> Found:
    """Ask the configured archive what URLs it holds for `domain`.

    **This sends `domain` to a third party.** The gate is checked
    here rather than only at the caller, so there is one place that
    can be audited for it -- the same shape `ctlogs.lookup` uses,
    deliberately, because they are the same decision.
    """
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return Found(domain=domain, source="", error="no domain given")
    if not enabled(cfg):
        raise Disabled(
            "Archived-URL lookups are off. Turning them on sends this "
            "engagement's domain names to a third party, which needs to be "
            "an explicit decision — see Site settings.")
    picked = source_url(cfg)
    if picked is None:
        raise Disabled(
            "No archive source is configured. Choose one in Site settings; "
            "the choice is which third party the domain goes to, and the "
            f"options are: {', '.join(SOURCES)}.")
    name, template = picked

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT,
                                     follow_redirects=True) as c:
            r = await c.get(template.format(domain=d),
                            headers={"Accept": "application/json"})
            r.raise_for_status()
            body = r.json()
    except json.JSONDecodeError:
        return Found(domain=d, source=name,
                     error="the archive answered with something that is not "
                           "JSON, which usually means a rate limit page")
    except httpx.HTTPStatusError as e:
        return Found(domain=d, source=name,
                     error=f"the archive answered {e.response.status_code}")
    except Exception as e:                            # noqa: BLE001
        # Named rather than swallowed. "No archived URLs" and "the
        # lookup failed" are different answers and only one of them
        # is about the client.
        return Found(domain=d, source=name,
                     error=f"the lookup did not complete: {e}")

    urls, skipped, truncated = clean(body, d)
    return Found(domain=d, source=name, urls=urls, skipped=skipped,
                 truncated=truncated)
