"""Virtual-host discovery from the Ghost's in-process gobuster.

`{"url", "domain", "wordlist", "found": [name, ...], "hits": [{...}],
"wildcard": {...}}` -- the shape `tasks/vhost.go` writes.

**What a hit here is, and is not.** A name in this list answered on
THIS ADDRESS when it was asked for by name. That is evidence about
the address, not about DNS: `intranet.acme.example` returning 200 on
10.0.0.5 does not mean the name resolves anywhere, and frequently it
does not. That is the entire finding -- an application reachable
only by asking for it, invisible to anything that scans the names it
already knew.

So hits become **alternate hostnames on the target that answered**,
the way a certificate's SANs do in `certnames.py`, and for the same
reason: the address is already in the engagement, the name is a fact
about it, and promoting either to a new target would be scanning
something nobody cleared.

**No web addresses are written.** It is tempting, because a 200 is a
reachable application and the Web view is where someone would look
for it. But a `WebAddress` of `https://intranet.acme.example/` is a
claim that the URL works, and for a vhost-only name it does not --
it works on one address with one Host header. Writing it would put a
URL in the inventory that nobody who clicks it can reach, which is
worse than not writing it. The names are on the target, the raw
result is on the task, and the finding is legible from both.

**The wildcard matters more than the hits.** A host that answers
every Host header makes every word in the wordlist a "hit". The
agent probes for that before sweeping and excludes the matching
length, and it reports what it found either way -- so a run against
a wildcard reads as "0 found, wildcard answers 200 at 1,432 bytes"
rather than as a clean zero. That is carried through to the note
here, because "found nothing" and "could not tell" are different
answers.
"""
from __future__ import annotations

import json

from .model import ImportError_, ParsedScan

#: The built-in wordlist is 4,751 entries. A ceiling well above it is
#: a backstop against a catch-all host that defeats the wildcard
#: probe turning one task into an unbounded write.
MAX_HITS = 20000


def looks_like(text: str) -> bool:
    head = text.lstrip()[:2000]
    if not head.startswith("{"):
        return False
    # `"found"` and `"wordlist"` are BOTH shared with content
    # discovery -- this writes the same two keys, so either alone
    # would match a gobuster result and import it as vhosts. The
    # discriminator has to be a key only this produces.
    return '"vhost"' in head or ('"domain"' in head and '"found"' in head
                                 and '"hits"' in head)


def parse(text: str) -> ParsedScan:
    try:
        o = json.loads(text)
    except (ValueError, TypeError) as e:
        raise ImportError_(f"not vhost JSON: {e}") from e
    if not isinstance(o, dict):
        raise ImportError_("vhost output is not an object")

    scan = ParsedScan(tool="vhost")
    url = str(o.get("url") or "").strip()
    # The target is the thing that ANSWERED, which is whatever the
    # task was pointed at -- an address or a name. The discovered
    # vhosts hang off it; they are not targets themselves.
    origin = url.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
    if not origin:
        raise ImportError_("vhost output names no url")

    host = scan.host_for(origin)
    host.alive = True

    names: list[str] = []
    seen: set[str] = set()
    for h in (o.get("hits") or [])[:MAX_HITS]:
        if not isinstance(h, dict):
            continue
        n = str(h.get("vhost") or "").strip().lower().rstrip(".")
        if not n or n == origin or n in seen:
            continue
        seen.add(n)
        names.append(n)
    # `found` is the same set as a plain list, kept because older
    # results carry it and a reader that only has that should still
    # import.
    if not names:
        for n in (o.get("found") or [])[:MAX_HITS]:
            n = str(n).strip().lower().rstrip(".")
            if n and n != origin and n not in seen:
                seen.add(n)
                names.append(n)

    host.hostnames.extend(names)

    wc = o.get("wildcard") or {}
    if isinstance(wc, dict) and wc.get("answers"):
        # Said plainly on the host, because a reader who sees no new
        # names needs to know which of the two reasons applies.
        host.notes = (
            f"vhost sweep of {origin}: this address answers ANY Host header "
            f"(status {wc.get('status')}, {wc.get('size')} bytes). Responses "
            f"matching that length were excluded, so a short list here means "
            f"the wildcard hid them, not that nothing is there."
        )
    return scan
