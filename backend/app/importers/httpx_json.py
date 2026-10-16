"""projectdiscovery httpx `-json` / `-jsonl`, and naabu's JSONL.

httpx: `{url, input, host, port, scheme, status_code, title, webserver,
tech, content_length, a, cname, cdn_name, asn, favicon, jarm_hash,
tls}` — a live-web inventory, not a findings tool, so it produces
targets and services and no vulns.

**The `tls` block is read, and was not.** This parsed sixteen fields
and the certificate was not among them, which threw away the richest
source of hostnames in the whole ingest: a cert names every host it
is valid for. See `_tls`.

naabu emits `{host, ip, port, protocol}` and nothing else; it is handled
here rather than in its own module because the ingest is identical and a
separate file would be ten lines of the same thing.

Named `httpx_json` because `httpx` is also the HTTP client this app uses —
shadowing it inside the package would be a genuinely nasty import bug.
"""
from __future__ import annotations

from . import certnames
from .model import ImportError_, ParsedScan, ParsedService, ParsedWebAddress
from .nuclei import iter_json


def looks_like(text: str) -> bool:
    head = text.lstrip()[:4000]
    if '"template-id"' in head:
        return False          # nuclei, which also carries a host field
    return (('"status_code"' in head or '"status-code"' in head)
            and ('"url"' in head or '"input"' in head)) \
        or ('"port"' in head and '"host"' in head and '"ip"' in head
            and '"protocol"' in head)


def parse(text: str) -> ParsedScan:
    scan = ParsedScan(tool="httpx")
    seen = False
    for o in iter_json(text):
        name = str(o.get("host") or o.get("input") or "").strip().lower()
        # httpx's `host` is sometimes the resolved IP and `input` the name;
        # prefer whichever is not an address so targets merge with DNS-named
        # ones from other tools.
        inp = str(o.get("input") or "").strip().lower()
        if inp and _is_ip(name) and not _is_ip(inp):
            name, ip_guess = inp.split(":")[0], name
        else:
            ip_guess = str(o.get("ip") or "") or None
        name = name.split("://")[-1].split("/")[0].split(":")[0]
        if not name:
            continue
        seen = True

        host = scan.host_for(name)
        host.alive = True
        if ip_guess and not host.ip_address and _is_ip(ip_guess):
            host.ip_address = ip_guess
        if o.get("ip") and not host.ip_address:
            host.ip_address = str(o["ip"])

        port = _int(o.get("port"))
        scheme = str(o.get("scheme") or "").lower()
        if port is None and scheme:
            port = 443 if scheme == "https" else 80
        if port is None:
            continue

        proto = str(o.get("protocol") or "tcp").lower()
        if proto not in ("tcp", "udp", "sctp"):
            proto = "tcp"
        svc = next((s for s in host.services
                    if s.port == port and s.protocol == proto), None)
        if svc is None:
            svc = ParsedService(port=port, protocol=proto, state="open",
                                name=scheme or "UNKNOWN")
            host.services.append(svc)
        if scheme:
            svc.name = scheme
            svc.tunnel = "ssl" if scheme == "https" else svc.tunnel

        tech = o.get("tech") or o.get("technologies")
        bits = [
            str(o.get("webserver")) if o.get("webserver") else None,
            f'"{o["title"]}"' if o.get("title") else None,
            f'HTTP {o["status_code"]}' if o.get("status_code") else None,
            ("tech: " + ", ".join(map(str, tech))) if isinstance(tech, list) and tech else None,
        ]
        line = " · ".join(b for b in bits if b)
        if line:
            svc.banner_override = line[:400]
        if o.get("webserver"):
            svc.product = str(o["webserver"])[:255]
        for k in ("cname", "cdn_name", "cdn", "cdn_type"):
            if o.get(k):
                host.extra.setdefault("httpx", {})[k] = o[k]
        # Who owns the address, which is the question every ownership
        # ruling turns on and which nothing else here answers.
        #
        # Kept, but httpx is no longer the thing that fills it: v1.12
        # resolves ASNs through ProjectDiscovery's hosted service, so
        # `-asn` reports null without a PDCP key and sends every address
        # we ask about to a third party with one. The agent does not pass
        # the flag, and nothing is lost by that: `geoip.tag_missing`
        # already writes `geo_asn` and `geo_org` onto every TargetAddress
        # from the local GeoLite2-ASN database, which is the same answer
        # without the egress. This branch stays so that a capture made
        # elsewhere, or by a future httpx that answers offline, is still
        # read rather than dropped.
        if isinstance(asn := o.get("asn"), dict):
            host.extra.setdefault("httpx", {})["asn"] = {
                k: asn[k] for k in ("as_number", "as_name", "as_country")
                if asn.get(k)}
        # The two fingerprints that pivot. A favicon mmh3 hash is the
        # same number on every host serving that icon, so one hit names
        # the rest of an estate -- including addresses no name resolves
        # to. JARM does the same for the TLS stack underneath.
        #
        # Recorded per host, not per URL, because there is nowhere on a
        # web row to put them without a migration. A host serving two
        # apps with two icons keeps whichever httpx reported last; the
        # pivot still works, the completeness does not. Worth a column
        # if that case ever turns up for real.
        for src, dst in (("favicon", "favicon_mmh3"),
                         ("favicon_md5", "favicon_md5"),
                         ("favicon_path", "favicon_path"),
                         ("jarm_hash", "jarm")):
            if o.get(src):
                host.extra.setdefault("httpx", {})[dst] = str(o[src])[:128]
        # Every A record, not just the one that became `ip_address`.
        # A name on four addresses is four hosts to account for.
        if isinstance(a := o.get("a"), list) and a:
            host.extra.setdefault("httpx", {})["a"] = [str(x) for x in a][:32]

        _tls(o.get("tls"), host)

        # httpx fetched it, so this is a crawled address, not a guess.
        url = str(o.get("url") or "").strip()
        if url:
            scan.web.append(ParsedWebAddress(
                url=url, host=name, scheme=scheme or "http", port=port,
                status_code=_int(o.get("status_code") or o.get("status-code")),
                title=str(o["title"])[:512] if o.get("title") else None,
                content_type=(str(o.get("content_type")
                                  or o.get("content-type") or "")[:128] or None),
                content_length=_int(o.get("content_length") or o.get("content-length")),
                webserver=str(o["webserver"])[:255] if o.get("webserver") else None,
                tech=[str(t) for t in tech] if isinstance(tech, list) else [],
                crawled=True,
                # Present when httpx was run with `-irr`. It knows
                # what it sent and what came back; reporting only
                # that the address is alive throws away the part a
                # tester reads.
                request=(str(o["request"])[:200000] if o.get("request") else None),
                response=(str(o["response"])[:2000000]
                          if o.get("response") else None),
            ))
    if not seen:
        raise ImportError_("no httpx/naabu records found")
    return scan


#: Cert fields worth keeping, and no more. `fingerprint_hash` and the
#: full DNs are not here: they are long, they are not read by
#: anything, and a column of noise is how the useful fields stop
#: being looked at.
_TLS_KEEP = ("tls_version", "cipher", "not_after", "not_before",
             "subject_cn", "issuer_cn", "issuer_org", "self_signed",
             "expired", "mismatched", "wildcard_certificate")


def _tls(tls, host) -> None:
    """The certificate, onto the host that presented it.

    **SANs are the point.** A certificate names every host it is
    valid for, which on a real estate is the single richest source
    of names nothing else has recorded -- and it was being thrown
    away entirely: this importer read sixteen fields and `tls` was
    not one of them.

    They go into `hostnames`, which is a JSON list on the host that
    ALREADY EXISTS. Deliberately not new targets. A shared or
    CDN-issued certificate names hundreds of other people's hosts,
    and a scan that quietly created targets from a SAN list would be
    scanning things nobody cleared. As alternate names they are
    evidence attached to a host we already have, `roots.py` already
    mines them for zones worth enumerating, and promoting one to a
    target stays a decision somebody makes.

    Tolerant by construction: httpx's schema has moved between
    versions and an older build omits half of this. A field that is
    not there is skipped, never defaulted -- "the cert did not say"
    and "the cert said no" are different facts, and `self_signed`
    is exactly the one where guessing would be a finding.
    """
    if not isinstance(tls, dict):
        return
    keep = {k: tls[k] for k in _TLS_KEEP if tls.get(k) is not None}
    if keep:
        host.extra.setdefault("tls", {}).update(keep)

    # The rule for what counts as a name lives in `certnames`, shared
    # with the nmap importer's `ssl-cert` parsing. Two copies of it
    # drifting apart is how one importer starts creating `*.example`
    # as a host while the other does not.
    names = certnames.san_names(tls.get("subject_an"))
    if cn := certnames.clean_name(tls.get("subject_cn")):
        names.insert(0, cn)
    certnames.add_names(host, names)


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _is_ip(v: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(v.split(":")[0])
        return True
    except ValueError:
        return False
