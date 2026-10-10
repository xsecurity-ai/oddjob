"""Parse nmap XML into the shapes Oddjob stores.

Covers what `nmap -sV -O -A` produces, which is the union of service/version
detection, OS fingerprinting, traceroute and the `default` NSE category --
plus any other scripts that were asked for, since the XML format is the same
for all of them.

Two rules the rest of the code depends on:

* A port that answered but could not be identified is named `UNKNOWN`, never
  left blank. Blank reads as "not looked at"; this host was looked at and the
  service resisted identification, which is a different and often more
  interesting fact.

* Nothing nmap reported is discarded. Anything without a column of its own is
  kept as JSON on `extra`/`scripts`. Parsers that keep only the fields the
  current UI happens to show are how a scan has to be re-run months later.

Parsing is read-only and takes no network: it accepts a file someone else's
scanner produced, so it is treated as untrusted input. External entities are
disabled, and a malformed document raises rather than yielding a half-host.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from xml.etree.ElementTree import Element, ParseError  # nosemgrep: use-defused-xml

from ..portcoverage import technique_from_scan
from .model import UNKNOWN, ImportError_, ParsedHost, ParsedScan, ParsedService
from .safexml import fromstring


class NmapParseError(ImportError_):
    pass


def looks_like(text: str) -> bool:
    head = text[:4000]
    return "<nmaprun" in head and "masscan" not in head[:200].lower()


def parse(xml: str | bytes) -> ParsedScan:
    """-> ParsedScan, or raise NmapParseError."""
    try:
        # resolve_entities is off by default in ElementTree, and it has no
        # DTD processing, so a document cannot pull in a local file. Said
        # explicitly because this is parsing a file from outside.
        root = fromstring(xml.encode() if isinstance(xml, str) else xml)
    except ParseError as e:
        raise NmapParseError(f"not valid XML: {e}") from e
    if root.tag != "nmaprun":
        raise NmapParseError(
            f"expected an nmap XML document (<nmaprun>), got <{root.tag}>. "
            f"Run nmap with -oX to produce one.")

    scan = ParsedScan(tool="nmap", args=root.get("args"), version=root.get("version"))
    if (start := root.get("start")) and start.isdigit():
        scan.started = datetime.fromtimestamp(int(start), tz=UTC)
    if (fin := root.find("runstats/finished")) is not None:
        scan.summary = fin.get("summary")

    # What nmap says it actually did. There is one <scaninfo> per
    # technique, so `-sS -sU` in one run yields two, and each carries
    # the exact port list that technique covered.
    #
    # Taken from here rather than from `args` because the two disagree
    # in the case that matters: -sS without raw sockets silently runs
    # a connect scan, and only scaninfo records that it did.
    for si in root.findall("scaninfo"):
        tech = technique_from_scan(si.get("type"), scan.args)
        if tech is None:
            continue   # ack/window scans and the like are not coverage
        proto = (si.get("protocol") or "tcp").strip().lower()
        services = si.get("services")
        if not services:
            continue   # nothing to record a range against
        scan.coverage.append((tech, proto, services))

    for h in root.findall("host"):
        parsed = _host(h)
        if parsed is not None:
            scan.hosts.append(parsed)
    return scan


# ------------------------------------------------------------------ hosts
def _host(el: Element) -> ParsedHost | None:
    addrs = {a.get("addrtype"): a for a in el.findall("address")}
    ipv4 = addrs.get("ipv4", {}).get("addr") if "ipv4" in addrs else None
    ipv6 = addrs.get("ipv6", {}).get("addr") if "ipv6" in addrs else None
    mac = addrs.get("mac")

    names = [n.get("name") for n in el.findall("hostnames/hostname") if n.get("name")]
    # Deduplicate but keep nmap's order: the PTR and the user-supplied name
    # are often the same, and the first is the one nmap considered primary.
    names = list(dict.fromkeys(n.strip().rstrip(".").lower() for n in names if n))

    primary = names[0] if names else (ipv4 or ipv6)
    if not primary:
        return None          # nothing to key a target on

    out = ParsedHost(
        host=primary, ip_address=ipv4, ipv6_address=ipv6,
        mac_address=mac.get("addr") if mac is not None else None,
        mac_vendor=mac.get("vendor") if mac is not None else None,
        hostnames=names,
    )

    st = el.find("status")
    if st is not None and st.get("state"):
        # "up" and "down" are claims; anything else nmap emits is not, so it
        # stays None rather than being forced into one of the two.
        out.alive = {"up": True, "down": False}.get(st.get("state"))
        if st.get("reason"):
            out.extra["status_reason"] = st.get("reason")

    _os(el, out)
    _host_extras(el, out)

    for p in el.findall("ports/port"):
        svc = _port(p)
        if svc is not None:
            out.services.append(svc)

    # Ports nmap collapsed into a summary line rather than listing.
    ignored = [{"state": x.get("state"), "count": _int(x.get("count")),
                "protocol": x.get("proto")}
               for x in el.findall("ports/extraports")]
    if ignored:
        out.extra["extraports"] = ignored
    return out


def _os(el: Element, out: ParsedHost) -> None:
    matches = []
    for m in el.findall("os/osmatch"):
        acc = _int(m.get("accuracy"))
        classes = [{
            "type": c.get("type"), "vendor": c.get("vendor"),
            "family": c.get("osfamily"), "gen": c.get("osgen"),
            "accuracy": _int(c.get("accuracy")),
            "cpe": [x.text for x in c.findall("cpe") if x.text],
        } for c in m.findall("osclass")]
        matches.append({"name": m.get("name"), "accuracy": acc, "classes": classes})
    if matches:
        best = max(matches, key=lambda m: m["accuracy"] or 0)
        out.os, out.os_accuracy = best["name"], best["accuracy"]
        # Every candidate is kept: a 92/90 split between two operating
        # systems is a materially different result from a single 92, and
        # storing only the winner hides that completely.
        out.extra["os_matches"] = matches
    if (used := el.findall("os/portused")):
        out.extra["os_portsused"] = [
            {"state": p.get("state"), "proto": p.get("proto"), "port": _int(p.get("portid"))}
            for p in used]
    if (fp := el.find("os/osfingerprint")) is not None and fp.get("fingerprint"):
        out.extra["os_fingerprint"] = fp.get("fingerprint")


def _host_extras(el: Element, out: ParsedHost) -> None:
    if (u := el.find("uptime")) is not None:
        out.extra["uptime"] = {"seconds": _int(u.get("seconds")),
                               "last_boot": u.get("lastboot")}
    if (d := el.find("distance")) is not None:
        out.extra["distance"] = _int(d.get("value"))
    for tag, key in (("tcpsequence", "tcp_sequence"),
                     ("ipidsequence", "ipid_sequence"),
                     ("tcptssequence", "tcpts_sequence")):
        if (s := el.find(tag)) is not None:
            out.extra[key] = dict(s.attrib)
    if (tr := el.find("trace")) is not None:
        out.extra["traceroute"] = {
            "port": _int(tr.get("port")), "protocol": tr.get("proto"),
            "hops": [{"ttl": _int(h.get("ttl")), "ip": h.get("ipaddr"),
                      "rtt": h.get("rtt"), "host": h.get("host")}
                     for h in tr.findall("hop")]}
    # Host-level NSE: whole-host scripts such as smb-os-discovery.
    hs = {s.get("id"): _script_text(s) for s in el.findall("hostscript/script") if s.get("id")}
    if hs:
        out.extra["hostscripts"] = hs


# ------------------------------------------------------------------ ports
def _port(el: Element) -> ParsedService | None:
    portid = _int(el.get("portid"))
    if portid is None:
        return None
    state_el = el.find("state")
    state = (state_el.get("state") if state_el is not None else None) or "unknown"
    # Only open ports are recorded.
    #
    # A UDP probe that gets no reply is indistinguishable from one a
    # firewall dropped, and nmap says so honestly: "open|filtered". A
    # closed TCP port is a reply, but it is a reply saying there is
    # nothing there. Neither is a service, and importing them buried
    # the real findings: one -sU sweep of 2,051 hosts produced 42,890
    # open|filtered rows against 13 genuinely open ports, which made
    # every port count in the UI meaningless.
    #
    # The scan is still recorded against the host, so the coverage —
    # "we looked at this and found nothing" — is not lost. What is
    # dropped is the claim that a service exists.
    if state != "open":
        return None

    s = el.find("service")
    name = (s.get("name") if s is not None else None) or ""
    name = name.strip()
    # nmap writes "unknown" itself when a probe came back unrecognised, and
    # writes nothing at all when -sV never ran. Both become UNKNOWN: the port
    # is open and we cannot say what is behind it.
    if not name or name.lower() in ("unknown", "unrecognized"):
        name = UNKNOWN

    svc = ParsedService(
        port=portid,
        protocol=(el.get("protocol") or "tcp").lower(),
        state=state,
        name=name,
        reason=state_el.get("reason") if state_el is not None else None,
    )
    if s is not None:
        svc.product = s.get("product")
        svc.version = s.get("version")
        svc.extrainfo = s.get("extrainfo")
        svc.tunnel = s.get("tunnel")
        svc.method = s.get("method")
        svc.confidence = _int(s.get("conf"))
        svc.cpe = [c.text for c in s.findall("cpe") if c.text]
    svc.scripts = {x.get("id"): _script_text(x)
                   for x in el.findall("script") if x.get("id")}
    return svc


def _script_text(el: Element) -> str:
    """NSE output as text, falling back to its structured form.

    Most scripts set @output. Some only emit <table>/<elem> children, and for
    those the attribute is empty -- returning "" there would silently drop
    the entire result of, for example, ssl-cert.
    """
    out = (el.get("output") or "").strip()
    if out:
        return out
    structured = _elem(el)
    return json.dumps(structured, indent=2) if structured else ""


def _elem(el: Element):
    """<table>/<elem> tree -> dict/list/str."""
    children = [c for c in el if c.tag in ("table", "elem")]
    if not children:
        return (el.text or "").strip()
    keyed = {c.get("key"): _elem(c) for c in children if c.get("key")}
    rest = [_elem(c) for c in children if not c.get("key")]
    if keyed and not rest:
        return keyed
    if rest and not keyed:
        return rest
    return {"items": rest, **keyed}


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
