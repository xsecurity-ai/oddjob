"""Nessus / Tenable `.nessus` v2.

`<NessusClientData_v2><Report><ReportHost name="…">` with a `<HostProperties>`
bag of `<tag name="…">` and one `<ReportItem>` per finding. The host's real
identity lives in those tags — `host-ip`, `host-fqdn`, `netbios-name`,
`operating-system` — not in the `name` attribute, which is whatever the scan
was pointed at.

Severity is the `severity` attribute 0-4. Plugin 0 is Nessus's own
"service detection" family: those are inventory, not findings, so they
populate services and are not filed as vulns. Importing them as findings is
how a report ends up with four hundred informational rows that say "a web
server is running on 443".
"""
from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError  # nosemgrep: use-defused-xml

from .safexml import fromstring

from .model import (UNKNOWN, ImportError_, ParsedHost, ParsedScan,
                    ParsedService, ParsedVuln, norm_severity)

#: Plugin families that describe what is listening rather than what is wrong.
_INVENTORY_FAMILIES = {"Service detection", "Port scanners", "General"}


def looks_like(text: str) -> bool:
    head = text[:4000]
    return "<NessusClientData_v2" in head or ("<Policy" in head and "<Report" in head)


def parse(xml: str | bytes) -> ParsedScan:
    try:
        root = fromstring(xml.encode() if isinstance(xml, str) else xml)
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    if root.tag != "NessusClientData_v2":
        raise ImportError_(
            f"expected a Nessus v2 export (<NessusClientData_v2>), got <{root.tag}>.")

    scan = ParsedScan(tool="nessus")
    report = root.find("Report")
    if report is not None and report.get("name"):
        scan.summary = report.get("name")

    for rh in root.findall(".//ReportHost"):
        tags = {t.get("name"): (t.text or "").strip()
                for t in rh.findall("HostProperties/tag") if t.get("name")}
        ip = tags.get("host-ip")
        fqdn = tags.get("host-fqdn") or tags.get("hostname")
        netbios = tags.get("netbios-name")
        # Prefer a name over an address, the same rule the nmap importer
        # uses, so the same box imported by both tools lands on one target.
        primary = (fqdn or rh.get("name") or ip or "").strip().rstrip(".").lower()
        if not primary:
            continue

        names = [n.strip().rstrip(".").lower()
                 for n in (fqdn, rh.get("name"), netbios) if n]
        host = ParsedHost(
            host=primary,
            ip_address=ip or (rh.get("name") if _is_ip(rh.get("name")) else None),
            mac_address=(tags.get("mac-address") or "").split("\n")[0].strip() or None,
            hostnames=list(dict.fromkeys(names)),
            os=tags.get("operating-system", "").split("\n")[0].strip() or None,
            alive=True,       # it is in the report, so it answered something
        )
        for k in ("system-type", "host-rdns", "scan-start", "scan-end"):
            if tags.get(k):
                host.extra[k.replace("-", "_")] = tags[k]
        scan.hosts.append(host)

        for item in rh.findall("ReportItem"):
            _item(scan, host, item)

    return scan


def _item(scan: ParsedScan, host: ParsedHost, item: Element) -> None:
    port = _int(item.get("port"))
    proto = (item.get("protocol") or "tcp").lower()
    svcname = (item.get("svc_name") or "").strip()
    plugin = item.get("pluginID") or ""
    family = (item.get("pluginFamily") or "").strip()
    sev = norm_severity(item.get("severity"))

    # Port 0 means "about the host", not about a service.
    if port:
        existing = next((s for s in host.services
                         if s.port == port and s.protocol == proto), None)
        if existing is None:
            existing = ParsedService(
                port=port, protocol=proto,
                name=svcname if svcname and svcname.lower() not in
                     ("unknown", "general", "") else UNKNOWN)
            host.services.append(existing)
        # Nessus's service-detection plugins carry the banner in their output.
        out = _text(item, "plugin_output")
        if family in _INVENTORY_FAMILIES and out and not existing.banner_override:
            first = out.strip().splitlines()
            if first:
                existing.banner_override = first[0][:400]

    if family in _INVENTORY_FAMILIES and sev == "info":
        return      # inventory, already recorded as a service

    cves = [c.text.strip() for c in item.findall("cve") if c.text]
    solution = _text(item, "solution")
    output = _text(item, "plugin_output")
    cvss3 = _text(item, "cvss3_base_score")
    see_also = _text(item, "see_also")
    body = "\n\n".join(x for x in [
        _text(item, "synopsis"),
        _text(item, "description"),
        f"Output:\n{output}" if output else None,
        ("CVE: " + ", ".join(cves)) if cves else None,
        f"CVSS v3 base: {cvss3}" if cvss3 else None,
        f"See also:\n{see_also}" if see_also else None,
    ] if x) or None

    scan.vulns.append(ParsedVuln(
        host=host.host,
        title=item.get("pluginName") or f"Nessus plugin {plugin}",
        # A CVSS score, where present, is a better signal than the coarse
        # 0-4 band, but never downgrades what Nessus itself flagged.
        severity=_worst(sev, norm_severity(cvss3, default="info")),
        description=body,
        external_id=f"nessus-{plugin}" if plugin else None,
        remediation=solution,
        port=port or None,
        protocol=proto if port else None,
    ))


_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _worst(a: str, b: str) -> str:
    return a if _RANK.get(a, 0) >= _RANK.get(b, 0) else b


def _text(el: Element, tag: str) -> str | None:
    c = el.find(tag)
    if c is None or not c.text:
        return None
    return c.text.strip() or None


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _is_ip(v: str | None) -> bool:
    if not v:
        return False
    import ipaddress
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False
