"""masscan, in all three of its output formats.

`-oX` is nmap-shaped (it says so: `<nmaprun scanner="masscan">`), so that
path reuses the nmap parser wholesale. `-oJ` is a JSON array of
`{ip, ports:[{port, proto, status, reason, ttl, service{name,banner}}]}`,
and `-oL` is the grepable `open tcp 443 1.2.3.4 1699999999` list.

masscan only ever reports that a port answered. It does no service
detection, so every service lands as UNKNOWN unless a banner grab
(`--banners`) filled one in — which is exactly the distinction UNKNOWN
exists to record.
"""
from __future__ import annotations

import json

from .model import (UNKNOWN, ImportError_, ParsedScan, ParsedService)
from . import nmap as _nmap


def looks_like(text: str) -> bool:
    head = text[:4000]
    if 'scanner="masscan"' in head:
        return True
    if head.lstrip().startswith(("[", "{")) and '"ports"' in head and '"ip"' in head:
        return True
    # grepable: "open tcp 443 10.0.0.1 1699999999"
    for line in head.splitlines():
        parts = line.split()
        if len(parts) == 5 and parts[0] in ("open", "closed") \
                and parts[1] in ("tcp", "udp", "sctp") and parts[2].isdigit():
            return True
    return False


def parse(text: str) -> ParsedScan:
    stripped = text.lstrip()
    if stripped.startswith("<"):
        scan = _nmap.parse(text)
        scan.tool = "masscan"
        return scan
    if stripped.startswith(("[", "{")):
        return _json(text)
    return _list(text)


def _json(text: str) -> ParsedScan:
    try:
        doc = json.loads(text)
    except ValueError:
        # masscan's -oJ trails a stray comma and sometimes omits the closing
        # bracket when interrupted; salvage it rather than refusing the file.
        doc = json.loads("[" + text.strip().strip(",").lstrip("[").rstrip("]") + "]")
    if isinstance(doc, dict):
        doc = [doc]
    scan = ParsedScan(tool="masscan")
    for rec in doc:
        if not isinstance(rec, dict) or not rec.get("ip"):
            continue
        host = scan.host_for(str(rec["ip"]).strip().lower())
        host.ip_address = str(rec["ip"])
        host.alive = True
        for p in rec.get("ports") or []:
            port = _int(p.get("port"))
            if port is None:
                continue
            # Only open ports are recorded, same rule as the nmap
            # reader. masscan reports "closed" when run with --banners
            # against a refused port, and a refusal is not a service.
            if str(p.get("status") or "open").lower() != "open":
                continue
            svc = (p.get("service") or {}) if isinstance(p.get("service"), dict) else {}
            name = str(svc.get("name") or "").strip()
            host.services.append(ParsedService(
                port=port,
                protocol=str(p.get("proto") or "tcp").lower(),
                state=str(p.get("status") or "open").lower(),
                name=name if name and name.lower() != "unknown" else UNKNOWN,
                reason=str(p.get("reason")) if p.get("reason") else None,
                banner_override=str(svc.get("banner"))[:400] if svc.get("banner") else None,
            ))
    if not scan.hosts:
        raise ImportError_("no masscan records in this JSON")
    return scan


def _list(text: str) -> ParsedScan:
    scan = ParsedScan(tool="masscan")
    n = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4 or parts[1] not in ("tcp", "udp", "sctp"):
            continue
        state, proto, port, ip = parts[0], parts[1], parts[2], parts[3]
        if not port.isdigit():
            continue
        if state.lower() != "open":
            continue
        host = scan.host_for(ip.lower())
        host.ip_address = ip
        host.alive = True
        host.services.append(ParsedService(
            port=int(port), protocol=proto, state=state, name=UNKNOWN))
        n += 1
    if not n:
        raise ImportError_(
            "no masscan list lines found — expected `open tcp 443 10.0.0.1 <ts>`")
    return scan


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
