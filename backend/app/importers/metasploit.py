"""Metasploit `db_export -f xml`.

The document is `<MetasploitV4>` or `<MetasploitV5>` with `<hosts>`,
`<services>`, `<vulns>`, `<notes>`, `<creds>`/`<credentials>`, `<loots>`,
`<web_vulns>` and `<events>`. Services and vulns reference their host by the
numeric `host-id` msf assigned, so the host table has to be indexed first and
the children resolved through it — matching on address string alone loses
every host msf knows by two names.

What msf is uniquely good for, and what makes it worth importing over a bare
nmap file: it carries **credentials** and **what was actually exploited**,
not just what was listening.
"""
from __future__ import annotations

from datetime import UTC, datetime
from xml.etree.ElementTree import ParseError  # nosemgrep: use-defused-xml

from .model import (
    UNKNOWN,
    ImportError_,
    ParsedCredential,
    ParsedHost,
    ParsedNote,
    ParsedScan,
    ParsedService,
    ParsedVuln,
    norm_severity,
)
from .safexml import fromstring


def looks_like(text: str) -> bool:
    return "<MetasploitV" in text[:4000]


def _t(el, tag: str) -> str | None:
    """Text of a child element, or None. msf writes empty elements freely."""
    if el is None:
        return None
    c = el.find(tag)
    if c is None or c.text is None:
        return None
    v = c.text.strip()
    return v or None


def _i(el, tag: str) -> int | None:
    v = _t(el, tag)
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _when(el, tag: str) -> datetime | None:
    v = _t(el, tag)
    if not v:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def parse(xml: str | bytes) -> ParsedScan:
    try:
        root = fromstring(xml.encode() if isinstance(xml, str) else xml)
    except ParseError as e:
        raise ImportError_(f"not valid XML: {e}") from e
    if not root.tag.startswith("MetasploitV"):
        raise ImportError_(
            f"expected a Metasploit export (<MetasploitV4/V5>), got <{root.tag}>. "
            f"Produce one with `db_export -f xml /path/out.xml` in msfconsole.")

    scan = ParsedScan(tool="metasploit", version=root.tag.replace("Metasploit", ""))

    # host-id -> the name we keyed the target on, so children can find it.
    by_id: dict[str, str] = {}

    for h in root.findall("hosts/host"):
        addr = _t(h, "address")
        name = _t(h, "name")
        primary = (name or addr or "").strip().rstrip(".").lower()
        if not primary:
            continue
        ph = ParsedHost(
            host=primary,
            ip_address=addr,
            mac_address=_t(h, "mac"),
            alive={"alive": True, "up": True, "down": False,
                   "dead": False}.get((_t(h, "state") or "").split("_")[-1].lower()),
            os=" ".join(x for x in (_t(h, "os-name"), _t(h, "os-flavor"),
                                    _t(h, "os-sp")) if x) or None,
            notes=_t(h, "comments"),
        )
        if name and addr and name != addr:
            ph.hostnames = [name]
        purpose = _t(h, "purpose")
        if purpose:
            ph.extra["msf_purpose"] = purpose
        if (arch := _t(h, "arch")):
            ph.extra["arch"] = arch
        hid = _t(h, "id")
        if hid:
            by_id[hid] = primary
        scan.hosts.append(ph)

    def host_name(el) -> str | None:
        hid = _t(el, "host-id")
        if hid and hid in by_id:
            return by_id[hid]
        # Fall back to an address the row carries itself; some exports
        # inline it, and an orphan is still worth keeping.
        return _t(el, "host") or _t(el, "address")

    for s in root.findall("services/service"):
        name = host_name(s)
        port = _i(s, "port")
        if not name or port is None:
            continue
        svc_name = (_t(s, "name") or "").strip()
        info = _t(s, "info")
        scan.host_for(name).services.append(ParsedService(
            port=port,
            protocol=(_t(s, "proto") or "tcp").lower(),
            state=(_t(s, "state") or "open").lower().replace("_", "|"),
            name=svc_name if svc_name and svc_name.lower() != "unknown" else UNKNOWN,
            banner_override=info,
        ))

    for v in root.findall("vulns/vuln"):
        name = host_name(v)
        if not name:
            continue
        refs = [r.text.strip() for r in v.findall("refs/ref") if r.text]
        # msf has no severity column. Anything with a CVE or an exploit
        # module behind it is not "info", but inventing a number would be
        # worse than saying so — the refs are shown and the operator rates it.
        scan.vulns.append(ParsedVuln(
            host=name,
            title=_t(v, "name") or "unnamed Metasploit vuln",
            severity=norm_severity(None, default="medium" if refs else "info"),
            description="\n".join(x for x in [
                _t(v, "info"),
                ("References: " + ", ".join(refs)) if refs else None,
            ] if x) or None,
            external_id=next((r for r in refs if r.upper().startswith("CVE-")), None)
                        or (f"msf-vuln-{_t(v, 'id')}" if _t(v, "id") else None),
            port=_i(v, "port"),
            protocol=_t(v, "proto"),
        ))

    # Credentials moved between schema versions; accept both shapes.
    for c in list(root.findall("creds/cred")) + list(root.findall("credentials/credential")):
        name = host_name(c)
        kind = (_t(c, "ptype") or _t(c, "private_type") or "password").lower()
        scan.credentials.append(ParsedCredential(
            host=name,
            username=_t(c, "user") or _t(c, "username") or _t(c, "public"),
            secret=_t(c, "pass") or _t(c, "private") or _t(c, "private_data"),
            kind=("hash" if "hash" in kind or "ntlm" in kind
                  else "key" if "key" in kind else "password"),
            service=_t(c, "sname") or _t(c, "service_name"),
            port=_i(c, "port"),
            source=f"metasploit: {_t(c, 'source-type') or _t(c, 'origin_type') or 'db_export'}",
            notes=_t(c, "proof"),
            # msf records a cred against a host because something accepted it.
            validated="works" if (_t(c, "active") or "true").lower() == "true" else "none",
        ))

    for n in root.findall("notes/note"):
        name = host_name(n)
        if not name:
            continue
        scan.notes.append(ParsedNote(
            host=name,
            summary=f"msf note: {_t(n, 'ntype') or 'note'}",
            detail=_t(n, "data"),
        ))

    for el in root.findall("loots/loot"):
        name = host_name(el)
        if not name:
            continue
        scan.notes.append(ParsedNote(
            host=name,
            summary=f"msf loot: {_t(el, 'ltype') or 'loot'} — {_t(el, 'name') or ''}".strip(" —"),
            detail="\n".join(x for x in [_t(el, "info"), _t(el, "path")] if x) or None,
        ))

    # A session means the host was compromised, which is exactly what the
    # pwned flag records. Nothing here ever clears it.
    for s in root.findall("sessions/session"):
        name = host_name(s)
        if not name:
            continue
        h = scan.host_for(name)
        h.hacked = True
        scan.notes.append(ParsedNote(
            host=name,
            summary=f"msf session: {_t(s, 'stype') or 'session'} "
                    f"via {_t(s, 'via-exploit') or 'unknown module'}",
            detail="\n".join(x for x in [
                f"payload: {_t(s, 'via-payload')}" if _t(s, "via-payload") else None,
                f"desc: {_t(s, 'desc')}" if _t(s, "desc") else None,
                f"opened: {_t(s, 'opened-at')}" if _t(s, "opened-at") else None,
                f"closed: {_t(s, 'close-reason')}" if _t(s, "close-reason") else None,
            ] if x) or None,
        ))

    for w in root.findall("web_vulns/web_vuln"):
        name = host_name(w) or _t(w, "vhost")
        if not name:
            continue
        scan.vulns.append(ParsedVuln(
            host=name,
            title=f"{_t(w, 'name') or 'web vuln'} at {_t(w, 'path') or '/'}",
            severity=norm_severity(_i(w, "confidence"), default="medium"),
            description=_t(w, "description") or _t(w, "proof"),
            external_id=f"msf-web-{_t(w, 'id')}" if _t(w, "id") else None,
            port=_i(w, "port"),
        ))

    return scan
