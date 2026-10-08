"""C2 callback import: Cobalt Strike, Mythic, Merlin, Sliver, Havoc.

**On provenance, because it matters here more than for the scanners.** nmap
has `-oX`: one documented file format, stable for twenty years. The C2
frameworks have no equivalent. Each exposes its session list through an API
or a console command that can emit JSON, and the field *names* below are
taken from each framework's own data model:

  Cobalt Strike  the beacon metadata an Aggressor script sees from `&beacons`
                 — id, external, internal, computer, user, pid, os, ver,
                 arch/barch, listener, last, note. A trailing `*` on `user`
                 is CS's own marker for an elevated beacon.
  Mythic         the `callback` object — agent_callback_id, host, user, pid,
                 ip, external_ip, process_name, integrity_level (0-4),
                 architecture, domain, payload_type, init_callback,
                 last_checkin, active, description.
  Merlin         the agent record — id, hostname, username, platform,
                 architecture, process, pid, ips, integrity, initial,
                 statuscheckin, version, build.
  Sliver         `sessions`/`beacons --json` — ID, Name, Hostname, Username,
                 UID, OS, Arch, Transport, RemoteAddress, PID, Filename,
                 LastCheckin, ActiveC2, IsDead, Burned.
  Havoc          the demon table — NameID, Hostname, Username, DomainName,
                 InternalIP, ExternalIP, ProcessName, ProcessPID,
                 ProcessArch, Elevated, OSVersion, FirstCallIn, LastCallIn.

So: the names are real, but the *file* is whatever your tooling dumps. Each
parser therefore accepts a JSON array, JSONL, or an object wrapping the list
under any of the usual keys, matches field names case-insensitively, and
accepts several aliases per field. Anything it does not recognise is kept
verbatim in `extra` rather than discarded — a field this code has not heard
of is more likely a framework version we have not seen than something
worthless.

A callback means somebody has code running on that host, so importing one
sets the target's **pwned** flag and writes a timeline entry. Nothing here
ever clears the flag: losing a beacon is not evidence the access is gone.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from .model import ImportError_, ParsedImplant, ParsedScan
from .nuclei import iter_json

#: Where a framework's dump might hide the list.
_LIST_KEYS = ("beacons", "callbacks", "agents", "sessions", "demons",
              "data", "results", "items", "rows")


def _records(text: str) -> list[dict]:
    stripped = text.strip()
    if not stripped:
        raise ImportError_("empty document")
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except ValueError:
            return list(iter_json(text))
        if isinstance(doc, dict):
            for k in _LIST_KEYS:
                v = doc.get(k)
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
                # Mythic's GraphQL replies nest one level deeper.
                if isinstance(v, dict):
                    for k2 in _LIST_KEYS:
                        if isinstance(v.get(k2), list):
                            return [x for x in v[k2] if isinstance(x, dict)]
            return [doc]
    return list(iter_json(text))


def _get(rec: dict, *names, default=None):
    """Case/underscore-insensitive lookup across several possible names."""
    flat = {str(k).lower().replace("_", "").replace("-", ""): v
            for k, v in rec.items()}
    for n in names:
        key = n.lower().replace("_", "").replace("-", "")
        if key in flat and flat[key] not in (None, ""):
            return flat[key]
    return default


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _bool(v, default=None):
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "y", "active", "alive"):
        return True
    if s in ("false", "0", "no", "n", "dead", "inactive"):
        return False
    return default


def _when(v):
    """Parse the half-dozen timestamp shapes these frameworks emit."""
    if v in (None, "", 0, "0"):
        return None
    if isinstance(v, (int, float)) or str(v).strip().isdigit():
        n = float(v)
        if n > 1e11:          # milliseconds
            n /= 1000.0
        if n < 1e8:           # not a plausible epoch — likely "seconds ago"
            return None
        try:
            return datetime.fromtimestamp(n, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S",
                "%d-%m-%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            d = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


_KNOWN: dict[str, tuple[str, ...]] = {}


def _build(framework: str, rec: dict, *, host, implant_id, user, pid, process,
           arch, integrity, internal, external, os_, listener, domain,
           first, last, active, note, consumed: tuple[str, ...]) -> ParsedImplant | None:
    name = str(host or internal or external or "").strip().rstrip(".").lower()
    if not name:
        return None
    seen = {c.lower().replace("_", "").replace("-", "") for c in consumed}
    extra = {k: v for k, v in rec.items()
             if str(k).lower().replace("_", "").replace("-", "") not in seen
             and v not in (None, "", [], {})}
    return ParsedImplant(
        host=name, framework=framework,
        implant_id=str(implant_id) if implant_id is not None else None,
        listener=str(listener) if listener else None,
        user=str(user) if user else None,
        domain=str(domain) if domain else None,
        process=str(process) if process else None,
        pid=_int(pid),
        arch=str(arch) if arch else None,
        integrity=integrity,
        internal_ip=str(internal) if internal else None,
        external_ip=str(external) if external else None,
        os=str(os_) if os_ else None,
        first_seen=_when(first), last_seen=_when(last),
        active=active, note=str(note) if note else None,
        extra=extra,
    )


def _scan(framework: str, implants: list[ParsedImplant]) -> ParsedScan:
    scan = ParsedScan(tool=framework)
    for im in implants:
        h = scan.host_for(im.host)
        # A callback is proof of code execution on the box.
        h.hacked = True
        h.alive = True
        if im.internal_ip and not h.ip_address:
            h.ip_address = im.internal_ip
        if im.os and not h.os:
            h.os = im.os
        scan.implants.append(im)
    if not implants:
        raise ImportError_(f"no {framework} callbacks found in this document")
    return scan


# ----------------------------------------------------------- Cobalt Strike
def looks_like_cobaltstrike(text: str) -> bool:
    head = text[:4000].lower()
    return ('"computer"' in head and '"listener"' in head) or \
           ('"barch"' in head) or ('"beacons"' in head and '"external"' in head)


def parse_cobaltstrike(text: str) -> ParsedScan:
    out = []
    for r in _records(text):
        user = _get(r, "user")
        # CS marks an elevated beacon with a trailing asterisk on the user.
        elevated = isinstance(user, str) and user.rstrip().endswith("*")
        if elevated:
            # "jdoe *" -> "jdoe": strip the marker AND the space before it,
            # or every elevated user sorts and matches differently from the
            # same account seen unelevated.
            user = user.rstrip().rstrip("*").strip()
        im = _build(
            "cobaltstrike", r,
            host=_get(r, "computer", "hostname", "host"),
            implant_id=_get(r, "id", "bid", "beaconid"),
            user=user, pid=_get(r, "pid"), process=_get(r, "process", "name"),
            arch=_get(r, "barch", "arch"),
            integrity="high" if elevated else None,
            internal=_get(r, "internal", "internalip"),
            external=_get(r, "external", "externalip"),
            os_=" ".join(str(x) for x in [_get(r, "os"), _get(r, "ver"),
                                          _get(r, "build")] if x) or None,
            listener=_get(r, "listener"),
            domain=_get(r, "domain", "dnsdomain"),
            first=_get(r, "first", "opened", "firstcallin"),
            last=_get(r, "lastcheckin", "lastseen"),
            active=_bool(_get(r, "alive", "active"), True),
            note=_get(r, "note"),
            consumed=("computer", "hostname", "host", "id", "bid", "beaconid", "user",
                      "pid", "process", "name", "barch", "arch", "internal",
                      "internalip", "external", "externalip", "os", "ver", "build",
                      "listener", "domain", "dnsdomain", "first", "opened",
                      "firstcallin", "lastcheckin", "lastseen", "alive", "active",
                      "note", "last", "is64"),
        )
        if im:
            # `last` in CS is milliseconds *since* the last check-in, not a
            # timestamp — recording it as one would date every beacon to 1970.
            if im.last_seen is None and _int(_get(r, "last")) is not None:
                im.extra["last_checkin_ms_ago"] = _int(_get(r, "last"))
            if _get(r, "is64") is not None and not im.arch:
                im.arch = "x64" if _bool(_get(r, "is64")) else "x86"
            out.append(im)
    return _scan("cobaltstrike", out)


# ------------------------------------------------------------------ Mythic
#: Mythic's documented integrity_level scale.
_MYTHIC_INTEGRITY = {0: "unknown", 1: "low", 2: "medium", 3: "high", 4: "system"}


def looks_like_mythic(text: str) -> bool:
    head = text[:4000].lower()
    return ('"agent_callback_id"' in head or '"agentcallbackid"' in head
            or ('"integrity_level"' in head and '"payload_type"' in head)
            or ('"callbacks"' in head and '"last_checkin"' in head))


def parse_mythic(text: str) -> ParsedScan:
    out = []
    for r in _records(text):
        lvl = _int(_get(r, "integrity_level"))
        im = _build(
            "mythic", r,
            host=_get(r, "host", "hostname"),
            implant_id=_get(r, "agent_callback_id", "display_id", "id"),
            user=_get(r, "user", "username"), pid=_get(r, "pid"),
            process=_get(r, "process_name", "process"),
            arch=_get(r, "architecture", "arch"),
            integrity=_MYTHIC_INTEGRITY.get(lvl) if lvl is not None else None,
            internal=_get(r, "ip"), external=_get(r, "external_ip"),
            os_=_get(r, "os"),
            listener=_get(r, "payload_type", "c2_profile"),
            domain=_get(r, "domain"),
            first=_get(r, "init_callback"), last=_get(r, "last_checkin"),
            active=_bool(_get(r, "active"), True),
            note=_get(r, "description"),
            consumed=("host", "hostname", "agent_callback_id", "display_id", "id",
                      "user", "username", "pid", "process_name", "process",
                      "architecture", "arch", "integrity_level", "ip",
                      "external_ip", "os", "payload_type", "c2_profile", "domain",
                      "init_callback", "last_checkin", "active", "description"),
        )
        if im:
            if lvl is not None:
                im.extra["integrity_level"] = lvl
            out.append(im)
    return _scan("mythic", out)


# ------------------------------------------------------------------ Merlin
def looks_like_merlin(text: str) -> bool:
    head = text[:4000].lower()
    return ('"userguid"' in head
            or ('"statuscheckin"' in head and '"platform"' in head)
            or ('"platform"' in head and '"initial"' in head and '"ips"' in head))


def parse_merlin(text: str) -> ParsedScan:
    out = []
    for r in _records(text):
        ips = _get(r, "ips", "ip")
        if isinstance(ips, str):
            ips = [x.strip() for x in ips.replace(",", " ").split() if x.strip()]
        all_ips = [str(i) for i in (ips or [])]
        # Loopback is never how we reach the host, so it must not become the
        # internal address — but it is still part of what the agent reported.
        ips = [i for i in all_ips if not i.startswith("127.")]
        im = _build(
            "merlin", r,
            host=_get(r, "hostname", "host"),
            implant_id=_get(r, "id", "guid"),
            user=_get(r, "username", "user"), pid=_get(r, "pid"),
            process=_get(r, "process"),
            arch=_get(r, "architecture", "arch"),
            integrity=_merlin_integrity(_get(r, "integrity")),
            internal=ips[0] if ips else None,
            external=_get(r, "externalip"),
            os_=" ".join(str(x) for x in [_get(r, "platform"), _get(r, "build")] if x) or None,
            listener=_get(r, "listener", "protocol", "proto"),
            domain=_get(r, "domain"),
            first=_get(r, "initial", "initialcheckin"),
            last=_get(r, "statuscheckin", "lastcheckin"),
            active=_bool(_get(r, "status", "alive"), True),
            note=_get(r, "note", "comment"),
            consumed=("hostname", "host", "id", "guid", "username", "user", "pid",
                      "process", "architecture", "arch", "integrity", "ips", "ip",
                      "externalip", "platform", "build", "listener", "protocol",
                      "proto", "domain", "initial", "initialcheckin",
                      "statuscheckin", "lastcheckin", "status", "alive", "note",
                      "comment", "version", "userguid"),
        )
        if im:
            if len(all_ips) > 1:
                im.extra["all_ips"] = all_ips
            if _get(r, "userguid"):
                im.extra["user_guid"] = _get(r, "userguid")
            if _get(r, "version"):
                im.extra["agent_version"] = _get(r, "version")
            out.append(im)
    return _scan("merlin", out)


def _merlin_integrity(v):
    """Merlin reports an integrity *level*; map it to the shared words."""
    n = _int(v)
    if n is None:
        return str(v).lower() if v else None
    return {0: "unknown", 1: "low", 2: "medium", 3: "high", 4: "system"}.get(n)


# ------------------------------------------------------------------ Sliver
def looks_like_sliver(text: str) -> bool:
    head = text[:4000]
    return ('"ActiveC2"' in head or '"activec2"' in head.lower()
            or ('"ReconnectInterval"' in head)
            or ('"Transport"' in head and '"Hostname"' in head and '"Burned"' in head))


def parse_sliver(text: str) -> ParsedScan:
    out = []
    for r in _records(text):
        im = _build(
            "sliver", r,
            host=_get(r, "Hostname", "host"),
            implant_id=_get(r, "ID", "id"),
            user=_get(r, "Username", "user"), pid=_get(r, "PID", "pid"),
            process=_get(r, "Filename", "process"),
            arch=_get(r, "Arch", "architecture"),
            # Sliver has no integrity field; UID 0 / an SYSTEM-ish name is
            # the only hint, and guessing beyond that would be invention.
            integrity="system" if str(_get(r, "UID", default="")).strip() == "0" else None,
            internal=None,
            external=(str(_get(r, "RemoteAddress", "remoteaddress", default=""))
                      .split(":")[0] or None),
            os_=" ".join(str(x) for x in [_get(r, "OS"), _get(r, "Version")] if x) or None,
            listener=_get(r, "ActiveC2", "Transport"),
            domain=None,
            first=_get(r, "FirstContact", "firstcontact"),
            last=_get(r, "LastCheckin", "lastcheckin"),
            active=not _bool(_get(r, "IsDead"), False),
            note=_get(r, "Name", "name"),
            consumed=("Hostname", "host", "ID", "id", "Username", "user", "PID",
                      "pid", "Filename", "process", "Arch", "architecture", "UID",
                      "RemoteAddress", "remoteaddress", "OS", "Version", "ActiveC2",
                      "Transport", "FirstContact", "firstcontact", "LastCheckin",
                      "lastcheckin", "IsDead", "Name", "name"),
        )
        if im:
            out.append(im)
    return _scan("sliver", out)


# ------------------------------------------------------------------- Havoc
def looks_like_havoc(text: str) -> bool:
    head = text[:4000]
    return ('"NameID"' in head or '"nameid"' in head.lower()
            or ('"ProcessPID"' in head and '"InternalIP"' in head)
            or ('"demons"' in head.lower() and '"FirstCallIn"' in head))


def parse_havoc(text: str) -> ParsedScan:
    out = []
    for r in _records(text):
        im = _build(
            "havoc", r,
            host=_get(r, "Hostname", "Computer", "host"),
            implant_id=_get(r, "NameID", "id"),
            user=_get(r, "Username", "user"), pid=_get(r, "ProcessPID", "pid"),
            process=_get(r, "ProcessName", "process"),
            arch=_get(r, "ProcessArch", "Arch"),
            integrity="high" if _bool(_get(r, "Elevated"), False) else None,
            internal=_get(r, "InternalIP"), external=_get(r, "ExternalIP"),
            os_=_get(r, "OSVersion", "OS"),
            listener=_get(r, "Listener"),
            domain=_get(r, "DomainName", "domain"),
            first=_get(r, "FirstCallIn"), last=_get(r, "LastCallIn"),
            active=_bool(_get(r, "Active"), True),
            note=_get(r, "Note"),
            consumed=("Hostname", "Computer", "host", "NameID", "id", "Username",
                      "user", "ProcessPID", "pid", "ProcessName", "process",
                      "ProcessArch", "Arch", "Elevated", "InternalIP", "ExternalIP",
                      "OSVersion", "OS", "Listener", "DomainName", "domain",
                      "FirstCallIn", "LastCallIn", "Active", "Note"),
        )
        if im:
            out.append(im)
    return _scan("havoc", out)
