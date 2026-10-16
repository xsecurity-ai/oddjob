"""Nuclei `-jsonl` (and the legacy `-json` array).

One object per match: `template-id`, `info{name,severity,description,tags,
reference}`, `host`, `ip`, `matched-at`, `type`, `extracted-results`,
`curl-command`.

Nuclei's own severity is authoritative here — unlike most scanners it is set
per template by someone who looked at the check, so it is used as-is.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .model import (
    ImportError_,
    ParsedScan,
    ParsedService,
    ParsedVuln,
    ParsedWebAddress,
    norm_severity,
)


def looks_like(text: str) -> bool:
    head = text.lstrip()[:4000]
    return '"template-id"' in head or '"template_id"' in head


def iter_json(text: str):
    """Yield objects from JSONL, a JSON array, or concatenated objects.

    Tools disagree about which they emit and change their minds between
    releases, so accepting all three costs little and saves the operator
    finding out the hard way that their file was the other kind.
    """
    stripped = text.strip()
    if not stripped:
        return
    if stripped.startswith("["):
        try:
            doc = json.loads(stripped)
        except ValueError as e:
            raise ImportError_(f"not valid JSON: {e}") from e
        for x in doc:
            if isinstance(x, dict):
                yield x
        return
    ok = False
    for line in stripped.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in ("[", "]"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            ok = True
            yield obj
    if not ok:
        raise ImportError_("no JSON objects found — expected one per line (JSONL)")


#: Templates whose job is to say WHAT something is, rather than that
#: something is wrong with it.
#:
#: These become service detail, not findings. A technology detection
#: is `info` severity and there are 1,228 of them; filing each as a
#: vulnerability would put hundreds of rows in front of an operator
#: that nobody can triage and bury the findings that are real. The
#: same argument the endpoint table was split out for.
_TECH_TAGS = frozenset({"tech", "detect", "detection"})


def _is_tech(info: dict) -> bool:
    tags = info.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    tags = {str(t).strip().lower() for t in tags}
    # Severity as well as tag. A template tagged `tech` that reports
    # something at high severity is telling us about a problem, not
    # about a stack, and must not be quietly filed as a banner.
    return bool(tags & _TECH_TAGS) and \
        str(info.get("severity") or "info").lower() == "info"


def _technology(o: dict, info: dict, tid: str) -> str:
    """What was detected, as a product name.

    `matcher-name` first, and this is the important case rather than a
    fallback: `tech-detect.yaml` is ONE template carrying about a
    hundred named matchers, and its `info.name` is the constant
    "Wappalyzer Technology Detection" for every one of them. Taking
    the name would record a hundred different technologies under one
    meaningless label.
    """
    m = o.get("matcher-name") or o.get("matcher_name")
    if m:
        return str(m).strip()
    # Otherwise the template id, which is per-technology for the
    # single-purpose templates: `nginx-version`, `openssh-detect`.
    # The suffix says what the template did, not what it found.
    name = tid
    for suffix in ("-version-detect", "-detect", "-detection", "-version"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name.replace("-", " ").strip() or tid


#: A version, out of an extractor's result. `nginx-version` extracts
#: `nginx/1.25.5` rather than `1.25.5`, so the product prefix has to
#: come off or every service reads "nginx nginx/1.25.5".
_VERSION = re.compile(r"(\d+(?:\.\d+)+(?:[-_a-zA-Z0-9.]*)?)")


def _version(extracted) -> str | None:
    for x in extracted or []:
        m = _VERSION.search(str(x))
        if m:
            return m.group(1)[:64]
    return None


def parse(text: str) -> ParsedScan:
    scan = ParsedScan(tool="nuclei")
    seen = False
    for o in iter_json(text):
        info = o.get("info") or {}
        if "template-id" not in o and "template_id" not in o and not info:
            continue
        seen = True
        target = str(o.get("host") or o.get("matched-at") or o.get("matched_at") or "")
        parts = urlsplit(target if "//" in target else f"//{target}")
        name = (parts.hostname or target).strip().lower()
        if not name:
            continue

        host = scan.host_for(name)
        host.alive = True
        ip = o.get("ip")
        if ip and not host.ip_address:
            host.ip_address = str(ip)
        # `host` is a BARE HOSTNAME, with the port and scheme beside
        # it as their own top-level fields:
        #
        #   "host":"x.acme.example","port":"80","scheme":"http"
        #
        # Not a URL, whatever a hand-written fixture might suggest.
        # Parsing a scheme out of `host` finds none, which made the
        # port None, which meant no service was ever built to hang a
        # technology on -- so every detection fell through into the
        # findings table instead. Read off real agent output, after
        # the fixture said otherwise and the test passed anyway.
        #
        # `port` arrives as a STRING. int() on it, guarded, because a
        # non-numeric port is not worth an exception over a finding.
        scheme = str(o.get("scheme") or parts.scheme or "").lower()
        port = parts.port
        if port is None and o.get("port") is not None:
            try:
                port = int(str(o["port"]))
            except ValueError:
                port = None
        if port is None:
            port = 443 if scheme == "https" else 80 if scheme == "http" else None
        svc = next((s for s in host.services if s.port == port), None)
        if port and svc is None:
            svc = ParsedService(
                port=port, protocol="tcp", state="open",
                name=scheme or "http",
                tunnel="ssl" if scheme == "https" else None)
            host.services.append(svc)

        tid = o.get("template-id") or o.get("template_id") or "nuclei"
        info_tags = info.get("tags") or []
        extracted_ = (o.get("extracted-results")
                      or o.get("extracted_results") or [])

        if svc is not None and _is_tech(info):
            # What it IS goes on the service. `method="probed"`
            # because nuclei sent a request and read the answer --
            # this is an observation, not a guess from the port
            # number, and `webtargets.web_service_clause` treats the
            # two differently on purpose.
            tech = _technology(o, info, tid)
            ver = _version(extracted_)
            if not svc.product:
                svc.product = tech[:128]
                svc.method = "probed"
            elif tech.lower() not in (svc.product or "").lower():
                # A page can be several things at once -- nginx in
                # front of PHP in front of WordPress -- and recording
                # only the first would throw away most of the stack.
                svc.product = f"{svc.product}, {tech}"[:128]
            if ver and not svc.version:
                svc.version = ver
            # Deliberately no vuln row. See _TECH_TAGS.
            continue

        matched = o.get("matched-at") or o.get("matched_at")
        if matched and str(matched).startswith(("http://", "https://")):
            # The exchange, when nuclei was asked for it (`-irr`). A
            # template that matched is a claim; the request and the
            # response are the evidence for it, and a finding that
            # cannot be shown is one somebody has to take on trust.
            scan.web.append(ParsedWebAddress(
                url=str(matched), host=name, scheme=scheme or "http",
                port=port, crawled=True,
                request=(str(o["request"])[:200000] if o.get("request") else None),
                response=(str(o["response"])[:2000000]
                          if o.get("response") else None),
                notes=f"matched by nuclei template {tid}"))
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        scan.vulns.append(ParsedVuln(
            host=name,
            title=str(info.get("name") or tid),
            severity=norm_severity(info.get("severity")),
            description="\n\n".join(x for x in [
                info.get("description"),
                f"Matched: {matched}" if matched else None,
                ("Extracted: " + ", ".join(map(str, extracted_))) if extracted_ else None,
                ("Tags: " + ", ".join(map(str, info_tags)))
                if isinstance(info_tags, list) and info_tags else None,
                ("References:\n" + "\n".join(f"  {r}" for r in refs)) if refs else None,
                f"Template: {tid}",
            ] if x) or None,
            remediation=info.get("remediation") or None,
            external_id=f"nuclei-{tid}-{_slug(str(matched or name))}",
            port=port,
            protocol="tcp",
        ))
    if not seen:
        raise ImportError_("no nuclei results in this file "
                           "(expected objects with a `template-id`)")
    return scan


def _slug(s: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "x"
