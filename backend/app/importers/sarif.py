"""SARIF 2.1.0 — semgrep, CodeQL, grype, osv-scanner, and friends.

One JSON document: `{"version": "2.1.0", "runs": [...]}`. Each run has a
`tool.driver` (name + rules) and a `results` array. Each result carries a
`ruleId`, a `message.text`, and one or more `locations` with file path and
line number.

Severity mapping: SARIF uses `error | warning | note | none` on the rule's
`defaultConfiguration.level`. We override with `properties.security-severity`
(CVSS score) when present, because semgrep and CodeQL both emit it and it is
more granular than the four-level scale.

The `host` field on each ParsedVuln is set to the target's host (the repo
slug or URL) — the importer receives it via the import request's
`target_host` parameter, which the ghost task runner supplies from its own
args. When imported manually without a target_host, the host defaults to
"unknown" and the operator re-files it.
"""
from __future__ import annotations

import json

from .model import (
    ImportError_,
    ParsedScan,
    ParsedVuln,
    norm_severity,
)


def looks_like(text: str) -> bool:
    """True if this is a SARIF 2.1.x JSON document."""
    head = text.lstrip()[:512]
    if not head.startswith("{"):
        return False
    # SARIF documents have "version" and "runs" at the top level.
    return '"version"' in head and '"runs"' in head


def _cvss_to_severity(score: float) -> str:
    """Map a CVSS v3/v4 base score onto our five-level scale."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _level_to_severity(level: str | None) -> str:
    """Map SARIF's four-level scale onto ours."""
    if level is None:
        return "info"
    mapping = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }
    return mapping.get(level, "info")


def _rule_severity(rule: dict | None) -> str:
    """Best severity for a rule, preferring CVSS over the level."""
    if not rule:
        return "info"
    props = rule.get("properties", {})
    cvss = props.get("security-severity")
    if cvss is not None:
        try:
            return _cvss_to_severity(float(cvss))
        except (ValueError, TypeError):
            pass
    level = rule.get("defaultConfiguration", {}).get("level")
    return _level_to_severity(level)


def parse(text: str, *, target_host: str | None = None) -> ParsedScan:
    """Parse a SARIF 2.1 document into the IR.

    `target_host` is the repo slug or URL these findings belong to. When
    absent (manual import without context), findings get host="unknown".
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise ImportError_(f"not valid JSON: {e}") from e

    if not isinstance(doc, dict):
        raise ImportError_("SARIF document must be a JSON object")

    version = doc.get("version", "")
    # Accept 2.0 and 2.0.x too — the structure is close enough for
    # our purposes (runs[].results[]).
    if not version.startswith(("2.1", "2.0")):
        raise ImportError_(
            f"unsupported SARIF version {version!r}; expected 2.1.x")

    runs = doc.get("runs")
    if not isinstance(runs, list):
        raise ImportError_("missing 'runs' array")

    host = (target_host or "unknown").lower().strip()
    scan = ParsedScan(tool="sarif", version=version)
    errors: list[str] = []

    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        tool_name = driver.get("name", "unknown")
        scan.tool = tool_name  # e.g. "Semgrep", "CodeQL"

        # Build a rule id → rule dict lookup for severity and metadata.
        rules: dict[str, dict] = {}
        for r in driver.get("rules", []):
            if isinstance(r, dict) and "id" in r:
                rules[r["id"]] = r

        results = run.get("results", [])
        if not isinstance(results, list):
            continue

        for i, result in enumerate(results):
            if not isinstance(result, dict):
                errors.append(f"run[{len(rules)}] result {i}: not an object")
                continue

            rule_id = result.get("ruleId", "unknown-rule")
            rule = rules.get(rule_id)

            # Title: prefer the rule's name/description if available.
            title = rule_id
            if rule:
                name = rule.get("name") or rule.get("shortDescription", {}).get("text")
                if name:
                    title = name
            # Fall back to the result message for a human-readable title.
            msg_text = result.get("message", {}).get("text", "")
            if not title or title == rule_id:
                title = (msg_text[:200] if msg_text else rule_id)

            # Severity: CVSS > level > info.
            severity = _rule_severity(rule)
            # Per-result override (some tools set it on the result).
            result_props = result.get("properties", {})
            if result_props.get("security-severity") is not None:
                try:
                    severity = _cvss_to_severity(
                        float(result_props["security-severity"]))
                except (ValueError, TypeError):
                    pass

            # Location: first physical location in the first location.
            file_path = None
            line_number = None
            locations = result.get("locations", [])
            if locations and isinstance(locations, list) and locations[0]:
                loc = locations[0] if isinstance(locations[0], dict) else {}
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                file_path = artifact.get("uri")
                region = phys.get("region", {})
                ln = region.get("startLine")
                if ln is not None:
                    try:
                        line_number = int(ln)
                    except (ValueError, TypeError):
                        pass

            # Description: the result message + any related locations.
            desc_parts = []
            if msg_text and msg_text != title:
                desc_parts.append(msg_text)
            # Related locations (e.g. source→sink for taint findings).
            related = result.get("relatedLocations", [])
            if related:
                loc_strs = []
                for rl in related[:5]:  # cap at 5 to keep descriptions sane
                    if not isinstance(rl, dict):
                        continue
                    phys_rl = rl.get("physicalLocation", {})
                    uri = phys_rl.get("artifactLocation", {}).get("uri", "?")
                    ln_rl = phys_rl.get("region", {}).get("startLine", "")
                    loc_strs.append(f"{uri}:{ln_rl}" if ln_rl else uri)
                if loc_strs:
                    desc_parts.append("Related: " + ", ".join(loc_strs))
            description = "\n".join(desc_parts) or None

            # External ID: rule id + file + line for dedupe stability.
            ext_id = rule_id
            if file_path and line_number:
                ext_id = f"{rule_id}:{file_path}:{line_number}"
            elif file_path:
                ext_id = f"{rule_id}:{file_path}"

            # Fingerprint (semgrep, CodeQL both emit one) is even more stable.
            fingerprint = result.get("fingerprints")
            if isinstance(fingerprint, dict):
                fp_val = fingerprint.get("UniqueID") or next(
                    iter(fingerprint.values()), None)
                if fp_val:
                    ext_id = str(fp_val)[:128]

            scan.vulns.append(ParsedVuln(
                host=host,
                title=title[:1000],
                severity=norm_severity(severity),
                description=description,
                external_id=ext_id[:128],
                remediation=None,
                file_path=file_path,
                line_number=line_number,
            ))

    scan.errors = errors
    return scan
