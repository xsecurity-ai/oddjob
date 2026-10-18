"""Dependency manifests found on a client's web server, read.

`assetwork.library_leads` already asks the local CVE corpus about
every library a page SHIPS -- jQuery 3.6.0, Bootstrap 5.3.2, read
out of the file the client's own server serves. This is the other
half: the manifests that say what went INTO the build, which turn up
on web servers more often than anybody intends.

`package-lock.json` at a web root is two findings at once and they
are not the same size:

  1. the file should not be there, which is a fact about the
     deployment and is certain;
  2. what is in it, which is a dependency inventory and is where the
     CVEs are.

Both are reported, and the second is reported more carefully than
the first -- see below.

# Why a lockfile CVE is a weaker claim than a shipped-library CVE

A lockfile lists what the build resolved. Much of it is
devDependencies, much of the rest is tree-shaken out, and a good
deal never reaches a browser at all. So "this lockfile names lodash
4.17.15, and CVE-2020-8203 names that version" is TRUE and is not
the same sentence as "this page loads lodash 4.17.15".

The finding says which one it is. Collapsing them would put a
build-time dependency and a running one at the same severity, and
the first one an operator checked by hand and found unreachable
would teach them to distrust the rest.

# Parsing

Each format is parsed from its own shape, not by a regex over all
of them. A lockfile is machine-written and perfectly regular, and
the cost of guessing is a version number attached to the wrong
package -- which produces a confident CVE match against software
that is not there.

Nothing here runs or installs anything. These are text files being
read.
"""
from __future__ import annotations

import json
import re

#: Filenames worth reading, and the format each is in. Matched on the
#: basename, because a lockfile is a lockfile wherever it is served
#: from.
KNOWN: dict[str, str] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "yarn",
    "composer.lock": "composer",
    "gemfile.lock": "gem",
    "requirements.txt": "pip",
    "pipfile.lock": "pipenv",
    "go.mod": "gomod",
    "go.sum": "gosum",
    "cargo.lock": "cargo",
}


def format_of(path: str) -> str | None:
    """-> which parser this path wants, or None.

    On the basename alone. `/static/vendor/package-lock.json` is as
    much a lockfile as one at the root, and the path it was served
    from is evidence about the deployment rather than about the
    format.
    """
    base = (path or "").rstrip("/").rsplit("/", 1)[-1].lower()
    return KNOWN.get(base)


def _clean(name: str, version: str) -> tuple[str, str] | None:
    """One pair, or None if either half is unusable.

    A version with a range operator in it is dropped. `^4.17.0` is
    not a version that was installed, it is a constraint that was
    resolved, and matching a CVE against it would be matching against
    something nobody is running.
    """
    quotes = "\"'"
    n = (name or "").strip().strip(quotes).lower()
    v = (version or "").strip().strip(quotes)
    if not n or not v:
        return None
    if any(c in v for c in "^~*><|= "):
        return None
    v = v.lstrip("v")
    # A git ref or a file path is not a release.
    if not re.match(r"^\d+(\.\d+)*([.-][0-9A-Za-z.-]+)?$", v):
        return None
    return n, v


def _npm(text: str) -> list[tuple[str, str]]:
    """package-lock.json, all three lockfileVersions.

    v1 nests under `dependencies`; v2 and v3 use a flat `packages`
    map keyed by install path. Both shapes appear in the wild and v2
    carries both, so `packages` is preferred and `dependencies` is
    the fallback rather than an alternative.
    """
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    if not isinstance(doc, dict):
        return []
    out: list[tuple[str, str]] = []

    pkgs = doc.get("packages")
    if isinstance(pkgs, dict):
        for where, meta in pkgs.items():
            if not isinstance(meta, dict):
                continue
            # "" is the project itself, not a dependency.
            name = meta.get("name") or where.rsplit("node_modules/", 1)[-1]
            if not where or not name:
                continue
            got = _clean(str(name), str(meta.get("version", "")))
            if got:
                out.append(got)
        if out:
            return out

    def walk(d) -> None:
        if not isinstance(d, dict):
            return
        for name, meta in d.items():
            if not isinstance(meta, dict):
                continue
            got = _clean(name, str(meta.get("version", "")))
            if got:
                out.append(got)
            walk(meta.get("dependencies"))

    walk(doc.get("dependencies"))
    return out


def _yarn(text: str) -> list[tuple[str, str]]:
    """yarn.lock v1. An entry header, then an indented `version`."""
    out, name = [], None
    for raw in (text or "").splitlines():
        if raw[:1] not in (" ", "\t", "#", "") and raw.rstrip().endswith(":"):
            # `lodash@^4.17.0, lodash@^4.17.15:` -- the package is the
            # part before the LAST @, which keeps scoped names whole.
            first = raw.rstrip(":").split(",")[0].strip().strip('"')
            name = first.rsplit("@", 1)[0] if "@" in first[1:] else first
            continue
        m = re.match(r'^\s+version\s+"?([^"\s]+)"?', raw)
        if m and name:
            got = _clean(name, m.group(1))
            if got:
                out.append(got)
            name = None
    return out


def _json_packages(text: str) -> list[tuple[str, str]]:
    """composer.lock and Pipfile.lock: a list or map of named packages."""
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    out = []
    if isinstance(doc, dict):
        for key in ("packages", "packages-dev", "default", "develop"):
            section = doc.get(key)
            if isinstance(section, list):
                for p in section:
                    if isinstance(p, dict):
                        got = _clean(str(p.get("name", "")),
                                     str(p.get("version", "")))
                        if got:
                            out.append(got)
            elif isinstance(section, dict):
                for name, meta in section.items():
                    v = (meta or {}).get("version", "") if isinstance(meta, dict) else ""
                    got = _clean(name, str(v).lstrip("="))
                    if got:
                        out.append(got)
    return out


def _gem(text: str) -> list[tuple[str, str]]:
    """Gemfile.lock. `    name (1.2.3)` under a specs: block."""
    out, in_specs = [], False
    for raw in (text or "").splitlines():
        if raw.strip().endswith("specs:"):
            in_specs = True
            continue
        if raw and not raw[:1].isspace():
            in_specs = False
            continue
        if not in_specs:
            continue
        m = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)\s*$", raw)
        if m:
            got = _clean(m.group(1), m.group(2))
            if got:
                out.append(got)
    return out


def _pip(text: str) -> list[tuple[str, str]]:
    """requirements.txt. Only `==`: anything looser is a constraint."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([^\s;]+)", line)
        if m:
            got = _clean(m.group(1), m.group(2))
            if got:
                out.append(got)
    return out


def _gomod(text: str) -> list[tuple[str, str]]:
    """go.mod require lines, and go.sum's first column."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line.startswith("//") or not line:
            continue
        m = re.match(r"^(?:require\s+)?([a-z0-9][\w./~-]*\.[\w./~-]+)\s+"
                     r"(v[0-9][\w.+-]*)", line)
        if m:
            # `v1.2.3/go.mod h1:...` in go.sum names the same module.
            got = _clean(m.group(1), m.group(2).split("/")[0])
            if got:
                out.append(got)
    return out


def _cargo(text: str) -> list[tuple[str, str]]:
    """Cargo.lock. TOML `[[package]]` blocks, read without a TOML parser.

    Hand-read because the only thing wanted is two keys out of each
    block, and adding a TOML dependency to parse a file this regular
    would be paying for a library to do one `startswith`.
    """
    out, name = [], None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line == "[[package]]":
            name = None
            continue
        if line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("version = ") and name:
            got = _clean(name, line.split("=", 1)[1].strip().strip('"'))
            if got:
                out.append(got)
            name = None
    return out


PARSERS = {
    "npm": _npm, "yarn": _yarn, "composer": _json_packages,
    "pipenv": _json_packages, "gem": _gem, "pip": _pip,
    "gomod": _gomod, "gosum": _gomod, "cargo": _cargo,
}


def parse(path: str, text: str) -> list[tuple[str, str]]:
    """Every (name, version) a manifest pins. Deduplicated, sorted.

    Sorted so two reads of an unchanged file produce an identical
    list, which is what makes the findings it raises idempotent.
    """
    fmt = format_of(path)
    if not fmt:
        return []
    fn = PARSERS.get(fmt)
    if fn is None:
        return []
    try:
        pairs = fn(text or "")
    except Exception:                                 # noqa: BLE001
        # A malformed manifest is not an error worth failing a sweep
        # for. It is a file that did not parse, which the caller
        # reports as nothing found rather than as a clean result.
        return []
    return sorted(set(pairs))
