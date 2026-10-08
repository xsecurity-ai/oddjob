"""What version of Oddjob this process is.

The number itself is decided in exactly one place — the `VERSION` file
at the repository root — and this module is how the Python half reads
it. The Go agent reads the same file through `-ldflags` at build time
(drone/Makefile), and the images stamp it into an OCI label
(.github/workflows/images.yml). Nothing here carries a literal version
string, because a second literal is a second answer, and the two would
diverge on the first release nobody remembered to update both for.

**Three sources, in order, and the order is the whole design.**

1. ``ODDJOB_VERSION`` in the environment. Set by the Dockerfile from
   the build argument, so a released image states its version as a
   fact rather than recomputing it from a tree it no longer has. Also
   the hook a deployment or a test uses to say "this is X" without
   touching the filesystem.

2. The ``VERSION`` file, found by walking up from this file, plus
   ``-dev-<commit time>`` when a ``.git`` directory sits beside it. A
   checkout *is* a development instance — that is what distinguishes
   one from an artefact, and asking the filesystem is more honest than
   asking an environment variable somebody might forget to set.

3. ``"unknown"``. Not a version number, deliberately. An install whose
   version cannot be determined is a third state, and reporting it as
   either a release or a dev build would be a guess presented as a
   fact. The Health view renders it as "unknown".

The commit *timestamp* rather than the build time, so the same source
always produces the same string: a rebuild to reproduce a bug must not
change the version number it reports. See scripts/version.sh, which
computes the identical string for the shell callers, and
scripts/check-version.sh, which is what stops a ``-dev-`` version ever
reaching main.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

#: Matches scripts/version.sh. Anything containing this is a build from
#: somebody's working tree and must never be published; ci.yml reads the
#: version back out of the built image and fails on it.
DEV_MARKER = "-dev-"


def _read_version_file() -> tuple[str, pathlib.Path] | None:
    """The nearest ``VERSION`` above this module, and where it was found.

    Walks up rather than assuming a fixed depth because the layout is
    not the same in both places this runs. In a checkout the file is
    three levels up (``backend/app/version.py`` -> repo root); in the
    image ``backend/`` is copied to ``/app/backend`` and ``VERSION``
    alongside it at ``/app/VERSION``, which is the same walk and a
    different number of levels. Hard-coding ``parents[2]`` worked in
    exactly one of those.
    """
    for d in pathlib.Path(__file__).resolve().parents:
        f = d / "VERSION"
        if f.is_file():
            try:
                text = f.read_text(encoding="utf-8").strip()
            except OSError:
                return None
            if text:
                return text, d
    return None


def _commit_stamp(root: pathlib.Path) -> str:
    """Unix time of HEAD, or ``"unknown"``.

    Shelled out rather than parsed out of ``.git`` by hand: reading a
    packed ref, following a symbolic HEAD and decoding a commit object
    is a surprising amount of code to get the one number git prints.

    A failure here does not fall back to the bare release number. The
    build is still a development build — git being unavailable is a
    fact about the toolchain, not about the source — so it keeps the
    ``-dev-`` marker and says the stamp is unknown. Collapsing "could
    not determine" into "released" is how a dev build acquires a
    release number.
    """
    try:
        out = subprocess.run(                          # noqa: S603
            ["git", "-C", str(root), "log", "-1", "--format=%ct"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    stamp = out.stdout.strip()
    return stamp if out.returncode == 0 and stamp.isdigit() else "unknown"


def _resolve() -> str:
    env = (os.environ.get("ODDJOB_VERSION") or "").strip()
    if env:
        return env

    found = _read_version_file()
    if found is None:
        return "unknown"
    base, root = found

    # A checkout, therefore a development instance. The marker goes on
    # whether or not the tree is dirty: "built from a commit that is on
    # main" and "built from a working copy of it" are both unreleased,
    # and only the release path — Dockerfile, or ODDJOB_RELEASE=1 —
    # produces a bare number.
    if (root / ".git").exists():
        return f"{base}{DEV_MARKER}{_commit_stamp(root)}"
    return base


#: Resolved once, at import. The answer cannot change while the process
#: runs — the file is not reread and HEAD is not re-examined — and the
#: health endpoint is polled every fifteen seconds by every open admin
#: tab, which is not somewhere to put a subprocess call.
VERSION: str = _resolve()

#: True when this process is running an unreleased build. Exposed so the
#: Health view can say so plainly rather than making a site admin parse
#: the string, and so tests can assert on the distinction.
IS_DEV: bool = DEV_MARKER in VERSION
