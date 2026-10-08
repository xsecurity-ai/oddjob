#!/usr/bin/env bash
# A `-dev-` version must never reach main, or a release artefact.
#
# The rule on its own is a comment. This is what makes it a build
# failure. One script, three callers: ci.yml's `version` job, the
# pre-commit hook of the same name, and promote.yml before it puts a
# release number on anything. Two copies of this test would eventually
# disagree, and the one that matters is whichever is weaker.
#
#   scripts/check-version.sh            the file, and the release path
#   scripts/check-version.sh <string>   that string, as well
#
# The argument form is how a built artefact is checked: ci.yml reads
# the version back out of the running oddjob image and out of
# `ghost version`, and hands it here. Checking the file alone would
# only prove the file is clean — the interesting failure is a clean
# file and an artefact built without --release.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fail=0

say() { echo "$@" >&2; }

# ---------------------------------------------------------- the file
#
# A bare triple and nothing else. The pre-release and build-metadata
# halves of semver are legal semver and are wrong *here*: the suffix is
# produced by scripts/version.sh at build time, so a suffix committed
# to the file would be a second mechanism deciding it, and `0.0.1-dev-…`
# sitting in VERSION on main is precisely the state this check exists
# to prevent.
base=$(tr -d '[:space:]' < "$here/VERSION" 2>/dev/null || true)
if [ -z "$base" ]; then
    say "error: VERSION is missing or empty"
    exit 1
fi
if ! printf '%s' "$base" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    say "error: VERSION is '$base' — it must be a bare semver triple, e.g. 0.0.1."
    say "       Pre-release and build suffixes are produced by scripts/version.sh"
    say "       at build time and must not be committed to the file."
    fail=1
fi

# ------------------------------------------------------ the artefact
#
# Checked by shape, not by equality with VERSION. `0.1.0` built from a
# commit where VERSION already said `0.2.0` is a stale artefact and a
# different complaint; a `-dev-` anywhere in a release path is this one.
#
# A release artefact's version must be a bare triple for a second
# reason beyond tidiness: it becomes a Docker Hub tag. `0.0.1-dev-…` is
# a legal tag string, so the registry would accept it without
# complaint and the fleet would be running something whose version
# nobody can reproduce.
check_string() {
    local what=$1 ver=$2
    if [ -z "$ver" ]; then
        say "error: $what reported no version at all"
        fail=1
        return
    fi
    case "$ver" in
        *-dev-*)
            say "error: $what is '$ver' — a development build."
            say "       Release artefacts are built with ODDJOB_RELEASE=1 or"
            say "       scripts/version.sh --release. See scripts/version.sh."
            fail=1
            return
            ;;
    esac
    if ! printf '%s' "$ver" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
        say "error: $what is '$ver', which is not a bare semver triple."
        say "       This string becomes a Docker Hub tag and a git tag; both"
        say "       would accept it and neither would be reproducible."
        fail=1
        return
    fi
    echo "ok: $what is $ver"
}

# The release path, exercised rather than assumed. If `--release` ever
# stops suppressing the suffix, this is where it is found — on every
# PR, rather than on the first promotion after it broke.
check_string "scripts/version.sh --release" "$("$here/scripts/version.sh" --release)"

# And the other direction. A guard that cannot fail is not a guard: if
# the default path stopped adding the suffix, every check above would
# still pass while the feature had quietly gone away.
devver=$("$here/scripts/version.sh")
case "$devver" in
    "$base"-dev-*) echo "ok: the default path is a dev build ($devver)" ;;
    *) say "error: scripts/version.sh produced '$devver', expected '$base-dev-<stamp>'."
       say "       The dev suffix has stopped working, so nothing below would catch"
       say "       a dev build wearing a release number."
       fail=1 ;;
esac

for given in "$@"; do
    check_string "the version handed to this check" "$given"
done

exit "$fail"
