#!/usr/bin/env bash
# The one place a version string is produced.
#
#   scripts/version.sh            -> 0.0.1-dev-1759900000
#   scripts/version.sh --release  -> 0.0.1
#
# ------------------------------------------------------ one decider
#
# `VERSION` at the repository root holds a bare semver triple and
# nothing else. It is the only place a version number is *decided*;
# everything else in this repository *reads* it:
#
#   backend/app/version.py      walks up for VERSION, same rules below
#   ghost/Makefile              stamps config.Version via -ldflags
#   Dockerfile, ghost/Dockerfile    build arg, baked into the image
#   .github/workflows/images.yml    stamps the OCI version label
#   .github/workflows/promote.yml   reads it back off the image
#
# The file is changed by two things and nothing else:
#
#   scripts/bump-build.sh            the BUILD component, automatically,
#                                    once per branch, when shipped source
#                                    changes. Run as a pre-commit hook.
#   .github/workflows/bump-version.yml   minor and major, by hand
#
# The split is deliberate. "This ships different code" is a fact a
# script can check; "this is 0.1.0 now" is a judgement about what
# changed, and no script can make it. Before this existed, promote.yml computed the next
# version from the highest git tag, which meant the number lived in two
# places that could disagree — and the one people would have trusted is
# whichever they looked at last. Git tags are still created, but they
# are now a *record* of a released VERSION rather than the input that
# decides it. See the header of promote.yml.
#
# ------------------------------------------------------- the suffix
#
# A build that is not a release gets `-dev-<unix time of HEAD>`
# appended. The commit timestamp, not the build time, so the same
# source always produces the same version string: two developers who
# build the same commit should not be comparing two different version
# numbers, and a rebuild to reproduce a bug should not change the
# answer. `%ct` is the committer date in seconds, which is what `git
# log` orders by and what changes on a rebase — a cherry-picked commit
# with an old author date is, for our purposes, new.
#
# Underscores are not legal in a semver pre-release identifier, so the
# literal `-dev-timestamp_of_lastcommit` of the original request is
# spelled `-dev-<seconds>`. `0.0.1-dev-1759900000` parses as semver,
# sorts BELOW `0.0.1` (a pre-release precedes its release, which is the
# correct ordering for an unreleased build of it), and is still obvious
# to a human reading a table of ghosts.
#
# ---------------------------------------------- release is explicit
#
# `--release` (or ODDJOB_RELEASE=1) is required to get a bare version.
# The default is the dev suffix, deliberately: the failure we care
# about is a dev build wearing a release number, so the safe answer is
# the one you get by saying nothing. A missing flag costs you a `-dev-`
# in a local build; a missing flag the other way round would put an
# unreleasable string on a published image.
#
# What enforces that a `-dev-` version never reaches main is
# scripts/check-version.sh and the jobs in ci.yml that call it.
set -euo pipefail

release=0
case "${1:-}" in
    --release) release=1 ;;
    "")        ;;
    *) echo "usage: version.sh [--release]" >&2; exit 2 ;;
esac
[ "${ODDJOB_RELEASE:-}" = "1" ] && release=1

# Resolved from this script's own location rather than from $PWD or
# from `git rev-parse --show-toplevel`: the Makefile calls it from
# ghost/, CI calls it from the root, and a Docker build has no git at
# all. The file sits beside scripts/, and that is true in every one of
# those cases.
here=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
base=$(tr -d '[:space:]' < "$here/VERSION")

if [ -z "$base" ]; then
    echo "error: $here/VERSION is empty" >&2
    exit 1
fi

if [ "$release" = "1" ]; then
    printf '%s\n' "$base"
    exit 0
fi

# A dev build whose timestamp could not be read is still a dev build.
# `-dev-unknown` is valid semver, is still caught by every check that
# greps for `-dev-`, and is a far better answer than falling back to
# the bare release number because git was not available. Three
# outcomes, not two: released, dev-at-a-known-commit, dev-at-an-
# unknown-commit.
stamp=$(git -C "$here" log -1 --format=%ct 2>/dev/null || true)
printf '%s-dev-%s\n' "$base" "${stamp:-unknown}"
