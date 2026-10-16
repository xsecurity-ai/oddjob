#!/usr/bin/env bash
# Bump the build component when shipped source changes — once per branch.
#
# `VERSION` holds a bare semver triple and used to be decided in one
# place, bump-version.yml, run by hand. That is still true of `minor`
# and `major`: deciding to call something 0.1.0 is a judgement about
# what changed, and no script can make it.
#
# The `build` component is not a judgement. If the code that ships
# changed, the thing that ships is different and its number should
# say so. Leaving that to somebody remembering meant two images with
# the same version and different contents, which is the one thing a
# version is for.
#
# ------------------------------------------------------ once per PR
#
# Not once per commit. A ten-commit branch should move 0.0.1 -> 0.0.2,
# not 0.0.1 -> 0.0.11.
#
# Decided by comparing this branch's VERSION against the one at its
# merge-base with the default branch, which needs no state anywhere:
#
#   same    this branch has not bumped yet  -> bump
#   differs this branch already bumped      -> leave it alone
#
# A marker file or a commit-message trailer would both have to be
# cleaned up, and both go wrong on rebase. The merge-base comparison
# is correct after a rebase, a squash, an amend, or a branch renamed
# halfway through, because it only ever asks what the file says.
#
# ------------------------------------------------- what counts
#
# What ships: the agent, the server, the UI, the images that carry
# them, and the migrations that run on start. NOT documentation,
# tests, CI config or this script — a README fix is not a new build,
# and bumping for one produces a release nobody can tell from the
# last.
#
# The list lives in .pre-commit-config.yaml as `files`/`exclude`, so
# pre-commit does the matching and this script trusts what it is
# handed. One place, and it is the place a reader already looks.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
V=VERSION

# Nothing shipped in this commit. pre-commit filters by path, so an
# empty list here means a documentation-only or test-only change.
[ "$#" -gt 0 ] || exit 0

# The branch this work is based on. origin/main normally; main when
# there is no remote, which is the case in a fresh clone and in CI.
base=""
for ref in origin/main origin/HEAD main; do
    if git rev-parse --verify --quiet "$ref" >/dev/null 2>&1; then
        base=$(git merge-base HEAD "$ref" 2>/dev/null) && break
    fi
done
if [ -z "$base" ]; then
    # No base to compare against: a brand new repository, or a clone
    # with no main. Do nothing rather than guess -- a hook that bumps
    # on every commit because it could not find a branch is worse than
    # one that occasionally does not bump.
    exit 0
fi

current=$(tr -d '[:space:]' < "$V")
at_base=$(git show "$base:$V" 2>/dev/null | tr -d '[:space:]' || true)

if [ -z "$at_base" ]; then
    exit 0          # VERSION did not exist at the base; not ours to fix
fi
if [ "$current" != "$at_base" ]; then
    exit 0          # already bumped on this branch
fi

IFS=. read -r major minor build <<< "$current"
case "$major$minor$build" in
    *[!0-9]*|"")
        echo "bump-build: VERSION is '$current', not a semver triple." >&2
        echo "bump-build: refusing to guess what comes next." >&2
        exit 1 ;;
esac

next="$major.$minor.$((build + 1))"
printf '%s\n' "$next" > "$V"
git add "$V"

echo "bump-build: $current -> $next (shipped source changed on this branch)"
echo "bump-build: VERSION has been staged; commit again to include it."
# Non-zero so the commit stops and the author sees the new number
# before it goes in, which is how every other file-modifying hook in
# this repository behaves (end-of-file-fixer, trailing-whitespace).
# A silent bump is a version nobody noticed changing.
exit 1
