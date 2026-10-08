#!/usr/bin/env bash
# Move a moving tag onto an image that already exists for this source.
#
#   retag.sh <image>      with KEY, POINTER and DATED in the environment
#
# `imagetools create` copies the manifest list by digest, so the
# pointer ends up on the same bytes on every architecture rather than
# on a rebuild that merely ought to match. Seconds, no QEMU, no cache.
#
# Why this exists at all: a merge to main builds `src-<key>` and moves
# `:develop`. The scheduled run that night finds `src-<key>` already
# published, and if "already built" meant "do nothing" then `:nightly`
# would stay where it was — and promote.yml draws from `:nightly`, so a
# version number would go on stale bytes.
set -euo pipefail

img=${1:?usage: retag.sh <image>}
repo="docker.io/cr0n1c/$img"
: "${KEY:?KEY not set}" "${POINTER:?POINTER not set}" "${DATED:?DATED not set}"

src="$repo:src-$KEY"

# The plan job decided to skip the build because this existed. If it
# has gone since — pruned, deleted by hand — say so and stop, rather
# than tagging thin air or silently publishing nothing.
if ! docker manifest inspect "$src" >/dev/null 2>&1; then
    echo "::error::$src was there when the run was planned and is not now." \
         "Re-run with force to rebuild it." >&2
    exit 1
fi

digest=$(docker buildx imagetools inspect "$src" \
            --format '{{json .Manifest.Digest}}' | tr -d '"')
echo "$src is $digest"

docker buildx imagetools create \
    --tag "$repo:$POINTER" --tag "$repo:$DATED" "$repo@$digest"

{
    echo "| \`cr0n1c/$img\` | \`$POINTER\`, \`$DATED\` | \`${digest:0:19}…\` | retagged |"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
