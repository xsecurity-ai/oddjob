#!/usr/bin/env bash
# Put the names on one image.
#
#   publish.sh <image> <source-key> <was-built>
#
# with POINTER and DATED in the environment, and, when <was-built> is
# true, one file per architecture under /tmp/digests holding what that
# leg pushed.
#
# Two paths, one outcome:
#
#   built      assemble the per-architecture digests into a manifest
#              list and tag it
#   not built  the source already has an image; point the moving tags
#              at the digest that image already has
#
# The second is not an optimisation, it is required. A merge builds
# `src-X` and moves `:develop`; the scheduled run that night finds
# `src-X` published, and if "already built" meant "do nothing" then
# `:nightly` would stay where it was — and promote.yml draws from
# `:nightly`, so a version number would land on stale bytes.
set -euo pipefail

img=${1:?usage: publish.sh <image> <source-key> <was-built>}
key=${2:?missing source key}
built=${3:?missing built flag}
: "${POINTER:?POINTER not set}" "${DATED:?DATED not set}"

repo="docker.io/cr0n1c/$img"
src="$repo:src-$key"

note() {
    echo "| \`cr0n1c/$img\` | \`src-$key\`, \`$POINTER\`, \`$DATED\` | \`${1:0:19}…\` | $2 |" \
        >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
}

if [ "$built" = "true" ]; then
    # One `-r` per architecture. Globbed rather than listed, so adding
    # a third architecture to the matrix needs no change here.
    refs=()
    for f in /tmp/digests/"$img"-*; do
        [ -e "$f" ] || continue
        refs+=("$repo@$(cat "$f")")
    done
    if [ ${#refs[@]} -eq 0 ]; then
        echo "::error::$img was built but no digests arrived." \
             "A build leg pushed nothing, or its artifact did not upload." >&2
        exit 1
    fi
    # Refused rather than published: a manifest list with one
    # architecture under a name that has always served two is worse
    # than no publish, because every arm64 host pulling `:develop`
    # starts failing and the tag looks fine from an amd64 laptop.
    if [ ${#refs[@]} -lt 2 ]; then
        echo "::error::$img has only ${#refs[@]} architecture(s): ${refs[*]}." \
             "Publishing that under :$POINTER would drop an architecture." >&2
        exit 1
    fi
    echo "assembling $img from ${#refs[@]} architectures"
    docker buildx imagetools create \
        --tag "$src" --tag "$repo:$POINTER" --tag "$repo:$DATED" \
        "${refs[@]}"
    how="built"
else
    # The plan job skipped the build because this existed. If it has
    # gone since — pruned, deleted by hand — say so and stop, rather
    # than tagging thin air.
    if ! docker manifest inspect "$src" >/dev/null 2>&1; then
        echo "::error::$src was there when the run was planned and is not now." \
             "Re-run with force to rebuild it." >&2
        exit 1
    fi
    echo "$src already exists — moving tags onto it"
    docker buildx imagetools create \
        --tag "$repo:$POINTER" --tag "$repo:$DATED" "$src"
    how="retagged"
fi

digest=$(docker buildx imagetools inspect "$repo:$POINTER" \
            --format '{{json .Manifest.Digest}}' | tr -d '"')
echo "cr0n1c/$img:$POINTER is $digest ($how)"
note "$digest" "$how"
