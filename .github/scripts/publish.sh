#!/usr/bin/env bash
# Put the name on one image.
#
#   publish.sh <image> <was-built> <have-digest>
#
# with POINTER in the environment, and, when <was-built> is true, one
# file per architecture under /tmp/digests holding what that leg
# pushed.
#
# Two paths, one outcome:
#
#   built      assemble the per-architecture digests into a manifest
#              list and put the moving name on it
#   not built  the source already has an image; point the moving name
#              at the digest the plan job found for it
#
# The second is not an optimisation, it is required. A merge builds
# the image and moves `:develop`; the scheduled run that night finds
# the same source already built, and if "already built" meant "do
# nothing" then `:nightly` would stay where it was -- and promote.yml
# draws from `:nightly`, so a version number would land on stale
# bytes.
#
# ------------------------------------------------------- one name
#
# One moving name per run and nothing else. This used to write three:
# the pointer, a dated `develop-<sha>`, and a `src-<key>` per distinct
# source tree -- so a repository that had been merged to a dozen times
# carried a dozen names nobody would ever type.
#
# `src-<key>` was load-bearing and is not simply gone: the question it
# answered, "is there already an image for this exact source", is now
# answered from the `ai.xsecurity.source-key` label the images already
# carry. The plan job reads it off `:develop` and `:nightly` and hands
# the digest here. The fact lives on the bytes instead of in a second
# name beside them.
#
# The dated tag was not load-bearing. Nothing resolved it -- not this
# workflow, not promote.yml, not the deploy -- and a name nobody reads
# is not a pin. Pin by digest; it cannot move under you at all.
set -euo pipefail

img=${1:?usage: publish.sh <image> <was-built> <have-digest>}
built=${2:?missing built flag}
have=${3-}
: "${POINTER:?POINTER not set}"

repo="docker.io/cr0n1cx/$img"

note() {
    echo "| \`cr0n1cx/$img\` | \`$POINTER\` | \`${1:0:19}…\` | $2 |" \
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
    docker buildx imagetools create --tag "$repo:$POINTER" "${refs[@]}"
    how=built
else
    # Nothing was built, so there must be something to point at. The
    # plan job resolved it; an empty value here means it decided not
    # to build and then did not say from what, which is a bug in this
    # workflow rather than a state to paper over by leaving the
    # pointer where it was.
    if [ -z "$have" ]; then
        echo "::error::$img was not built and no existing digest was given." \
             "The plan job must output a digest whenever it skips a build," \
             "or :$POINTER would silently keep its old bytes." >&2
        exit 1
    fi
    echo "retagging $img from $have"
    docker buildx imagetools create --tag "$repo:$POINTER" "$repo@$have"
    how=retagged
fi

digest=$(docker buildx imagetools inspect "$repo:$POINTER" \
          --format '{{json .Manifest.Digest}}' | tr -d '"')
note "$digest" "$how"
echo "cr0n1cx/$img:$POINTER is $digest ($how)"
