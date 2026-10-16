#!/usr/bin/env bash
# Lint both Dockerfiles, the way CI does.
#
# Through Docker rather than a locally installed hadolint, so the
# version and the ruleset are the ones hadolint-action uses in CI. A
# hook that disagrees with CI is worse than no hook.
#
# Both files are always checked, even though pre-commit knows which
# one changed: they share .hadolint.yaml, so a config edit can break
# the file you did not touch.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Matches the image hadolint-action v3.5.0 runs.
IMAGE=hadolint/hadolint:v2.15.1

fail=0
for f in Dockerfile ghost/Dockerfile; do
    # `-t style` is the strictest threshold — every rule fails.
    # .hadolint.yaml sets the same thing; passing it here means the
    # hook does not quietly become more lenient if that file moves.
    if ! docker run --rm -i \
            -v "$PWD/.hadolint.yaml":/.hadolint.yaml:ro \
            "$IMAGE" hadolint -c /.hadolint.yaml -t style - < "$f"; then
        echo "  ^ in $f" >&2
        fail=1
    fi
done

exit $fail
