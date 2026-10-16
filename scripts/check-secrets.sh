#!/usr/bin/env bash
# No credentials, keys or engagement data in a public repository.
#
# This repository is public and the application it builds handles
# client engagement data — findings, captured traffic, hostnames. A
# credential or a database landing here is a disclosure, so it fails
# rather than waiting to be noticed in review.
#
# One script, two callers: ci.yml's `secrets` job and the pre-commit
# hook of the same name. Two copies of this test would eventually
# disagree, and the one that matters is whichever is weaker.
#
# TruffleHog runs alongside this and does a different job: it verifies
# candidates against the provider, so it finds live keys in shapes
# nobody wrote down here. This finds the shapes that matter to this
# repository even when the key is already revoked — which is most of
# them by the time anyone looks.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

fail=0

# Files that are never acceptable, by name or extension.
if git ls-files | grep -nE '\.(db|sqlite3?|pem|key)$|(^|/)\.secret$|(^|/)pg\.env$|(^|/)\.env$'; then
    echo "error: a database, key or environment file is committed" >&2
    fail=1
fi

# Real tokens have a length; the placeholders in the docs and tests do
# not reach these thresholds. Kept deliberately narrow — a pattern
# that fires on example values is one people learn to skip past.
if git grep -nIE 'xoxb-[A-Za-z0-9-]{20,}|xapp-[A-Za-z0-9-]{20,}|ghp_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9_-]{40,}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY|dckr_pat_[A-Za-z0-9_-]{20,}|msk_[A-Za-z0-9_-]{30,}' -- . ; then
    echo "error: what looks like a real credential is committed" >&2
    fail=1
fi

exit $fail
