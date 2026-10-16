#!/usr/bin/env bash
# Move an existing Oddjob database from PostgreSQL 17 to 18.
#
# Needed because the db image changed to Chainguard's, which is
# PostgreSQL 18. Postgres refuses to start against a data directory
# written by a different major version:
#
#   FATAL:  database files are incompatible with server
#   DETAIL: The data directory was initialized by PostgreSQL version 17,
#           which is not compatible with this version 18.6.
#
# There is no in-place upgrade here. The data comes out as SQL, the
# volume is destroyed, and the data goes back in. That is the whole
# operation, and every risky part of it is the middle step.
#
#   ./deploy/pg17-to-18.sh              dry run: dump and verify only
#   ./deploy/pg17-to-18.sh --commit     actually do it
#
# The dump is written next to this script and is NOT deleted,
# whatever happens. If the restore goes wrong it is the only copy of
# the engagement, so it outlives the script deliberately.
set -euo pipefail

cd "$(dirname "$0")/.."

COMMIT=0
[ "${1:-}" = "--commit" ] && COMMIT=1

PROJECT=${COMPOSE_PROJECT_NAME:-oddjob}
DUMP="deploy/pg17-dump-$(date -u +%Y%m%dT%H%M%SZ).sql"
USER_NAME=${POSTGRES_USER:-oddjob}

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---- 1. is there anything to migrate? -------------------------------
if ! docker volume inspect "${PROJECT}_pgdata" >/dev/null 2>&1; then
    say "No ${PROJECT}_pgdata volume. This is a fresh install —"
    say "nothing to migrate, just \`docker compose up -d\`."
    exit 0
fi

ver=$(docker run --rm -v "${PROJECT}_pgdata":/d alpine \
        sh -c 'cat /d/PG_VERSION 2>/dev/null || echo unknown' | tr -d '[:space:]')
say "existing data directory: PostgreSQL ${ver}"
case "$ver" in
    18) say "Already 18. Nothing to do."; exit 0 ;;
    17) ;;
    *)  die "expected 17, found '${ver}'. This script only handles 17 -> 18." ;;
esac

# ---- 2. dump, using the OLD major ------------------------------------
# NOT through compose. The compose file has already been changed to
# PostgreSQL 18 — that is why this script exists — so
# `docker compose up -d db` here would start 18 against the 17
# directory, crash-loop, and dump nothing. That is not hypothetical:
# the first version of this script did exactly that and produced a
# zero-byte dump.
#
# So the dump runs against a throwaway postgres:17 bound to the same
# volume, which is independent of whatever the compose file now says.
TMP=oddjob-pg17-dump-$$
cleanup() { docker rm -f "$TMP" >/dev/null 2>&1 || true; }
trap cleanup EXIT

say "stopping the app so nothing writes during the dump"
docker compose -p "$PROJECT" stop app >/dev/null 2>&1 || true
docker compose -p "$PROJECT" stop db >/dev/null 2>&1 || true

say "starting a temporary postgres:17 against ${PROJECT}_pgdata"
# No password needed: the directory already exists so the entrypoint
# skips initialisation, and `docker exec` connects over the local
# socket, which the official image trusts.
docker run -d --name "$TMP" \
    -v "${PROJECT}_pgdata":/var/lib/postgresql/data \
    postgres:17 >/dev/null

ready=0
for _ in $(seq 1 30); do
    if docker exec "$TMP" pg_isready -q -U "$USER_NAME" 2>/dev/null; then ready=1; break; fi
    sleep 2
done
[ "$ready" = 1 ] || {
    docker logs "$TMP" 2>&1 | tail -5
    die "the temporary postgres:17 did not come up; nothing has been changed"
}

say "dumping -> ${DUMP}"
# On failure the redirect has already created an empty file. Removing
# it matters: a zero-byte dump left lying next to the real ones is
# exactly the thing someone restores from at 3am.
if ! docker exec "$TMP" pg_dumpall -U "$USER_NAME" --clean --if-exists > "$DUMP"; then
    rm -f "$DUMP"
    die "pg_dumpall failed; nothing has been changed"
fi
cleanup
trap - EXIT

# ---- 3. refuse to go further on a dump that looks wrong --------------
# The failure this guards against is the one that matters: destroying
# a volume on the strength of a dump that is empty because the
# password was wrong, or truncated because the disk filled.
bytes=$(wc -c < "$DUMP" | tr -d ' ')
tables=$(grep -c '^CREATE TABLE' "$DUMP" || true)
say "dump: ${bytes} bytes, ${tables} CREATE TABLE statements"
[ "$bytes" -gt 2000 ] || die "dump is only ${bytes} bytes — refusing to continue"
[ "$tables" -gt 10 ] || die "only ${tables} tables in the dump — refusing to continue"
grep -q 'PostgreSQL database cluster dump complete' "$DUMP" \
    || die "dump has no completion marker — it was truncated"
say "dump looks complete."

if [ "$COMMIT" -ne 1 ]; then
    say ""
    say "Dry run. Nothing has been changed."
    say "The dump above is kept. Re-run with --commit to:"
    say "  - stop the stack"
    say "  - DESTROY the ${PROJECT}_pgdata volume"
    say "  - start PostgreSQL 18 and restore the dump"
    exit 0
fi

# ---- 4. the destructive part ------------------------------------------
say ""
say "stopping the stack and destroying ${PROJECT}_pgdata"
docker compose -p "$PROJECT" down
docker volume rm "${PROJECT}_pgdata"

say "starting PostgreSQL 18 on an empty volume"
# No ownership fixing needed: the new volume is initialised by the new
# image, which runs as its own uid (70 in Chainguard's, against 999 in
# the official one). That difference is exactly why this cannot be an
# in-place swap of the image alone.
docker compose -p "$PROJECT" up -d db
for _ in $(seq 1 60); do
    docker compose -p "$PROJECT" exec -T db pg_isready -q -U "$USER_NAME" && break
    sleep 2
done
docker compose -p "$PROJECT" exec -T db pg_isready -q -U "$USER_NAME" \
    || die "PostgreSQL 18 did not come up. The dump is still at ${DUMP}."

say "restoring"
docker compose -p "$PROJECT" exec -T db psql -U "$USER_NAME" -d postgres < "$DUMP"

say "starting the app"
docker compose -p "$PROJECT" up -d

say ""
say "done. The dump is kept at ${DUMP} — delete it once you have"
say "confirmed the application is working, because it contains"
say "everything the database held."
