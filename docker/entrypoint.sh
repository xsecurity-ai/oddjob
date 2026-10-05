#!/usr/bin/env sh
# Migrate, then serve.
#
# Migrations run here rather than in the application's startup hook so
# that a failed migration stops the container instead of leaving it
# serving against a schema it does not match — which looks like a
# hundred unrelated bugs rather than one clear error.
set -eu

if [ -n "${ODDJOB_DATABASE_URL:-}" ]; then
    echo "oddjob: database is PostgreSQL"
else
    echo "oddjob: no ODDJOB_DATABASE_URL set — using SQLite at ${ODDJOB_DB:-backend/oddjob.db}"
    echo "        SQLite takes one writer at a time; a long import and the"
    echo "        background workers will contend. Use the compose file's"
    echo "        Postgres for anything beyond a look around."
fi

echo "oddjob: applying migrations"
alembic upgrade head

exec uvicorn app.main:app \
    --host "${HOST:-0.0.0.0}" \
    --port "${PORT:-8000}" \
    --proxy-headers \
    --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
    --log-level "${LOG_LEVEL:-info}"
