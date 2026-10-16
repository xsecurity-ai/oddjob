#!/usr/bin/env bash
# Start Oddjob against the Postgres container.
#
# The DSN is an ENVIRONMENT variable, not a setting: the settings table
# lives inside the database, so a connection string stored there could
# not be read until the connection it describes was already open.
set -euo pipefail
cd "$(dirname "$0")"
set -a; . ./pg.env; set +a
exec uv run uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}" "$@"
