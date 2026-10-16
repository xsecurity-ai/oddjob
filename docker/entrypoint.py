#!/usr/bin/env python
"""Migrate, then serve.

Migrations run here rather than in the application's startup hook so
that a failed migration stops the container instead of leaving it
serving against a schema it does not match — which looks like a
hundred unrelated bugs rather than one clear error.

Python rather than sh because the runtime image is distroless: there
is no shell in it to run a shell script with. This is a transcription
of the sh version, not a redesign — same output, same order, same
exec at the end.
"""
import os
import sys


def say(line: str) -> None:
    # Unbuffered, or the banner appears after uvicorn's own logging
    # when stdout is a pipe rather than a terminal — which is every
    # case that matters, `docker logs` included.
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def main() -> None:
    if os.environ.get("ODDJOB_DATABASE_URL"):
        say("oddjob: database is PostgreSQL")
    else:
        db = os.environ.get("ODDJOB_DB", "backend/oddjob.db")
        say(f"oddjob: no ODDJOB_DATABASE_URL set — using SQLite at {db}")
        say("        SQLite takes one writer at a time; a long import and the")
        say("        background workers will contend. Use the compose file's")
        say("        Postgres for anything beyond a look around.")

    say("oddjob: applying migrations")
    # In-process rather than spawning `alembic`: there is no shell to
    # resolve it on PATH, and a non-zero exit has to stop the
    # container rather than be swallowed. A raised exception does
    # exactly that, with the traceback in the logs.
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), "head")

    # execv, not subprocess: uvicorn replaces this process so it is
    # pid 1 and receives SIGTERM from `docker stop` directly. Behind a
    # parent that does not forward signals, a stop becomes a ten
    # second wait and then SIGKILL — mid-write, for a database.
    argv = [
        sys.executable, "-m", "uvicorn", "app.main:app",
        "--host", os.environ.get("HOST", "0.0.0.0"),
        "--port", os.environ.get("PORT", "8000"),
        "--proxy-headers",
        "--forwarded-allow-ips", os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        "--log-level", os.environ.get("LOG_LEVEL", "info"),
    ]
    os.execv(sys.executable, argv)


if __name__ == "__main__":
    main()
