#!/usr/bin/env python3
"""Superseded by Alembic. This is a signpost, not a tool.

    uv run alembic upgrade head                      # apply
    uv run alembic revision --autogenerate -m "..."  # after a model change
    uv run alembic downgrade -1                      # undo the last one
    uv run alembic current / history                 # where am I

The app applies pending migrations at startup unless ODDJOB_AUTO_MIGRATE=0,
and a database that predates Alembic is adopted at the baseline rather than
rebuilt.

Kept as a file because the old instructions are in shell history and in the
README's git history, and a "command not found" is a worse answer than a
pointer.
"""
import sys

print(__doc__)
print("Running `alembic upgrade head` for you…\n")
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from pathlib import Path  # noqa: E402

cfg = Config(str(Path(__file__).resolve().parent / "alembic.ini"))
try:
    command.upgrade(cfg, "head")
except Exception as e:
    sys.exit(f"{type(e).__name__}: {e}")
