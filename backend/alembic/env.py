"""Alembic environment.

Two things here are not boilerplate and matter:

**The URL comes from the app, not from alembic.ini.** `app.db` already
works out whether this deployment is on SQLite or on a customer's
Postgres, including turning a pasted `postgresql://` into the async
driver. Duplicating that logic in a second place is how the migration
runner ends up pointed at a different database than the application.

**`render_as_batch` for SQLite.** SQLite cannot ALTER a column — it has
no DROP COLUMN before 3.35 and still cannot change a type or add a
constraint. Batch mode makes Alembic rebuild the table instead: create a
new one, copy the rows, swap. Without it, every migration that is not a
plain ADD COLUMN fails on SQLite and works on Postgres, which is the
worst possible place for the two to diverge.
"""
from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import DATABASE_URL  # noqa: E402
from app.models import Base  # noqa: E402

config = context.config
if config.config_file_name is not None and not os.environ.get("ODDJOB_QUIET_ALEMBIC"):
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))

target_metadata = Base.metadata

IS_SQLITE = DATABASE_URL.startswith("sqlite")


def _configure(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # See the module docstring: without this, SQLite and Postgres
        # diverge on anything beyond ADD COLUMN.
        render_as_batch=IS_SQLITE,
        compare_type=True,
        compare_server_default=_same_default,
    )


def _same_default(context, inspected_column, metadata_column,
                  inspected_default, metadata_default,
                  rendered_metadata_default):
    """Whether two server defaults really differ, for SQLite.

    SQLite reflects a default back wrapped in parentheses: a column
    declared `DEFAULT ''` comes back as `('')`, and `DEFAULT 0` as
    `(0)`. With `compare_server_default=True` that cosmetic difference
    reads as a change, so every autogenerate proposed an `alter_column`
    that does nothing -- and on SQLite `alter_column` means
    `batch_alter_table`, which COPIES THE WHOLE TABLE. On
    `web_addresses`, holding a proxy history at up to 64 KB per row,
    that is a multi-gigabyte rewrite to change nothing.

    Returning None falls through to Alembic's own comparison, so a
    genuine default change is still caught.
    """
    def norm(v):
        if v is None:
            return None
        t = str(getattr(v, "arg", v)).strip()
        while t.startswith("(") and t.endswith(")"):
            t = t[1:-1].strip()
        if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
            t = t[1:-1]
        return t

    if norm(inspected_default) == norm(rendered_metadata_default or metadata_default):
        return False
    return None


def run_migrations_offline() -> None:
    context.configure(
        url=DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=IS_SQLITE,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    _configure(connection)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    # The app's startup hands us a live connection through
    # config.attributes. Use it rather than opening a second one: we are
    # already inside its transaction and inside a running event loop, so
    # creating another engine here would both deadlock SQLite and fail on
    # asyncio.run().
    existing = config.attributes.get("connection")
    if existing is not None:
        do_run_migrations(existing)
        return
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
