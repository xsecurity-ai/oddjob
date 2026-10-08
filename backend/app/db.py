"""Async SQLite engine and session plumbing.

Three PRAGMAs are set on every new connection, and all three matter:

  foreign_keys=ON   SQLite defaults this OFF, per connection. Without it the
                    ON DELETE CASCADE declared on services/vulns/pocs is
                    silently ignored and deleting a target orphans its rows.
  journal_mode=WAL  Lets reads proceed while a bulk import is writing. Without
                    it the UI blocks for the length of a 6,000-row load.
  busy_timeout      Waits for a lock instead of failing instantly with
                    "database is locked" when a write overlaps a read.
"""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .models import Base

DB_PATH = Path(os.environ.get("ODDJOB_DB", Path(__file__).resolve().parents[1] / "oddjob.db"))

# A customer running on their own Postgres sets this. It has to come from
# the ENVIRONMENT and not from Site Config, and the reason is structural:
# the settings table lives in the database, so a connection string stored
# there could not be read until after the connection it describes is
# already open. Site Config can hold, mask, test and migrate to a DSN —
# but the switch itself is a startup decision.
_EXTERNAL = (os.environ.get("ODDJOB_DATABASE_URL") or "").strip()

if _EXTERNAL:
    DATABASE_URL = _EXTERNAL
    # Accept the plain forms people paste and route them to the async driver.
    for _prefix in ("postgresql://", "postgres://"):
        if DATABASE_URL.startswith(_prefix):
            DATABASE_URL = "postgresql+asyncpg://" + DATABASE_URL[len(_prefix):]
            break
else:
    DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

IS_SQLITE = DATABASE_URL.startswith("sqlite")

#: Safe to print or serve: the password is never in it.
def display_url() -> str:
    if IS_SQLITE:
        return str(DB_PATH)
    from .dsn import mask
    return mask(DATABASE_URL)


if IS_SQLITE:
    engine = create_async_engine(DATABASE_URL, echo=False, future=True)
else:
    # Postgres needs a real pool; SQLite's default is right for a file.
    # pre_ping because a customer's database sits behind a network that
    # will silently drop an idle connection and hand back a dead socket.
    engine = create_async_engine(
        DATABASE_URL, echo=False, future=True,
        pool_size=int(os.environ.get("ODDJOB_POOL_SIZE", "10")),
        max_overflow=int(os.environ.get("ODDJOB_POOL_OVERFLOW", "20")),
        pool_pre_ping=True, pool_recycle=1800)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


if IS_SQLITE:
    @event.listens_for(engine.sync_engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        """SQLite-only. PRAGMA is not SQL — running these against Postgres
        is a syntax error on every single connection."""
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.close()


def _check_drift(sync_conn) -> None:
    """Refuse to start on a database older than the models.

    create_all() adds MISSING TABLES but never alters an existing one, so a
    new column on an existing model leaves the file silently stale and every
    request that touches it returns 500. There is no migration tool here yet,
    so the honest behaviour is to fail at startup and say exactly what is
    wrong, rather than serve a half-broken API.
    """
    from sqlalchemy import inspect
    insp = inspect(sync_conn)
    drift: list[str] = []
    for name, table in Base.metadata.tables.items():
        if not insp.has_table(name):
            continue                      # create_all handles this case
        have = {c["name"] for c in insp.get_columns(name)}
        missing = sorted(set(table.columns.keys()) - have)
        if missing:
            drift.append(f"  {name}: missing {', '.join(missing)}")
    if drift:
        raise RuntimeError(
            "the database schema is older than the models:\n"
            + "\n".join(drift)
            + "\n\nA model was changed without a migration. Generate one:\n"
              "  uv run alembic revision --autogenerate -m 'what changed'\n"
              "  uv run alembic upgrade head"
        )


# --------------------------------------------------------------- alembic
def _alembic_config():
    from alembic.config import Config
    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("script_location",
                        str(Path(__file__).resolve().parents[1] / "alembic"))
    cfg.set_main_option("sqlalchemy.url", DATABASE_URL.replace("%", "%%"))
    return cfg


def _head() -> str:
    from alembic.script import ScriptDirectory
    return ScriptDirectory.from_config(_alembic_config()).get_current_head()


def _state(sync_conn) -> tuple[str | None, bool]:
    """-> (current revision, whether the app's tables already exist)."""
    from alembic.runtime.migration import MigrationContext
    from sqlalchemy import inspect
    rev = MigrationContext.configure(sync_conn).get_current_revision()
    populated = inspect(sync_conn).has_table("targets")
    return rev, populated


def _stamp(sync_conn, rev: str) -> None:
    """Record a revision without running it.

    Needed for a database that predates Alembic: its tables are already
    there, so running the baseline migration would fail on CREATE TABLE.
    The drift check immediately afterwards is what verifies the assumption
    that such a database really is at the baseline.
    """
    from alembic.runtime.migration import MigrationContext
    ctx = MigrationContext.configure(sync_conn)
    ctx.stamp(__import__("alembic.script", fromlist=["ScriptDirectory"])
              .ScriptDirectory.from_config(_alembic_config()), rev)


def _upgrade(sync_conn) -> None:
    from alembic import command
    cfg = _alembic_config()
    cfg.attributes["connection"] = sync_conn
    command.upgrade(cfg, "head")


AUTO_MIGRATE = os.environ.get("ODDJOB_AUTO_MIGRATE", "1") not in ("0", "false", "no")


async def init_db() -> None:
    head = _head()

    async with engine.begin() as conn:
        rev, populated = await conn.run_sync(_state)

        if rev is None and not populated:
            # Brand new. Build from the migrations so the schema and its
            # history agree from the first run.
            await conn.run_sync(_upgrade)
        elif rev is None and populated:
            # Predates Alembic. Adopt it at the baseline rather than
            # trying to create tables that are already there.
            await conn.run_sync(_stamp, head)
            print(f"adopted an existing database at revision {head[:12]}")
        elif rev != head:
            if AUTO_MIGRATE:
                await conn.run_sync(_upgrade)
                print(f"migrated {rev[:12] if rev else 'base'} -> {head[:12]}")
            else:
                raise RuntimeError(
                    f"the database is at revision {rev}, the code expects "
                    f"{head}. Run `uv run alembic upgrade head`, or set "
                    f"ODDJOB_AUTO_MIGRATE=1 to apply it at startup.")

        # Belt and braces: catches a model edited without a migration
        # generated for it, which Alembic cannot know about.
        await conn.run_sync(_check_drift)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
