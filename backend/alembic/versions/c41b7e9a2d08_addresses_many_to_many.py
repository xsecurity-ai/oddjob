"""A host has many addresses, and an address has many hosts

Revision ID: c41b7e9a2d08
Revises: c4b7e2098d15
Create Date: 2026-10-08

`targets.ip_address` held one string. The thing it was modelling does
not fit in one string: a CDN edge or a shared-hosting address serves
dozens of names, and a single name routinely has an A record, a AAAA
record and several more behind a load balancer. The v6 address was the
one being thrown away in practice — the ingest path wrote
`ip_address or ipv6_address`, so a dual-stacked host recorded its v4
and lost the rest.

This moves that column out into `target_addresses` (one row per
address per project) joined through `target_address_links`.

Three things happen here and the order is not negotiable:

  1. `targets.host` is normalised — lowercased, trailing dot stripped —
     BEFORE anything else. Two rows that differ only in case are two
     buckets a single machine's findings were split across, and
     collapsing them is itself a merge: children are reparented and the
     loser is deleted. Doing this after the new tables exist would mean
     carrying addresses for a row that is about to vanish.
  2. The new tables are created and the existing `ip_address` values
     are carried across, normalised to their canonical form.
  3. Only then is the column dropped, with `batch_alter_table` so the
     SQLite path rebuilds the table rather than failing.

**Collisions are reported, not fatal.** A migration that raises
half-way through leaves a database neither at the old revision nor the
new one. Every case-collision merge is printed with both hosts, the
row counts moved, and which id survived, so the operator has a record
of what the upgrade did to their data. It is printed rather than
logged because alembic's logging is configured by the caller and a
message nobody sees is not a report.

**What the downgrade cannot restore.** It is honest about this rather
than quietly keeping the first value:

  * A target with more than one address loses all but the first — the
    column has room for one, which is the entire reason this migration
    exists. The addresses are NOT recoverable afterwards; take a dump
    first if you intend to come back.
  * Which address is "first" is the one with the lowest link id, i.e.
    the earliest observed. That is the same one `Target.ip_address`
    showed, so the column comes back holding what the UI displayed —
    but it is a choice the downgrade is making, not information the
    old schema carried.
  * The case-collision merges in step 1 are not undone. The deleted
     rows are gone and their children now belong to the survivor.
     Nothing records which child came from which side.
"""
from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import ip_address as _parse_ip

import sqlalchemy as sa

from alembic import op

revision: str = 'c41b7e9a2d08'
down_revision: str | Sequence[str] | None = 'c4b7e2098d15'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Children keyed by target_id that have to follow a merged row. Taken
#: from the schema at this revision; a table added later gets its own
#: migration and is not this one's problem.
CHILD_TABLES = ("services", "vulns", "pocs", "events", "web_addresses",
                "implants")


def _canonical(raw):
    """-> the canonical text of an IP literal, or None.

    Same rule as `app.addresses.normalise_address`, repeated rather
    than imported. A migration must keep doing what it did on the day
    it was written; importing from the application would make an old
    migration's behaviour change when that function is next edited.
    """
    s = (raw or "").strip().strip("[]")
    if not s:
        return None
    head, sep, zone = s.partition("%")
    try:
        ip = _parse_ip(head)
    except ValueError:
        return None
    return ip.compressed + (sep + zone.lower() if sep else "")


def _normalise_hosts(conn) -> list[tuple[int, str]]:
    """Lowercase every host, merging the rows that then collide.

    -> (target_id, ip_address) pairs rescued off merged-away rows, for
    the carry step to attach to the survivor. Without this the loser's
    address would be deleted with it, which is exactly the kind of
    silent loss the new model exists to stop: the two rows were one
    machine, so the survivor answers at both addresses.
    """
    rows = conn.execute(sa.text(
        "SELECT id, project_id, host, ip_address FROM targets "
        "ORDER BY id")).fetchall()

    # (project_id, normalised host) -> the id that keeps it. First seen
    # wins, which is the lowest id, which is the oldest row: the one
    # most likely to carry the engagement's earlier work.
    keeper: dict[tuple[int, str], int] = {}
    merges: list[tuple[int, str, str, int, str]] = []
    renames: list[tuple[int, str]] = []
    for tid, pid, host, ip in rows:
        norm = (host or "").strip().rstrip(".").lower()
        if not norm:
            # Nothing to normalise it to and nothing safe to guess.
            # Left exactly as it is; a blank host is a pre-existing
            # problem and inventing a value here would hide it.
            continue
        key = (pid, norm)
        if key in keeper:
            merges.append((tid, host, ip, keeper[key], norm))
        else:
            keeper[key] = tid
            if norm != host:
                renames.append((tid, norm))

    # **Merges before renames, and it has to be this way round.** The
    # row that keeps the name is usually the one whose spelling has to
    # change — `Web01.Acme.Example` normalising onto a `web01.acme.
    # example` that already exists — so renaming first hits the
    # uniqueness constraint against a row that is about to be deleted
    # anyway, and the migration dies half-done. Clearing the losers
    # first makes every rename land on a free name.
    rescued: list[tuple[int, str]] = []
    for loser, loser_host, loser_ip, winner, norm in merges:
        moved = []
        for table in CHILD_TABLES:
            n = conn.execute(
                sa.text(f"UPDATE {table} SET target_id = :w "      # noqa: S608
                        f"WHERE target_id = :l"),
                {"w": winner, "l": loser}).rowcount
            if n:
                moved.append(f"{n} {table}")
        conn.execute(sa.text("DELETE FROM targets WHERE id = :i"),
                     {"i": loser})
        if loser_ip:
            rescued.append((winner, loser_ip))
        print(f"[c41b7e9a2d08] host collision on {norm!r}: target {loser} "
              f"({loser_host!r}) merged into target {winner}; "
              f"moved {', '.join(moved) or 'nothing'}"
              + (f"; its address {loser_ip} goes to the survivor"
                 if loser_ip else ""))

    for tid, norm in renames:
        conn.execute(sa.text("UPDATE targets SET host = :h WHERE id = :i"),
                     {"h": norm, "i": tid})
    if renames:
        print(f"[c41b7e9a2d08] normalised {len(renames)} host(s) to lowercase")
    return rescued


def upgrade() -> None:
    conn = op.get_bind()
    rescued = _normalise_hosts(conn)

    op.create_table(
        "target_addresses",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("address", sa.String(length=45), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False,
                  server_default="4"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "address",
                            name="uq_target_address_project_addr"),
    )
    op.create_index("ix_target_addresses_project_id", "target_addresses",
                    ["project_id"])
    op.create_index("ix_target_addresses_address", "target_addresses",
                    ["address"])
    op.create_index("ix_target_addresses_project_addr", "target_addresses",
                    ["project_id", "address"])

    op.create_table(
        "target_address_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("address_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["address_id"], ["target_addresses.id"],
                                ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_id", "address_id",
                            name="uq_target_address_link"),
    )
    # Indexed because this is a table rows get deleted THROUGH: dropping
    # a target cascades here, and `web_addresses.service_id` already
    # taught us what an unindexed cascade costs — 294,251 rows scanned
    # per delete, and a delete of 46,811 that did not finish in ten
    # minutes.
    op.create_index("ix_target_address_links_target_id",
                    "target_address_links", ["target_id"])
    op.create_index("ix_target_address_links_address_id",
                    "target_address_links", ["address_id"])

    # ---- carry the data across -------------------------------------
    # A Python timestamp, not `func.now()`. The column is NOT NULL with
    # no server default — same as every other `created_at` here — and
    # one value for the whole backfill is the honest one anyway: these
    # rows were all created by this migration, at this moment, and not
    # at the moment each address was first seen. That information was
    # never in the old column and is not being invented here.
    now = datetime.now(UTC)
    rows = list(conn.execute(sa.text(
        "SELECT id, project_id, ip_address FROM targets "
        "WHERE ip_address IS NOT NULL AND ip_address <> '' "
        "ORDER BY id")).fetchall())
    # The addresses taken off rows that a case-collision merged away.
    # Appended, so the survivor's OWN address keeps the lowest link id
    # and stays the one `Target.ip_address` reports — the merge must
    # not change what the grid shows for a row that already existed.
    project_of = dict(conn.execute(sa.text(
        "SELECT id, project_id FROM targets")).fetchall())
    rows += [(tid, project_of[tid], raw) for tid, raw in rescued
             if tid in project_of]
    made: dict[tuple[int, str], int] = {}
    seen_links: set[tuple[int, int]] = set()
    dropped = 0
    for tid, pid, raw in rows:
        value = _canonical(raw)
        if value is None:
            # Not an address. Reported, not silently discarded: the old
            # column was a free string and a scanner that wrote
            # "unknown" into it put a fact about that scan in there.
            dropped += 1
            print(f"[c41b7e9a2d08] target {tid}: ip_address {raw!r} is not "
                  f"an IP literal and was not carried over")
            continue
        key = (pid, value)
        aid = made.get(key)
        if aid is None:
            conn.execute(
                sa.text("INSERT INTO target_addresses "
                        "(project_id, address, version, created_at, updated_at) "
                        "VALUES (:p, :a, :v, :t, :t)"),
                {"p": pid, "a": value,
                 "v": _parse_ip(value.split("%", 1)[0]).version, "t": now})
            # Read the id back rather than trusting `lastrowid`. It is
            # not portable — Postgres does not populate it for a text()
            # INSERT at all — and the unique constraint makes this
            # SELECT exact.
            aid = conn.execute(
                sa.text("SELECT id FROM target_addresses "
                        "WHERE project_id = :p AND address = :a"),
                {"p": pid, "a": value}).scalar_one()
            made[key] = aid
        if (tid, aid) in seen_links:
            # A rescued address the survivor already had. One link, not
            # two: the unique constraint would refuse the second anyway,
            # and refusing it here keeps the migration from dying on a
            # case collision between two rows at the same address.
            continue
        seen_links.add((tid, aid))
        conn.execute(sa.text("INSERT INTO target_address_links "
                             "(target_id, address_id) VALUES (:t, :a)"),
                     {"t": tid, "a": aid})
    print(f"[c41b7e9a2d08] carried {len(rows) - dropped} address(es) across "
          f"into {len(made)} distinct address row(s)")

    # ---- and only now drop the column ------------------------------
    # batch, not drop-and-add: SQLite cannot ALTER, and a drop-and-add
    # on Postgres would work while the SQLite path silently did
    # something else.
    with op.batch_alter_table("targets") as batch:
        batch.drop_index("ix_targets_ip_address")
        batch.drop_column("ip_address")


def downgrade() -> None:
    """Put the single column back, holding the FIRST address only.

    Read the module docstring before running this. A target with more
    than one address keeps its earliest-observed one and loses the
    rest, permanently — there is nowhere in the old schema for them to
    go, which is what this migration existed to fix. The host
    normalisation and any case-collision merges are not undone either.
    """
    conn = op.get_bind()
    with op.batch_alter_table("targets") as batch:
        batch.add_column(sa.Column("ip_address", sa.String(length=45),
                                   nullable=True))
        batch.create_index("ix_targets_ip_address", ["ip_address"])

    rows = conn.execute(sa.text(
        "SELECT l.target_id, a.address, l.id FROM target_address_links l "
        "JOIN target_addresses a ON a.id = l.address_id "
        "ORDER BY l.target_id, l.id")).fetchall()
    first: dict[int, str] = {}
    lost = 0
    for tid, address, _lid in rows:
        if tid in first:
            lost += 1
            continue
        first[tid] = address
    for tid, address in first.items():
        conn.execute(sa.text("UPDATE targets SET ip_address = :a WHERE id = :i"),
                     {"a": address, "i": tid})
    if lost:
        print(f"[c41b7e9a2d08] downgrade DISCARDED {lost} address(es): the "
              f"column holds one per target and these targets had more. "
              f"They are not recoverable from this schema.")

    op.drop_index("ix_target_address_links_address_id",
                  table_name="target_address_links")
    op.drop_index("ix_target_address_links_target_id",
                  table_name="target_address_links")
    op.drop_table("target_address_links")
    op.drop_index("ix_target_addresses_project_addr",
                  table_name="target_addresses")
    op.drop_index("ix_target_addresses_address", table_name="target_addresses")
    op.drop_index("ix_target_addresses_project_id",
                  table_name="target_addresses")
    op.drop_table("target_addresses")
