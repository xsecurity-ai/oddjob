"""Where a secret was found, as columns rather than as prose.

A secret finding has always recorded its origin -- the asset URL and
the file inside it -- but only by being formatted into
`vulns.description`:

    <detail>

    https://example.test/static/app.js

    File: src/auth/session.ts:118

That is readable and useless. Anything that wants to GROUP secrets
by the file they came from, or show a URL beside a value, has to
re-parse English out of a text column, and a parser over a format
that one `f-string` produces is a parser that breaks the first time
somebody edits the sentence around it.

So the three facts get columns. `_file_vuln` fills them going
forward; this migration backfills what is already stored by parsing
the description ONE last time, here, where the parse is pinned to
the format that was actually used to write those rows.

Backfill is best-effort by design. A row whose description does not
match leaves the columns NULL rather than guessing, and NULL reads
as "not recorded" -- which is true, and is the third outcome. A
wrong URL beside a credential would send somebody to rotate the
wrong thing.

Revision ID: c5a2d83f61e4
Revises: b4e1f90c7d52
"""
from alembic import op
import re
import sqlalchemy as sa

revision = "c5a2d83f61e4"
down_revision = "b4e1f90c7d52"
branch_labels = None
depends_on = None

#: The tail `_file_vuln` appends to every one of these descriptions:
#:
#:     <detail>\n\n<asset url>\n\nFile: <path>[:<line>]
#:
#: Anchored at the end, because `detail` is free text that can
#: itself contain a URL -- an endpoint the scanner quoted back --
#: and matching the first URL in the field would record that one.
_ORIGIN = re.compile(
    r"\n\n(?P<url>https?://[^\n]+)\n\nFile: (?P<path>[^\n]+?)"
    r"(?::(?P<line>\d+))?\s*$")


def upgrade() -> None:
    op.add_column("finding_secrets", sa.Column("asset_url", sa.Text()))
    op.add_column("finding_secrets", sa.Column("path", sa.Text()))
    op.add_column("finding_secrets", sa.Column("line", sa.Integer()))

    # In Python rather than as one UPDATE..FROM with a regex, because
    # that is Postgres-only syntax and the test suites run on SQLite:
    # a migration that only works on the production dialect is one
    # nothing exercises until it runs for real.
    #
    # It reads `vulns.description`, never `finding_secrets.secret`,
    # so no credential is loaded to do this.
    conn = op.get_bind()
    rows = conn.execute(sa.text("""
        SELECT fs.id, v.description
          FROM finding_secrets fs
          JOIN vulns v ON v.id = fs.vuln_id
         WHERE v.description IS NOT NULL
    """)).fetchall()

    updates = []
    for sec_id, desc in rows:
        m = _ORIGIN.search(desc or "")
        if not m:
            # Left NULL on purpose. NULL reads as "not recorded",
            # which is true; a guessed URL beside a credential
            # would send somebody to rotate the wrong thing.
            continue
        updates.append({
            "sid": sec_id,
            "url": m.group("url")[:2000],
            "path": m.group("path")[:2000],
            "line": int(m.group("line")) if m.group("line") else None,
        })

    if updates:
        conn.execute(sa.text("""
            UPDATE finding_secrets
               SET asset_url = :url, path = :path, line = :line
             WHERE id = :sid
        """), updates)
    print(f"  backfilled the origin of {len(updates)} of {len(rows)} "
          f"stored secret(s)")


def downgrade() -> None:
    op.drop_column("finding_secrets", "line")
    op.drop_column("finding_secrets", "path")
    op.drop_column("finding_secrets", "asset_url")
