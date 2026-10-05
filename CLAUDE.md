# Working on Oddjob

Notes for Claude. Everything here was learned by getting it wrong first.

## Run and test

```bash
cd backend  && uv run uvicorn app.main:app --reload   # API, serves the built UI
cd frontend && npm run dev                            # UI, /api proxied

cd backend  && uv run python runtests.py              # all suites
cd backend  && uv run python runtests.py webtest      # one, by name
cd frontend && npx tsc --noEmit && node test/hooks.check.mjs
```

Backend suites live in `backend/tests/`; `runtests.py` stays at the
backend root because it is the command you type. Each suite gets its own
server, port and SQLite file.

**The backend suite needs `frontend/dist` to exist.** It asserts the
sign-in page, the SPA routes and the favicons are served. Without a
build, nine assertions 404 and the failure looks like an auth bug.

## This repository is public

It builds a tool that holds client engagement data. Never commit:

- a database, `.secret`, `pg.env`, `.env`, keys, scanner output
- **a real client's hostnames, IP ranges, project names or findings** —
  including in a test fixture or a code comment. Use `*.acme.example`,
  `ACME`, `FALCON`. A client name here discloses who the engagement was
  with.

CI fails the build on both. Check before staging, not after.

## Things that will bite

**SQLite forgives what Postgres does not.** It ignores `VARCHAR`
lengths and stores NUL bytes in text. A column declared `String(2048)`
held an 8,221-character URL for months. Captured HTTP responses contain
NUL. Run the Postgres CI job before believing a schema change.

**A Postgres btree entry caps near 2.7 KB.** Long text cannot be
indexed at all — the INSERT fails, not the query. `url` is unbounded
`Text` with a `url_hash` carrying the index and the uniqueness.

**Index every foreign key you delete through.** `web_addresses.service_id`
had none; deleting 46,811 services sequentially scanned 294,251 rows per
delete and did not finish in ten minutes.

**Alembic: `default=` is Python-side.** Adding a `NOT NULL` column needs
`server_default`, or the migration fails on a populated table. Adding
one with no default at all fails outright — add nullable, backfill, then
set `NOT NULL`.

**Autogenerate diffs against whatever `ODDJOB_DB` points at.** Generate
against a database built from the migrations, never the dev one, or a
column added out of band never reaches a migration. Strip the phantom
`server_default` round-trips it proposes: on SQLite `alter_column` means
`batch_alter_table`, which copies the whole table.

**Never hand-list fields.** `_out` in the projects router and the tuples
in `bulk.py` both silently dropped a column that was being stored
correctly (`codename`, `remediation`). Derive them from the schema.

**`ODDJOB_DATABASE_URL` beats `ODDJOB_DB`.** It is exported in the same
shell you use to run the app, so it will point your tests at production
if nothing strips it. `runtests.py` strips it; keep it that way.

**React hooks after an early return** blank the page at runtime and
typecheck fine. `test/hooks.check.mjs` catches it.

**The MIT DataGrid throws above 100 rows a page** and cannot do
master-detail. Paging, sorting, filtering and row expansion are all done
outside it; the grid gets `pageSize: -1` and one finished page of rows.

## How the data is shaped

- A web row is one **captured exchange** — `sha256(method, url, request,
  response)` — not one URL. The same endpoint probed ten ways is ten
  pieces of evidence. The UI groups them back under the URL.
- **Only open ports are recorded.** One `-sU` sweep produced 42,890
  `open|filtered` rows against 13 genuinely open ports.
- Targets are `host`, `mobile` or `cloud`. A blank IP means "unresolved"
  on a host and "nothing to resolve" on an app. Cloud identifiers are
  not hostnames — an ARN fails every DNS rule — so they validate
  differently.
- Imports are **strict by default**: they write only to hosts the
  project already has and report the rest for a decision. The file is
  held server-side so answering costs no second upload.

## House style

Say what is true. A failed lookup is a fact about the tool, not about
the target — "found", "absent" and "could not determine" are three
different answers and collapsing the third into the second is how a
finding gets missed. Comments explain *why*, especially where the
obvious thing was tried and did not work. When something is verified,
say so plainly; when it is not, say that instead.
