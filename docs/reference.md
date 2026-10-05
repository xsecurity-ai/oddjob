# Oddjob — reference

The long-form notes: every subsystem, why it is built the way it is, and
the traps found the hard way. Start with the [README](../README.md); come
here when you need the detail.

---

Engagement data store — projects, targets, ports/services, vulns and PoCs.
FastAPI + SQLite behind a React/MUI UI, with an MCP server so Claude can read
and write it directly.

```
backend/    FastAPI, SQLAlchemy 2, SQLite      → http://127.0.0.1:8000
frontend/   React 19, Vite 7, MUI 7 + DataGrid → http://127.0.0.1:5173 (dev)
backend/oddjob_mcp.py   MCP server (stdio)
```

## Run it

```bash
# API (serves the built UI too, if frontend/dist exists)
cd backend && uv run uvicorn app.main:app --reload --port 8000

# UI in dev mode, with hot reload and /api proxied to the backend
cd frontend && npm run dev
```

Open the app. **There is no default account.** On an empty database it asks
you to create the first one, which becomes the site administrator; that
endpoint stops working the moment an account exists.

Interactive API docs: <http://127.0.0.1:8000/docs>

## Model

```
Project 1---* Target 1---* Service   (a "port" and a "service" are one row)
                     1---* Vuln
                     1---* Poc
```

- **Project** keyed by `code` (`FALCON-1`). Every target belongs to one.
- **Target** keyed by `(project, host)`. Host is an FQDN or bare IP —
  **unique per project, not globally**, because the same asset recurs across
  consecutive engagements.
- **Service** keyed by `(target, port, protocol)`. One table, because nmap
  emits port, protocol, state, name and banner as a single fact.
  `GET /api/ports` is the same table pinned to `state='open'` — still there
  for scripts and MCP, though the UI no longer has a separate Ports tab
  (it was the Services grid with four of its columns hidden).
- **alive** is tri-state: `null` not probed, `true` responding, `false`
  probed and silent. "Not probed" is a gap in our coverage, not a claim about
  the asset.
- Vuln/PoC counts on the Targets grid are aggregated at query time, never
  stored, so they cannot drift.

### What is not a host

`host` is the join key for everything, so one junk value becomes a bucket
unrelated findings pile into. Wildcards (`*.acme.example`), regex fragments,
anything with whitespace or a slash (`docker.io/org/image`) are rejected.
A non-IP in `ip_address` — a hostname, a scanner's `SYNTHETIC-...` marker —
is coerced to null rather than widening the column into "some string".

## Auth

- **Every route is authenticated.** The only exceptions are first-run setup
  and the sign-in endpoints themselves, plus the page and bundle needed to
  render the sign-in screen. The check is middleware, not a per-route
  dependency, so it also covers `/docs`, `/openapi.json` and paths that do
  not exist; the routes keep their own checks underneath it.
- An unauthenticated **browser** request is sent to the sign-in screen
  with the page it wanted remembered: `302 → /?next=/projects/ACME/vulns`.
  Signing in lands you there, and the screen says which page it is waiting
  to take you to. An unauthenticated **XHR** gets `401`, because the SPA
  reads 401 as "your session ended, sign in again"; answering a fetch with
  a redirect would have it parse the login page as JSON.
- **Probing still learns nothing.** Every unauthenticated path redirects
  identically — a real one, an invented one and `/wp-admin` are
  indistinguishable apart from the path echoed back to the person who
  typed it.
- **Once signed in, a missing page is a 404**, not a 403. There is nothing
  left to withhold from someone who has proved who they are, and
  pretending every unknown path is forbidden makes a typo unreadable.
- `next` is validated on **both** sides. `//evil.com` is a
  protocol-relative URL browsers follow off-site, and checking it in one
  place only is how a return-path parameter becomes a phishing link.
- `readonly < user < admin`, granted **per project** to a user or a group.
- **Google sign-in** is configured in Site Config (environment variables are
  a fallback) and must pass **Test** before it can be switched on. A Google-registered
  account **joins no groups** — it can sign in and sees nothing until an
  administrator grants it a project. Registration is identity, not
  authorisation, and Google can never produce the first site admin.
- A **profile page** covers name, email, password and API keys. Changing an
  existing password requires the current one; a Google-only account has none
  to prove, so it may simply set one.
- Effective role = the highest grant across the user's own ACL and their
  groups. No grant means the project 404s — telling an unauthorised caller it
  exists is itself a disclosure.
- Site-wide authority is membership of the reserved **`site-admins`** group,
  not a per-user flag. That group cannot be deleted or emptied.
- Three credentials work: the login cookie (httpOnly, what the SPA and the
  SSE stream use), a bearer JWT, and `msk_…` API keys for scripts and MCP.

## Bulk import

`POST /api/bulk` upserts any mix of entities into one project in one
transaction. Idempotent — upsert keys are host, `(host, port, protocol)`,
`external_id` (falling back to `(host, title)` only when absent), and
`(host, title)`.

Rows with an unusable host are **skipped and reported in `errors`**, not
fatal: a real scanner export always contains some junk, and an all-or-nothing
importer just gets worked around. Always check `created`/`updated`/`skipped`
— they are built to add up to what you sent.

```bash
curl -X POST localhost:8000/api/bulk -H "Authorization: Bearer msk_…" \
  -H 'Content-Type: application/json' -d '{
    "project": "FALCON-1",
    "targets":  [{"host":"web01.acme.example","ip_address":"10.1.1.1","alive":true}],
    "services": [{"host":"web01.acme.example","port":443,"name":"https"}]
  }'
```

## Importing tool output

```
GET  /api/scans/formats
POST /api/scans/import?project=CODE         {"content": "…", "format": "auto"}
POST /api/scans/import/upload?project=CODE   multipart file
```

| format | produced by |
|---|---|
| `nmap` | `nmap -sV -O -A -oX` |
| `masscan` | `-oX`, `-oJ` and the `-oL` grepable list |
| `nessus` | Nessus/Tenable `.nessus` v2 |
| `metasploit` | `db_export -f xml` |
| `burp` | Scanner → Report issues → XML |
| `burphistory` | Proxy → HTTP history → select all → Save items |
| `nikto` | `-Format json` or `-Format xml` |
| `nuclei` | `-jsonl` |
| `httpx` | `-json`; also reads naabu JSONL |
| `cobaltstrike` `mythic` `merlin` `sliver` `havoc` | C2 session lists — see below |

`format: "auto"` sniffs the content. Detection returning *nothing* is a real
answer and the import is refused with the list of what is supported:
guessing wrong produces a confident import of nonsense, which is worse than
asking.

Everything lands in one pass — targets, services, findings, credentials and
C2 callbacks — and every change is written to the target's timeline.

### Only hosts you already have

**Imports are strict by default**: data is written only for hosts the
project already has. Anything else is reported back with *nothing
imported*, and you decide — in one modal, for all of them at once.

This exists because of a specific accident. A Burp HTTP history exported
from one engagement was imported into another, and it silently created
fourteen targets belonging to a different client. Nothing was wrong with
the file or the parser; the import simply assumed an unfamiliar hostname
was a new asset, which is right about half the time.

Each unknown host is listed with **what it would bring** — "431 URLs, 17
services" — because *"add this host?"* is unanswerable and *"add this
host, which brings 431 URLs?"* is not. Three choices per host:

| | |
|---|---|
| **Skip** | discard its data — **the default** |
| **Add as a new target** | create it |
| **Attach to an existing target** | correlate it, e.g. an IP onto its hostname |

A host left alone is **rejected, not created**. That asymmetry is the
whole point: the failure that actually happens is importing into the
wrong project, and its cost is another client's data in your engagement.
The cost of over-caution is one more click. Mapping onto a target that
does not exist is refused rather than creating it by another route.

The guard sits in the shared ingest path, so it covers **all fourteen
formats** — nmap, Nessus, Metasploit, C2 session lists and the rest — not
just the one that caused the problem. `mode: "open"` restores the old
behaviour for a deliberate bulk load, and the result always reports what
was skipped and what was mapped where.

### The rules that apply to all of them

**UNKNOWN, never blank.** A port that answered but could not be identified
is named `UNKNOWN`. Blank reads as *nobody looked*; these are different
claims and they get confused in exactly the situation where the difference
matters. `services_unknown` counts them separately.

**Upsert, never fork.** Target by host, service by `(target, port,
protocol)`, finding by `external_id` else `(host, title, port)`, callback by
`(target, framework, id)`. Re-running a scan updates; a wider scan adds.

**A tool that did not look at a field never erases it.** masscan reporting
an open port says nothing about its banner, so it does not null one Nessus
found. `UNKNOWN` likewise never overwrites a real service name.

**Compromise is one-way.** A C2 callback sets the pwned flag; nothing in
the import path clears it. Losing a beacon is not evidence the access is
gone.

**Nothing is discarded to fit the schema.** Fields without a column are
kept whole as JSON on `target.extra`, `service.scripts` and
`implant.extra` — including fields these parsers have never heard of, which
are more likely a newer version of the tool than something worthless.

### Per-tool notes worth knowing

- **nmap** keeps competing OS matches, not just the winner: a 96/92 split
  between two operating systems is a different result from a single 96. It
  also keeps uptime, distance, traceroute, TCP/IP-ID sequence analysis, and
  NSE output from both `<hostscript>` and per-port `<script>` — including
  scripts that emit only structured `<table>`/`<elem>` children and set no
  `@output`, which a naive reader drops entirely.
- **Metasploit** is imported for what nmap cannot give you: **credentials**
  and **what was actually exploited**. A `<session>` marks the host pwned.
  msf has no severity column, so a vuln carrying refs is filed `medium` and
  one without is `info` — the refs are shown so you can re-rate.
- **Nessus** takes the host's identity from the `host-fqdn` tag, not the
  `name` attribute, so a box scanned by address still merges with the
  DNS-named target another tool found. Service-detection plugins become
  **services, not findings** — importing them as findings is how a report
  ends up with 400 informational rows saying "a web server is running on
  443". Where a CVSS v3 score is present it is used, but never to downgrade
  what Nessus itself flagged.
- **Burp** imports the issue, the path and the confidence. The base64
  request/response pairs are **deliberately not imported**: they are the
  bulk of the file, they routinely contain session cookies, and a findings
  database is not where captured traffic belongs. It stays in the Burp
  project, which already has it.
- **Burp proxy history** is a separate format with the same rule.
  **A `.burp` project file cannot be read directly** — it is an
  undocumented proprietary container (no magic bytes, not zip, not
  SQLite), and Burp's REST API on :1337 exposes scan launching and issue
  definitions but *not* proxy history. The supported route is the export:
  *Proxy → HTTP history → select all → right-click → Save items*. From
  that, each item becomes a web address carrying its status, length, MIME
  type, method and analyst comment, plus the page title and `Server`
  header decoded out of the response head — and nothing else. Only the
  first 16 KB of each response is decoded, because a 200k-item history
  does not need its bodies read to be an inventory.
- **Nikto** has no severity field at all, so everything would be `info`
  taken literally. Findings are banded from the check text — an exposed
  `.env` is not a missing `X-Frame-Options` header — and **every imported
  description says the severity was assigned by Oddjob**, so nobody
  mistakes it for the tool's own rating.
- **nuclei**'s severity *is* trusted: unlike most scanners it is set per
  template by someone who looked at the check.

### C2 callbacks

nmap has `-oX`: one documented format, stable for twenty years. The C2
frameworks have no equivalent — each exposes its session list through an
API or console command that can emit JSON, and what your tooling dumps is
up to you. So the **field names** below are taken from each framework's own
data model, but the **file** is whatever you produce:

| framework | fields read from |
|---|---|
| Cobalt Strike | beacon metadata as an Aggressor script sees it — `id`, `computer`, `user`, `internal`, `external`, `listener`, `is64`, `ver`, `last`, `note` |
| Mythic | the `callback` object — `agent_callback_id`, `host`, `user`, `integrity_level`, `payload_type`, `init_callback`, `last_checkin` |
| Merlin | the agent record — `id`, `hostname`, `username`, `platform`, `ips`, `integrity`, `statuscheckin` |
| Sliver | `sessions`/`beacons --json` — `ID`, `Hostname`, `Username`, `UID`, `Transport`, `RemoteAddress`, `IsDead` |
| Havoc | the demon table — `NameID`, `Hostname`, `Username`, `DomainName`, `InternalIP`, `Elevated`, `FirstCallIn` |

Each parser accepts a JSON array, JSONL, or an object wrapping the list
under any usual key; matches names case- and underscore-insensitively; and
keeps anything it does not recognise in `extra`.

They are normalised onto one `implants` row because the fields an
engagement record needs — which box, as whom, at what integrity, last seen
when — are the same for all of them, and that is what makes a
mixed-framework operation reportable at all. Integrity in particular:
Cobalt Strike's trailing `*` on a username, Mythic's `integrity_level: 4`
and Havoc's `Elevated: true` are the same claim written three ways, and
they all become `high`/`system`.

Two details that are easy to get wrong and are handled:

- Cobalt Strike's `last` is **milliseconds since the last check-in, not a
  timestamp**. Treating it as one dates every beacon to 1970; it is kept as
  `last_checkin_ms_ago`.
- Merlin reports loopback in its `ips` list. `127.0.0.1` is never how you
  reach the host, so it is not taken as the internal address — but the full
  list is still kept.

## Web addresses

Nested under Services, and **shown only once an http(s) port exists** —
an empty view you have to click to discover is empty is worse than no
entry at all. It sits there rather than beside Services because a URL is
one protocol's view of a port, and SMB shares or database instances will
want the same treatment.

Its own view because a web server is not one thing: a
single :443 routinely carries a login page, an admin console, an API and a
forgotten status endpoint. "What is reachable" is the question an operator
has, and a banner cannot answer it.

Populated by every web tool that reports a URL — httpx, nuclei's
`matched-at`, Burp's issue paths, Nikto's findings — and addable by hand.

A row is keyed on **(target, method, URL)**. The verb is part of the
identity because `GET /login` and `POST /login` are different things and
a tester needs both — keying on the URL alone silently kept whichever the
importer saw last. The method is never NULL (unknown is `""`), because SQL
treats NULLs as distinct from one another and a nullable column would
defeat the deduplication it is part of. A row recorded without a verb by
httpx later *learns* it from a proxy history rather than forking into two.

Re-importing the same file therefore creates nothing the second time.

URLs are **canonicalised** so the same page is one row however it was
found: `https://shop.corp.local`, `https://shop.corp.local:443/` and
`https://SHOP.corp.local/` all collapse to one. Case and the default port
are not meaningful; a trailing slash on a non-root path and a query string
*are*, so they are kept — `/admin` and `/admin/` can be different handlers,
and dropping `?id=2` would collapse every parameterised page into one row.

### The packet view

Clicking a URL offers **View packet**, **Open in browser** or **Copy URL**
rather than assuming one — sometimes you want the live page, sometimes
what was actually exchanged. The packet modal shows the request and the
response side by side, headers separated from body, with the verb and
status in the title bar.

**This reverses an earlier decision.** The Burp importer originally kept
only metadata, on the reasoning that bodies are bulk and full of session
cookies. The reasoning was right and the conclusion was wrong: reading
the exchange is most of why a proxy history is worth importing, and
sending someone back to Burp to see it defeats the point.

So both sides are stored, capped at 16 KB of request and 48 KB of
response, with `truncated` set when either was cut — a viewer that
presents a trimmed body as the whole exchange is worse than one that says
it trimmed. The bodies are fetched **one at a time** from
`/api/web/{id}/packet` and are never part of the listing, where five
thousand rows of them would be hundreds of megabytes nobody is reading.
The modal says plainly that a captured exchange is credential material.

Each row records **which tools found it**, so a URL both httpx and Burp saw
is visibly better evidence than one only a wordlist guessed at. The
`Fetched` column is the distinction that matters: something actually
retrieved this address, as opposed to merely referencing it. A link
harvested from a page is not a visited page.

## Detect New Domains

A button above the Targets table. Give it a domain and it suggests
hostnames worth trying, each with the reason it was suggested.

**It sends no packets and performs no lookups.** Candidates are
extrapolated from what the project already holds — targets, their alternate
names, TLS certificate names captured by NSE, the hosts of web addresses.
That boundary is deliberate: generating a name is free and reversible,
resolving one is neither, and keeping them apart means this can be run on
any project at any time without anyone thinking about scope.

| source | what it does | score |
|---|---|---|
| `sequence` | `web01` exists → `web02`, `web03` | 80–85 |
| `environment` | `api-uat` exists → `api-qa`, `api-prod`, `api-staging` | 75 |
| `label` | a first label used under other domains in this project, applied here — ranked by how many | 45–80 |
| `sibling` | a name already known under the parent domain | 20 |
| seeds | a short list of common names, only when the estate has shown us little | 15 |

The estate's own vocabulary beats the seed list, which is why the seeds
score lowest and only appear when there is room: an organisation that uses
`sso` under four domains is better evidence for `sso` under a fifth than
any generic wordlist.

**It remembers.** Every domain searched is recorded with when, how many
candidates it produced, and how many hosts were known at the time. Asking
again returns what it found before and says so rather than grinding through
it again; `force` re-runs, and even then a name proposed before is not
proposed twice — it has its `times_seen` bumped instead, because three
patterns agreeing is itself a signal. Rejected names never come back.

Promotion to a target is a separate, deliberate act: a guessed name is a
hypothesis and an inventory row is a claim. Promoted targets are created
with `alive` unset — **not** `false` — because nothing here checked.

## Reports

Under Credentials in the sidebar. Three kinds, generated from the data:

| | sections |
|---|---|
| **Full Report** | Executive Summary · Scope · Findings · Appendix A: Targets Found |
| **Executive** | Executive Summary · Top Findings (max 10) |
| **Findings** | Findings · Appendix A: Targets Found |

Each finding carries severity, host, title, description and recommended
remediation. Where no remediation was recorded the report says so — that
is information the client needs, not a blank to hide.

A requested report appears in the table immediately as **In Progress**,
becomes **Ready to Download** when built, and the PDF/DOCX buttons are
greyed out until then. If the requester has an email address and SMTP is
configured, they are emailed. If not, the row says which of the two was
missing: *"I never got a mail"* is otherwise unanswerable.

### PDF and DOCX from one document

Both render from the same structured document rather than one being
converted from the other, so they cannot drift. Rendering happens at
download, so the PDF and the DOCX a client receives are the same report.
Neither renderer needs a system library — a report generator that only
works on the maintainer's laptop is not a feature — and the DOCX is a real
document with styled headings and native tables, because a client who asks
for DOCX is going to edit it.

### The executive summary is computed, not written

It is assembled from the counts, with the qualifications attached: *"47
did not respond"* is only meaningful next to *"and 112 were never
probed"*. It has to be correct and it has to exist whether or not an agent
is configured.

### Severity threshold

Default is **low and above**. On a real estate the informational entries
are coverage records — one per host per task — and including them took the
one real full report to **9,223 pages and 20 MB**. The threshold is
selectable up to "everything", and whatever is excluded is **stated in the
report** with where it still lives. Data is never silently dropped from a
deliverable.

### Use Agentic Support

Optional checkbox. The agent revises the narrative and tightens finding
wording before the report is marked ready.

What it may touch is **prose, and nothing else** — and that is structural,
not a request. It is handed only the text of the fields it may rewrite,
each tagged with an id, and only replacement text for those same fields is
read back. There is no path by which it can emit a finding, a host or a
severity.

On top of that, **every edit must preserve the numbers in the passage it
replaces**. A model smoothing *"47 hosts"* into *"several dozen hosts"*,
or quietly changing a count, is rejected and the original kept. The report
states on its first page that prose was machine-revised, and the Reports
table marks it. A failed pass never costs you the report: it completes
without the edit and says why it was skipped.

The scanner text the agent edits came from the assessed systems, so the
prompt tells it that content is untrusted input to be edited, never
instructions to follow.

## Timeline

Every target has one: **what was found, what was done, and every note**, in
order. `GET /api/targets/{project}/{host}/timeline`, filterable by kind.

| kind | written by |
|---|---|
| `discovered` | first appearance, and what found it |
| `note` | a person — first line is the summary, the full text is the detail |
| `scan` | a tool: OS fingerprints, NSE output |
| `service` | ports appearing or changing, with the before → after |
| `change` | edits to the target's own fields |
| `status` | `alive` / `hacked` flipping — the two that change how it reads |
| `vuln` `poc` `credential` | findings and proofs attached |

Only `note` and `scan` can be posted by hand. The rest are recorded by the
code that performed the change, so a gap in the list means a mutation path
that does not record itself — not a rendering bug. Entries are append-only:
a correction is another entry, never a rewrite.

Recording never fails the operation it describes. Losing the narrative is
bad; failing somebody's import because the narrative could not be written
is worse.

## URLs

The URL is the app's state, not a side effect of it.

```
/                                                  -> /projects
/projects                                          the project list
/projects/ACME                                     that project's targets
/projects/ACME/vulns                               its findings
/projects/ACME/targets/web01.corp.com              opens that host
/projects/ACME/targets/web01.corp.com/services/tcp/443
/config  /users  /profile                          global views
```

`/` lands on the **project list**, not targets-across-everything: with no
project chosen, "which engagement" is the question, and a grid of 4,600
hosts from nine clients is not an answer to it. The address bar is
rewritten to `/projects` on arrival rather than leaving a path that does
not describe the page — `replace`, not `push`, so Back does not bounce
between the two. A project of its own still opens on its targets.

**The same URL serves both readers.** A browser gets the app, which
routes on that path; a program gets a 307 to `/api/…` of the same path
and the JSON underneath. `curl -L` on a link someone pasted into chat
returns the resource.

Two bugs went away with this. Switching theme used to send you back to
Targets — the palette swap remounts the tree (see *Theme*), which reset a
view held in `useState`; reading it from the location means the remount
re-derives where you were. And a page became something you can paste to a
colleague.

Hand-rolled in `lib/route.ts` rather than react-router: the route table
above is the whole shape, the History API is three calls, and `parse`
sits next to `build` so the two cannot drift. A typo in a hand-edited URL
falls back to a usable view rather than erroring.

## The resource tree

```
GET /api                                           the index — start here
    /api/projects/{project}/targets
    /api/projects/{project}/targets/{target}
    /api/projects/{project}/targets/{target}/services
    /api/projects/{project}/targets/{target}/services/{protocol}/{port}
    /api/projects/{project}/targets/{target}/web
    /api/projects/{project}/targets/{target}/vulns
    /api/projects/{project}/targets/{target}/timeline
    /api/projects/{project}/targets/{target}/implants
```

Every response carries `_links` with absolute URLs, so the graph walks
from `/api` with nothing but a browser — that is the difference between
an API that is nested and one that is browsable. A reader who lands on a
service can get back to its host without knowing how the URL is built.

`{target}` takes the hostname **or** the numeric id. A path is something
people type, and refusing `…/targets/web01.corp.com` because the
canonical form is `…/targets/4821` is pedantry.

The flat collections (`/api/targets?project=…`) stay as they are and are
what the grids use — they filter, sort and page across a whole estate,
which a nested path cannot express. The tree is for the other half:
addressing one thing and finding what hangs off it.

## Layout

A left rail carries navigation — `Projects · Targets · Services · Vulns ·
Credentials`, with your profile at the bottom. The header is about the
**project**: which one is selected, its name, and its counts. The two do not
compete for the same strip.

The rail **collapses to icons** via the chevron, and the choice persists.
Collapsing is disabled on small screens, where the rail is already an overlay
drawer and a narrower overlay would gain nothing.

**Neon Dreams** (the sparkle button in the header) is the Synthwave '84 bloom,
opt-in exactly as it is in the editor theme. It works off `currentColor`, so
each element blooms in its own colour rather than having a blur laid over the
top. Chrome and headings get the full multi-layer bloom; cell text gets a
single tight halo, because several thousand rows of glowing data stops being
readable almost immediately.

Both preferences live in `localStorage`, not a cookie — a cookie is attached
to every request and the server has no use for which way a sidebar points.
Every access is wrapped, so blocked storage or a private window degrades to
the default instead of breaking the page.

All grids sort, filter and full-search client-side.

## Running on the customer's Postgres

Site Config holds a connection string under **Database**, tests it live,
and masks the password. `uv run python pgcopy.py` moves the data across.

**Site Config cannot switch the database over, and that is structural, not
an omission.** The settings table lives *inside* the database, so a
connection string stored there cannot be read until after the connection
it describes is already open. The switch is therefore a startup decision:

```bash
uv run python pgcopy.py --from-settings      # or --to 'postgresql://…'
export ODDJOB_DATABASE_URL='postgresql://user:pw@host:5432/db'
# restart
```

### Masking

The DSN is **not** write-only, unlike the SMTP password. Hiding it entirely
would mean the config screen could never show *which database you are
pointed at*, which is the thing you check before trusting it. So only the
password is replaced, and the host, user and database stay visible.

Masking is done on the **parsed URL**, never by regex over the raw string.
A password containing `@`, `:` or `/` — common, because generators do not
know about URL syntax — defeats every regex approach, and a mask that
leaks the tail of a password on some inputs is worse than no mask, because
it is trusted. The form round-trips the masked value, and a save that
still contains the mask is treated as "unchanged" rather than storing
`••••••••` as the password.

Both the URL form and libpq's keyword form (`host=… dbname=…`, what `psql`
prints) are accepted.

### The test

A real connection, read-only: `SELECT version()`, a count of tables in the
current schema, and whether the user holds CREATE. It reports the server
version and whether the schema is already populated — pointing at an empty
database and at one that already has Oddjob in it are very different
situations. A config test must never write to somebody else's database.

Saving is gated on a pass, like SMTP and Google.

### The copy

`pgcopy.py` creates the schema from `Base.metadata` and copies rows as
mapped objects in dependency order, so nothing hardcodes a column name.
Primary keys are preserved — the data is full of integer references and
renumbering would mean rewriting all of them — which is why Postgres
sequences are re-synced at the end. Skipping that is the classic import
bug: the copy succeeds and the first insert afterwards fails on a
duplicate key. Association tables with no mapped class (`user_groups`) are
copied through Core from the same metadata; missing them produces a
database with no site admins.

It refuses a non-empty destination unless told otherwise, because merging
on preserved primary keys gives a silent half-copy.

## Theme

**Profile → Appearance.** Fourteen schemes: Synthwave '84, Dracula, Tokyo
Night, Nord, Gruvbox Dark, One Dark, Catppuccin Mocha; Solarized Light,
GitHub Light, One Light, Gruvbox Light, Catppuccin Latte; and Windows XP
and Windows 95, which also bring square corners and their own typeface —
Windows 95 set in Orbitron is just Synthwave with grey boxes.

Stored per browser, not on the account: the same person wants dark on a
laptop at night and light on a projector, and a round trip to learn which
colours to paint means a flash of the wrong theme on every load.

Every palette fills the same thirteen slots, which are read as **semantic
roles** rather than literal colours — `neon.pink` is "primary accent", so
in Windows 95 it is navy. Renaming them across 23 components would be
churn for no behavioural gain.

Switching themes **remounts the tree**. `alpha(neon.pink, 0.2)` is
evaluated during render in those 23 components and `alpha()` cannot take a
CSS variable, so new colours only reach the screen when those functions
run again.

The grid horizon and scanlines are drawn only under Synthwave '84; over
Solarized Light they read as a rendering fault. **Neon Dreams** moved here
from the header and is disabled on schemes where a halo would reduce
contrast rather than add emphasis — the control says so instead of going
quiet.

## Version, not banner

The Services column shows **Version** — what software is listening,
`nginx 1.25`, `Laravel 5.4`, `Check Point SVN foundation`. The underlying
field is still called `banner`, because that is what nmap and Faraday both
call it.

A service also has **notes**: what a *person* recorded about it. The two
are deliberately separate, and keeping them apart was a fix rather than a
design. The Faraday importer originally mapped Faraday's service
`description` to the banner — but that field holds operator commentary,
so the column whose job is "what software is listening" was full of
`coverage gap` and `Created by DEADEYE for T138 residue`. Faraday's real
product string is in its `version` field, which is what the banner now
comes from.

Repairing the existing data moved **1,767** notes out of the banner column
into `notes`, keeping both. Nothing was discarded: an operator's note about
why a port is recorded is worth as much as the banner, just not in the same
column.

## Alive is inferred from services

A host with an open service is alive, whatever its liveness flag says.
Scanners routinely report ports without ever setting one — the Faraday
import left 1,185 hosts marked *never probed* while carrying 1,509 of
their services, and the executive summary dutifully reported zero
coverage.

Only `open` counts. `filtered` and `open|filtered` are the *absence* of a
reply and prove nothing, and `closed` is ambiguous in imported data where
it is often an operator's note about a port learned from a config rather
than a probe result. The inference only ever goes upwards: a later import
that mentions no open ports never marks a host down, because that is not
evidence either.

Backfilling this against the existing data marked **3,727 hosts** alive
that had been sitting as unprobed.

## Migrations

Alembic, applied at startup.

```bash
uv run alembic revision --autogenerate -m "what changed"   # after a model edit
uv run alembic upgrade head        # apply (startup does this too)
uv run alembic downgrade -1        # undo the last one
uv run alembic current / history   # where am I
```

Three behaviours worth knowing:

**A database that predates Alembic is adopted, not rebuilt.** On startup,
a schema with no `alembic_version` table but with the app's tables already
present is stamped at the baseline. Running the baseline migration against
it would fail on `CREATE TABLE`, and the obvious alternative — dropping and
recreating — is not available on a customer's Postgres.

**The drift check stayed.** Alembic cannot know about a model edited
without a migration generated for it, so startup still compares
`Base.metadata` against the live schema and refuses with the missing column
names and the two commands that fix it. Belt and braces, because the
failure it prevents is a 500 on every request that touches the new field.

**`render_as_batch` on SQLite.** SQLite cannot ALTER a column — no type
change, no added constraint, and no `DROP COLUMN` before 3.35. Batch mode
makes Alembic rebuild the table instead: create, copy, swap. Without it,
anything beyond a plain ADD COLUMN works on Postgres and fails on SQLite,
which is the worst possible place for the two to diverge. Both engines were
round-tripped — baseline, add a column, downgrade — before this was
written.

`alembic.ini` deliberately carries **no** `sqlalchemy.url`: `env.py` takes
it from `app.db`, so the migration runner and the application can never be
pointed at different databases. `ODDJOB_AUTO_MIGRATE=0` turns off the
startup upgrade and makes a pending migration a refusal to start instead.

`migrate.py` is superseded and now just forwards to Alembic.

### Migrations are tested against the models

`migrationtest.py` builds a database from nothing but the migrations and
compares it to `Base.metadata` — every table, every column, and whether
NOT NULL matches. It runs first in the suite and needs no server.

It exists because of a real failure. `alembic revision --autogenerate`
diffs against *whatever database it is pointed at*, so a column that had
been added out-of-band was invisible to it and never made it into the
migration. The result passed on the machine it was authored on and
produced a schema missing a column everywhere else — exactly the failure
Alembic was adopted to prevent. Regenerating against a database built
purely from migrations fixed it; this test makes sure the next one is
caught.

A related trap worth naming: `default=0` on a model column is applied in
Python, so the generated DDL is `ADD COLUMN … NOT NULL` with no default,
which neither SQLite nor Postgres accepts against a populated table. A
non-null column added to an existing model needs `server_default`.

## Tables remember how you left them

Sort, filters, the search box, which columns are showing, page size and
density, per table and per browser. Someone lives in these grids for days;
re-sorting Vulns by severity after every reload is the kind of friction
that makes a tool feel hostile.

Two things this has to get right, both about not stranding the user:

**A remembered filter announces itself.** The toolbar shows a chip —
`filtered · 37 shown` — with a one-click reset, and the tooltip spells out
what is active. Without it, someone returns to a grid they filtered last
week, sees four rows, and concludes the import broke. A remembered *sort*
is shown more quietly (`view saved`), because reordering rows hides
nothing.

**Stale state is pruned against the columns that exist now.** A filter
referring to a column a later release removed matches nothing, which looks
exactly like an empty table. Anything naming an unknown field is dropped on
load.

Column visibility is merged rather than replaced: a view hiding Project
when a single project is selected is a *default*, and only columns the
user actually toggled are stored — otherwise that default would be frozen
in as though it were a decision.

## Security headers

Computed from `site.base_url` at startup, recomputed when Site Config is
saved, and applied to **every** response — a gate refusal, a redirect and
a 404 need the same protection as a 200.

| | |
|---|---|
| `Content-Security-Policy` | `default-src 'self'`, no inline script, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'` |
| `Strict-Transport-Security` | **https only** — see below |
| `X-Frame-Options` | `DENY`, for browsers predating frame-ancestors |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` — an engagement URL must not leak this host to the target |
| `Permissions-Policy` | every feature denied; the app needs none |
| `Cross-Origin-Opener/Resource-Policy` | `same-origin` |
| `Cache-Control` | `no-store` on `/api/` |

**HSTS is sent only when the base URL is https**, and the cookie `Secure`
flag follows the same signal. Both directions are failure modes: HSTS
from a plain-http dev server teaches the browser to refuse the thing you
are developing, and a session cookie without `Secure` travels in clear
over any downgrade. One setting decides, which is most of why the
setting exists.

The policy has **one real concession**: `style-src 'unsafe-inline'`,
because MUI injects styles at runtime through Emotion and there is no
nonce to hand it. That is not free — with inline styles permitted a
CSS-injection bug stays exploitable — and it is the price of the UI
framework rather than an oversight.

Middleware order is load-bearing and was wrong once. `add_middleware`
prepends, so the last added is outermost: headers outside CORS outside
the gate. With the headers innermost, every response the gate
short-circuited went out bare.

## Dropdown ordering

Option lists are sorted alphabetically (numeric-aware, so `web2` precedes
`web10`) — formats, projects, usernames, domains.

Ranked lists are **not**, and that is deliberate. Severity sorted by name
gives `critical, high, info, low, medium`, which puts `info` third and
reads as an ordering that is simply wrong. The same applies to the role
hierarchy, to `starttls, tls, none` (most secure first) and to the Slack
delivery modes (escalating reach). `frontend/src/lib/sortOptions.ts` holds
the ranked set; everything else sorts.

## Editing

Every grid has **Add**, and multi-select with **Edit** and **Delete**.

Bulk edit gives each field a "change this" tick box. Without one there is no
way to distinguish *leave as-is* from *set to empty*, and a bulk edit that
silently blanks fields nobody thought about is unrecoverable. Join keys
(`host`, `port`) are creation-only — bulk-rewriting them would re-point child
rows at a different asset.

A selection may legitimately span projects you hold different roles on, so
bulk ops apply **the permitted subset** and report the rest rather than
failing wholesale.

## Credentials

Per engagement. **Secrets are withheld from `readonly` callers** — the row is
still listed with `secret_set` so the count is honest, but the value is not
sent. Secrets are masked in the grid until individually revealed, and are
excluded from the quick filter so they cannot be found by typing fragments.

They are stored **in plaintext**. Encrypting properly needs a key that does
not live beside the database, and a half-built scheme reads as protection
without being any. Treat `oddjob.db` as secret material.

## Service actions

Services have an action column. The first is **grab banner**, and it is
deliberately a stub with two independent interlocks, both failing closed:

1. `ODDJOB_ALLOW_ACTIVE_PROBES` must be explicitly true (default off).
2. `is_in_scope()` in `app/actions.py` must pass — it currently refuses
   everything, because this app has no scope document.

Both must be satisfied before a packet is sent. Whoever wires nmap in must
wire `is_in_scope()` to the real gate first; in an engagement repo that is
`scripts/intake/gate.py: assert_testable(host)`. Until then the job reports
`unavailable`, which is kept distinct from `failed`: no probe backend is a
fact about this deployment, not about the host.

Actions are jobs, not synchronous calls, because nmap takes seconds to
minutes. They are also the audit trail of who asked for an active probe
against which asset.

**Click a host** anywhere — Targets, Services or Vulns — for a full-screen
overview: hostname, OS, IP, alive/hacked, open ports with banners,
vulnerabilities worst-first, PoCs and notes. One `GET
/api/targets/{project}/{host}/detail` call, so the modal does not render in
four staggered pieces.

**Click a port or a service name** in Services for a two-way drill-down:

- *Show all hosts with port 443* — the flat list, for pivoting to a host.
- *Explore this port* — the aggregate, for deciding whether it is worth
  pivoting to: host and state counts, what is actually listening on it,
  products, banners, findings by severity, and every host ranked worst-first.

Severity is ranked, never sorted alphabetically — `critical, high, info,
low, medium` is the alphabetical order and it is actively misleading.

## Site Config  (site admins)

Below Credentials, after a divider. Rendered entirely from a spec the server
serves (`backend/app/settings_spec.py`) — adding a setting is one entry there:
no form field, no endpoint, no migration.

| group | covers |
|---|---|
| Site | name, base URL (emailed links are unusable if this is wrong) |
| Identity | Google SSO on/off, **client ID and secret**, redirect URI, allowed email domains, self-registration |
| Email (SMTP) | host, port, security, credentials, from address |
| Slack | bot token, channel prefix, **new channels private by default**, create-a-channel-per-project |

### Test before save

SMTP and Google credentials **cannot be saved until a Test has passed
against the exact values in the form**. Untested credentials fail at the
moment they are first needed, which is always the worst moment — a
password-reset link that silently never sends, or a sign-in button that
400s for everybody.

- The Test runs against the **draft**, not the stored config, so you find
  out before you overwrite something that worked.
- A pass issues a short-lived token carrying a **digest of the values
  tested**. The save recomputes that digest and refuses if it differs —
  testing with a working password and then saving a different one does not
  get through.
- The gate only fires on **change**. Editing the allowed-domains list, or
  anything ungated, saves freely.
- **Blanking the primary field** (SMTP host, Google client ID) is how you
  turn an integration off, and never needs a test — otherwise a bad
  password would be impossible to remove.
- Turning Google SSO **on** is itself gated; deleting a credential also
  switches it off, so the gate cannot be walked around via DELETE.
- Slack is deliberately **not** gated: a missing token disables channel
  creation, it does not lock anyone out.

The SMTP test sends a real message. Google's is a credential probe — an
intentionally invalid code is redeemed at Google's token endpoint, which
answers `invalid_client` for bad credentials and `invalid_grant` when the
client was accepted and only the throwaway code was not.

**Secrets are write-only.** The API never returns the SMTP password or Slack
token, only whether one is stored. An empty box means *leave it alone*, not
*clear it* — otherwise saving an unrelated checkbox would wipe the token.
Clearing is an explicit DELETE.

The domain restriction applies to **registration only**. An existing account
whose domain is later removed keeps working; locking people out of accounts
they already have is a different decision from deciding who may make one.
Leaving it empty means any Google account can register — they still join no
groups and see nothing, but they do get an account.

The connection tests actually connect. A config screen that only validates
the shape of the fields tells you nothing about whether mail will arrive.

## Slack routing

A project may supply its own bot token to reach the customer's workspace.
With one set, it chooses where findings go:

| delivery | |
|---|---|
| `site` | the site workspace only (the default; an override token can be stored but unused) |
| `override` | the customer's workspace only |
| `both` | both — visible to the customer *and* kept on the internal record |

Selecting `override` or `both` without a token is refused rather than
silently posting nowhere, and clearing the token resets delivery to `site`.

Channel names are normalised to Slack's own rules — lowercased, anything
outside `a-z0-9-_` collapsed to `-`, trimmed to 80 characters — so
`#Acme Falcon!!` becomes `acme-falcon`. Left empty, the name is the site's
**channel prefix** plus the codename: `eng-` + `FALCON-1` → `eng-falcon-1`.

Visibility is tri-state. A project that chooses private or public keeps that
choice; one that chooses neither **inherits the site default**, so changing
the site policy moves every project that never decided. The default default
is private, because engagement channels carry findings and credentials.

## The agent

A chat panel docked to the right, scoped to the open engagement. Toggle it
from the header.

Credentials resolve **project first, site second**, so one engagement can
run on the customer's own account without moving every other project with
it. Set them in Site Config under *Agent*, override them per project in the
project's settings.

### Anthropic tokens: two kinds, two headers

This is the detail that wastes an afternoon if you get it wrong.

| token | header |
|---|---|
| `sk-ant-api…` — an API key | `x-api-key: <token>` |
| `sk-ant-oat…` — an OAuth token, e.g. from `claude setup-token` | `Authorization: Bearer <token>` plus `anthropic-beta: oauth-2025-04-20` |

They are **not interchangeable**, and sending one as the other fails with an
authentication error that reads exactly like a wrong key. Oddjob detects
the kind from the prefix, uses the right header, and shows which kind it
found beside the token — so a 401 tells you something real instead of
sending you to regenerate a key that was fine.

OpenAI is a plain bearer key.

### Local models

Set the provider to **local** and give it a base URL. Anything speaking the
OpenAI chat-completions API works — Ollama (`:11434/v1`), LM Studio
(`:1234/v1`), llama.cpp's server, vLLM, LocalAI — which is why this is a
base URL rather than a second provider implementation. Most need no key;
the field is there for a proxy that wants one.

The engagement data never leaves your network, which for a pentest
database is the main reason to want this at all.

Two things that bite:

- **The Oddjob server makes the request, not your browser.** `localhost`
  means localhost *to the server*. A failure to connect says so explicitly
  rather than reporting a generic timeout.
- **Pick a model with tool-calling support.** Without it the agent can talk
  but can never look anything up. A model that returns no answer and calls
  no tools is reported as probably lacking tool support, rather than
  rendering an empty bubble.

The timeout is ten minutes for a local server, against two for a hosted
one: a cold model has to load before it emits a first token.

### Writing remediation automatically

When an agent is configured, findings that arrive without remediation get
one written for them. **Strictly one at a time**, in a single background
worker, with a pause between each.

That is the whole design constraint. Scanners deliver in bulk — a Faraday
import landed 6,801 findings at once — and firing those at a model
concurrently saturates a shared inference server, burns a rate-limited
quota in minutes, and produces a queue nobody can see.

**Worst severity first, always.** The next finding is chosen fresh each
iteration rather than from a frozen queue, so a critical that arrives
mid-run is picked up before any waiting low. Severity is the first sort
key unconditionally: a critical that has already failed twice still goes
before an untried high. If the worker only gets through two hundred
findings before someone turns it off, those two hundred are the right two
hundred.

What it may write is the `remediation` field of a finding that has none,
tagged `remediation_source='agent'`. It never overwrites a scanner's
advice, never touches a severity, title or host, and creates nothing. A
report can therefore distinguish vendor advice from model advice, which
a client is entitled to.

Bounded failure: attempts are counted per finding and capped at three,
with the error kept, so one finding that always errors cannot occupy the
queue. Repeated provider failures back off rather than retrying tightly.

**Informational findings are excluded by default.** On a real estate they
are coverage records, and "remediation" for *"swept this /24"* is
nonsense — they were also 5,323 of the 6,403 outstanding. Site Config →
Agent shows the backlog by severity with a wall-clock estimate, because
the honest answer to "should I leave this on" depends on it: 1,080
findings on a local model is about ten hours.

### Only one provider's settings are shown

Site Config → Agent shows the credentials for the selected provider and
hides the rest, driven by a `show_if` in the settings spec and evaluated
against the unsaved draft — so switching the selector swaps the fields
immediately rather than after a save.

### What it can do

The agent reads the engagement through tools — it knows nothing about the
project otherwise. Tool calls are shown in the transcript and can be
expanded: an agent that says "three criticals" is only worth anything if
you can see the query it ran.

Nine read tools (overview, targets, host detail, findings, services, web
addresses, credentials, timeline, domain suggestions) and, when
`agent.allow_writes` is on, three write tools (add note, add target, add
finding).

Three boundaries are structural rather than asked-for:

- **The project is fixed by the caller.** No tool can name a different one,
  so an injected instruction inside imported scan output cannot walk the
  agent into another customer's engagement.
- **Write tools are not offered unless enabled.** With writes off the model
  never sees them, which is far stronger than refusing at call time. Scan
  output, page titles and NSE results are attacker-influenced text, and an
  agent reading them is being fed untrusted input all day — the system
  prompt says so explicitly.
- **A readonly member cannot gain writes through the agent**, whatever the
  site setting says.

Credential *secrets* are never passed to the model: it can reason about
which accounts were captured without the plaintext leaving the database for
a third-party API. And `agent.max_steps` hard-stops the tool loop, because
a confused model can otherwise spend an afternoon and a lot of money going
in circles.

## Importing from Faraday

```bash
FARADAY_URL=… FARADAY_USER=… FARADAY_PASS=… \
ODDJOB_USER=… ODDJOB_PASS=… \
uv run python faraday_sync.py [--only NAME,NAME] [--dry-run]
```

One Oddjob project per Faraday workspace. Idempotent — the bulk importer
upserts on host and on the vuln's external id, so re-running reconciles.

Hosts are keyed on a **hostname** where Faraday has one, even though
Faraday itself keys on IP. Otherwise a box imported from a scan as
`api.corp.com` and the same box from Faraday as `10.0.0.5` would be two
targets forever.

**Archived workspaces** read 403 until un-archived, so the script
un-archives, reads, and re-archives each one immediately — the window stays
as short as the work. The original flag is captured first and restored in a
`finally`, on Ctrl-C, and on an unhandled exception; a failed restore is
reported loudly rather than exiting quietly having left somebody's archive
open. At the end it re-reads every workspace and compares the flags against
what it found, so "archive state unchanged" is verified, not assumed.

## Users

Visible to site admins and to anyone who administers at least one project.

- **Site admins** see every account: create, disable, delete, and toggle
  `site-admins` membership. Guarded against self-harm — you cannot delete or
  demote the account you are signed in as, and `site-admins` cannot be
  emptied.
- **Project admins** manage membership of their own projects only. They never
  receive the account directory; a separate `/api/users/selectable` returns
  id, username and name alone, which is what a picker needs and no more.

The UI hides what you cannot use; the server is what enforces it. Both were
tested from a project-admin token: granted on its own project, 403 on the
full directory.

## Magic-link sign-in

Available on the sign-in page once SMTP is configured, and used for
invitations: a site admin creates an account and hits **Invite**, the person
clicks the link, lands signed in, and sets a password from their profile.

A magic link is a bearer credential that skips the password entirely, so:

- **single use** — `used_at` is stamped in the same transaction that signs
  you in, so a link forwarded to a mailing list works exactly once
- **15 minutes**
- **hashed at rest** — only the hash is stored; the plaintext lives in the
  email, so a dump of the table does not let anyone sign in as anybody
- **constant answer** — requesting a link always returns 202 whether or not
  the account exists, including when delivery fails. An unauthenticated
  endpoint that answered differently would be a free "does this person have
  an account here" oracle. Failures are logged server-side, because
  otherwise an SMTP misconfiguration is invisible from both ends.
- **two separate throttles** — 60s cooldown and 3 per 15 min per *identifier*
  (don't mail one person repeatedly), a higher cap and no cooldown per
  *client* (don't let one source blast many addresses). A single shared limit
  gets this wrong invisibly: mistype your address, correct it, and the
  corrected request is silently dropped while the endpoint still says 202.

`/api/auth/invite/{username}` is admin-only and therefore reports honestly —
no email on file, SMTP not configured, SMTP refused — because there is no
account existence to protect from someone who can already list every account.

## Live updates

`GET /api/events` is an SSE stream that fires on every change. The UI
subscribes once and refetches; events carry no data, so a missed one is
self-healing. Behind nginx set `proxy_buffering off`, or events arrive late
and in bursts.

## MCP

```bash
claude mcp add oddjob --env ODDJOB_API_KEY=msk_… -- \
  uv --directory /Users/brandon/Desktop/oddjob/backend run python oddjob_mcp.py
```

Mint a key in the API (`POST /api/auth/keys?name=mcp`). The MCP server is a
thin client over the HTTP API, **not** a second path into the database, so it
gets exactly the same per-project ACL as the browser. Eleven tools:
`list_projects`, `create_project`, `list_targets`, `get_target`,
`set_target_flags`, `list_ports`, `list_services`, `list_vulns`,
`bulk_import`, `stats`, `whoami`.

## Tests

```bash
uv run python apitest.py       # CRUD, search, sort, cascade, SSE
uv run python authtest.py      # auth, per-project ACL, lockout guards
uv run python featuretest.py   # credentials, bulk edit/delete, profile
uv run python settingstest.py  # site config, secret masking, user management
uv run python magictest.py     # magic links, test-before-save — runs its own SMTP sink
uv run python projecttest.py   # project creation, scope, contacts, Slack routing
uv run python scantest.py      # nmap -sV -O -A ingestion and the timeline
uv run python importtest.py    # every other importer, incl. the C2 frameworks
uv run python webtest.py       # web addresses, domain discovery and its memory
uv run python reporttest.py    # the three report kinds, PDF/DOCX, the agentic guard
uv run python migrationtest.py # the migrations build exactly what the models say
```

Client-side logic — table-state pruning, dropdown ordering, the theme
definitions — has its own runner, no browser or DOM needed:

```bash
cd frontend && npm run test:logic     # 53 assertions
```

It covers the parts where being wrong is *silent*: a stale filter emptying
a grid, or severity alphabetised into `critical, high, info, low, medium`.

Or all of them, each against its own server, its own free port and its own
fresh database:

```bash
uv run python runtests.py            # 623 assertions
uv run python runtests.py scantest   # just one
```

A hard-coded port silently hands a suite to whatever else is listening —
a dev server, say — and the run then reports failures belonging to a
different database entirely. The runner picks free ports and passes them in
through `ODDJOB_TEST_BASE`.

## Known limits

- Grids fetch the full set and sort/filter/search client-side. Instant up
  to a few thousand rows; the API already supports server-side
  `q`/`sort`/`order`/`limit`/`offset` for when that stops holding.
- Grids fetch the full set and sort/filter/search client-side, which is
  instant up to a few thousand rows. The API already supports
  `q`/`sort`/`order`/`limit`/`offset` server-side for when that stops holding.
- The UI bundle is ~1 MB (310 KB gzipped), nearly all MUI. Code-split if it
  matters.
- Login cookies now take `Secure` from `site.base_url`. Turn
  that on before serving this over anything but loopback.
