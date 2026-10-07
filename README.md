# Oddjob

**Authorized penetration testing and red teaming only.** Nation-state
actors and criminal hacking groups, as defined under US law, are not
authorized to use this toolset. See [Authorized use](#authorized-use).

---

## What is this

Oddjob is where an engagement's data lives: projects, targets, services,
findings, credentials, captured web traffic and the reports that come out
of it. One place where "what do we know about this host" has one answer.

It owes its shape to [**lair-framework**](https://github.com/lair-framework/lair),
which got the important idea right years ago, that a team needs a shared
datastore for an engagement, not a folder of everyone's scan output. Lair
is where this starts from. What Oddjob adds is the rest: the parts of
every collaboration platform that were worth keeping, taken honestly and
put in one place: Faraday's importer breadth, Dradis's reporting,
Ghostwriter's engagement structure, the proxy-history handling you only
get from living in Burp... plus the things none of them do, like an agent
that can read and write the engagement, and Drones.

**You can use it two ways, and the second is optional:**

| | what you run | what you get |
|---|---|---|
| **As a reporter** | Oddjob alone | Import what your tools already produced. Triage, deduplicate, merge, write findings, generate the report. Nothing of yours ever touches the target. |
| **As an active engagement** | Oddjob **+ Drones** | The above, plus enumeration you drive from the UI. Drones run the scanners, on your infrastructure, and the results import themselves. |

If you only ever import files, you never need a Drone. The whole agent
side is additive and there is no degraded mode, no nagging, and no feature
that stops working because you did not deploy one.

### How the pieces fit

```
                      ┌───────────────────────────────┐
                      │            ODDJOB             │
                      │  ───────────────────────────  │
   you ──browser────► │  projects · targets · scope   │
                      │  findings · creds · web       │
                      │  reports · Slack · agent      │
                      │  the task queue               │
                      └───────────────┬───────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 │                    │                    │
            ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
            │ DRONE 1 │          │ DRONE 2 │          │ DRONE 3 │
            │ us-east │          │   eu    │          │  japan  │
            └────┬────┘          └────┬────┘          └────┬────┘
                 │                    │                    │
            nmap masscan         nmap masscan         nmap masscan
            amass nuclei         amass nuclei         amass nuclei
            gobuster httpx       gobuster httpx       gobuster httpx
                 │                    │                    │
                 ▼                    ▼                    ▼
            ── the client's estate, from the egress you chose ──
```

Oddjob holds the queue. Drones ask for work, run it, and send results
back, which import themselves into the project. A Drone **dials out**,
nothing listens on the internet, and nothing needs to be exposed to add
one.

Drones are **tied to a project**. A Drone enrolled on ACME takes tasking
from ACME, and everything it finds lands in ACME. It cannot be borrowed
by another engagement.

→ **[Drones have their own README](drone/README.md)** which includes what they are,
how to deploy one safely, and the rules about where they may be
installed.

---

## Authorized use

This is offensive tooling. It scans, enumerates, captures traffic and
stores credentials.

**Permitted:** authorized penetration testing, red team engagements,
security research on systems you own or have written permission to test,
and CTFs.

**Not permitted:** use by nation-state actors or criminal hacking groups,
and any activity that violates the Computer Fraud and Abuse Act or the
equivalent law in your jurisdiction. Running this against infrastructure
you have no written authorization to test is a crime in most countries,
and scope exists in this tool precisely because "I thought it was in
scope" is not a defence.

The project's scope lists are enforced, not advisory: a Drone will refuse
a target outside them, and the refusal is recorded.

---

## Setup

### Docker (Recommended way)

Everything, including PostgreSQL and the migrations, in one command.

```bash
git clone https://github.com/xsecurity-ai/oddjob && cd oddjob
cp .env.example .env            # set POSTGRES_PASSWORD
docker compose up -d            # app + database, migrations applied on boot
open http://127.0.0.1:8000
```

First run creates the admin account. Everything after that needs a
session.

That is the whole install. You get PostgreSQL rather than SQLite which
matters the moment a long import and a background worker want to write at
the same time and the UI already built, and the Drone binaries for every
platform built and ready to hand out.

### From a checkout, if you must

Useful for working *on* Oddjob; more moving parts than you want on an
engagement.

```bash
# API, which also serves the built UI
cd backend && uv run uvicorn app.main:app --reload

# UI in dev mode, hot reload, /api proxied to the backend
cd frontend && npm install && npm run dev
```

SQLite by default. See [Running on PostgreSQL](#running-on-postgresql)
to point it at a real database.

### Before you expose it

Both ports bind to loopback. There is no rate limiting and no
brute-force lockout so put this behind a reverse proxy (e.g., nginx) 
before changing that. It holds findings, credentials and captured
traffic including session cookies. Read [SECURITY.md](SECURITY.md).

---

## Drones

A Drone is the **forward-deployed enumeration** half: a single static
binary that runs on *your* attack infrastructure, takes tasking from
Oddjob, runs the scanners, and sends the results home to import
themselves.

```bash
# In Oddjob: Drones → Deploy a Drone. Copy the enrollment token, then:
docker run -d --name drone --restart unless-stopped \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e DRONE_SERVER=https://oddjob.internal \
  -e DRONE_ENROLL_TOKEN=drone_... \
  -v drone-state:/var/lib/drone/work drone-agent \
  run --name edge-01 --workdir /var/lib/drone/work
```

**Drones go on infrastructure you control and nowhere else.** Never on a
host you have compromised. The reasoning, the deployment modes, the
routing policies and region configuration are all in the
**[Drone README](drone/README.md)** read it before deploying one.

---

## Driving it from outside: the MCP server

Oddjob ships an MCP server, so a model in Claude Code, Claude Desktop or
anything else that speaks MCP can read and write the engagement
directly — "what do we know about web01", "file this finding", "import
this nmap XML" — without a human copying data between windows.

```bash
# Mint a key in the UI (Profile → API keys), or:
curl -X POST 'http://127.0.0.1:8000/api/auth/keys?name=mcp' \
     -H "Authorization: Bearer <jwt>"

# Register it with Claude Code
claude mcp add oddjob --env ODDJOB_API_KEY=ojk_... -- \
    uv --directory /path/to/oddjob/backend run python oddjob_mcp.py
```

**It is a thin client over the HTTP API, not a second way into the
database.** Every call carries the API key, so the server applies
exactly the same per-project ACL it applies to the browser. An MCP
server talking straight to SQLite would silently bypass the whole
authorisation model — which is the obvious way to build one, and wrong.

The key's ACL is the boundary. A key with `readonly` on one engagement
can read that engagement and nothing else, whatever the model is asked
to do.

| | |
|---|---|
| **Read** | `list_projects` `list_targets` `get_target` `list_ports` `list_services` `list_vulns` `target_timeline` `stats` `whoami` `import_formats` |
| **Exploits** | `search_exploits` `service_leads` `get_cve` `feed_status` |
| **Write** | `create_project` `set_target_flags` `add_target_note` `bulk_import` `import_report` `import_nmap` |

The exploit tools match against Oddjob's own copy of Exploit-DB and NVD,
so a lookup tells nobody what the client runs — see
[Exploits and CVEs](#exploits-and-cves-held-locally). `service_leads`
takes a product and version and has no host parameter, which is the
boundary rather than a convention. Read `version_match` on each result
before believing it, and `feed_status` before believing an empty one.

### Two agents, and they are not the same thing

| | runs | reaches | used for |
|---|---|---|---|
| **MCP server** | wherever your MCP client runs | Oddjob's HTTP API | driving the engagement from your editor |
| **In-platform agent** | inside Oddjob | its own database, and Drones | answering questions in the UI and over Slack |

The in-platform agent is configured in Site Config and is read-only
unless writes are explicitly enabled. See [The agent](#the-agent).

---

## What Oddjob does with the data

- **Import** nmap, masscan, Nessus, Metasploit, Burp (issues *and* proxy
  history), Nikto, Nuclei, httpx, and five C2 frameworks. Formats are
  detected from the file.
- **One row per captured exchange**, not per URL... the same endpoint
  probed ten ways is ten pieces of evidence, and the differences between
  the responses are usually the finding. The UI groups them back under
  the URL.
- **Replay** any captured request after editing it. The result is stored
  as a new exchange beside the original.
- **Report** to PDF or DOCX, optionally with an agent pass over the prose.
- **Notify** Slack: findings as one-liners with the detail in-thread, plus
  engagement, import, membership and report events.

---

## Targets come in three kinds

| kind | identified by | address | liveness |
|---|---|---|---|
| `host` | FQDN or IP | yes | meaningful |
| `mobile` | bundle / package id | **N/A** | **N/A** |
| `cloud` | whatever the provider uses to include hostname, ARN, resource path | optional | meaningful |

The distinction is not cosmetic. A blank IP on a *host* means "not
resolved yet" and a gap in our coverage. On a mobile app it means there is
nothing to resolve. Recording which is which is what stops an app
appearing in a report as an unscanned server.

## Importing at scale

The importers stream. A 2.5 GB Burp proxy history, 357,276 transactions
across 1,611 hosts parses in about 9 seconds at a flat ~360 MB, and
imports as a background job that survives closing the tab.

Two rules worth knowing:

- **Only open ports are recorded.** A UDP probe with no reply is
  indistinguishable from one a firewall dropped, and a closed TCP port is
  a reply saying nothing is there. One `-sU` sweep produced 42,890
  `open|filtered` rows against 13 genuinely open ports.
- **Strict mode by default.** An import only writes to hosts the project
  already has, and reports the rest for a decision. The file is held
  server-side while you decide, so answering costs a few hundred bytes
  rather than a second upload.

## Running on PostgreSQL

SQLite takes one writer at a time, which a long import and a background
worker will fight over. `docker compose up` gives you PostgreSQL
already wired in; to point an existing checkout at one yourself:

```bash
docker run -d --name oddjob-pg -e POSTGRES_USER=oddjob \
  -e POSTGRES_PASSWORD=... -e POSTGRES_DB=oddjob \
  -v oddjob-pgdata:/var/lib/postgresql/data -p 127.0.0.1:5433:5432 postgres:17

export ODDJOB_DATABASE_URL=postgresql://oddjob:...@127.0.0.1:5433/oddjob
cd backend && uv run alembic upgrade head
uv run python pgcopy.py --to "$ODDJOB_DATABASE_URL"   # existing data, optional
```

The DSN is an environment variable, not a setting: the settings table
lives inside the database, so a connection string stored there could not
be read until the connection it describes was already open.

## The agent

Configure a provider in Site Config and the agent can answer questions
about an engagement, draft remediation for findings one at a time, and
over Slack Socket Mode... reply when someone @-mentions it. It is
read-only unless writes are explicitly enabled, and scoped to a single
engagement: a question asked in one channel cannot be answered with
another's data.

Socket Mode means the app opens the connection outward, so nothing has to
be exposed to the internet.

### Tasking Drones from the assistant

With writes enabled, the agent can queue enumeration itself — including
sweeps across the project's own inventory, rather than hosts you type in:

```
"run httpx over everything we have not scanned yet"
"nuclei the web hosts, through tokyo-01"
"nslookup every name we know"
```

It picks hosts by selection — `all`, `unscanned`, `web`, `hacked`,
`technology`, or an explicit list — and creates **one task per host**, so
the fleet shares the work and one failure stays one failure.

**It shows you the plan and queues nothing until you say go.** A sweep is
hundreds of tasks against someone's estate, and "have a look at the web
hosts" is a sentence, not an authorisation. The preview names the hosts,
the count, what scope refused and what is not a network host at all; only
a second, explicit confirmation queues it.

Three things it will not do, whatever it is asked:

- **`shell` and `install` are never queued by the assistant.** Running
  commands on, or installing software onto, a privileged process inside
  a client's network belongs on the Drone page, where the allowlist and
  the agent are both in front of you.
- **It cannot reach past the scope gate.** Tasking goes through the same
  check as the Drone page, because a scan you could not queue by hand
  must not become queueable by asking for it in a sentence.
- **It will not silently skip things.** Assets that are not network
  hosts — an S3 ARN, a cloud resource id — are dropped and *named*.
  "Queued 1,700 of your 1,738" is how you notice thirty-eight assets are
  covered by nothing.

## Exploits and CVEs, held locally

Oddjob keeps its own copy of Exploit-DB and the NVD CVE list, and does
all matching against those tables.

**The point is that the client's inventory never leaves the building.**
Asking a third-party API "anything for Apache 2.4.49?" on behalf of a
host tells that third party what your client runs, when you looked, and
— over enough queries — the shape of their estate. A local copy answers
the same question and tells nobody.

```bash
# Site Config → Vulnerability feeds → Sync now, or:
curl -XPOST -H "Authorization: Bearer $KEY" \
     "$ODDJOB/api/vulnfeeds/sync?source=all"

curl -H "Authorization: Bearer $KEY" \
     "$ODDJOB/api/vulnfeeds/leads?product=Apache+httpd&version=2.4.49"
```

Exploit-DB is a single file and syncs in seconds. NVD is ~300k records;
the first run walks back to 2002 in resumable chunks and later runs are
incremental. Both refresh daily. An NVD API key in Site Config takes the
rate limit from 5 requests per 30s to 50 — worth having for the first
sync, optional after.

The lookup routes take **a product and version, never a host**. That is
the boundary, and it is enforced by the API shape rather than by
convention.

Three things the results are careful about, because a vulnerability feed
is unusually easy to over-read:

| the result says | it means |
|---|---|
| `exact` | a CPE names this exact version |
| `product only` | the CPE covers every version — not evidence about yours |
| `unknown` | NVD has not analysed this CVE yet, so it cannot be matched either way |

Every response carries the feed's age alongside it, because "no known
exploits" from a feed synced this morning and the same answer from one
that has never run are different claims. A feed that has never synced
says so rather than returning a confident empty list.

These are **leads, not findings**: a banner is often wrong, and a patched
host reports the same version as an unpatched one. Confirming them
against the target is the engagement.

## Tests

```bash
cd backend && uv run python runtests.py          # all suites
cd backend && uv run python runtests.py webtest  # one

cd frontend && npx tsc --noEmit && node test/hooks.check.mjs
```

Suites live in `backend/tests/`; `runtests.py` stays at the backend root
because it is the command you type. Each gets its own server, port and
database, and they refuse to run against `ODDJOB_DATABASE_URL`, so a
shell with the production DSN exported cannot point them at real data.

The backend suite needs `frontend/dist` to exist and it checks that the
API serves the built UI.

## Layout

```
backend/app/          FastAPI application
  importers/          one module per tool, sharing one intermediate form
  agent/              providers, tools, remediation worker
  reports/            templates, rendering, background runner
  slack.py            outbound notifications
  slack_socket.py     inbound, over Socket Mode
backend/tests/        one suite per area
backend/alembic/      migrations
frontend/src/         React UI
frontend/test/        typecheck helpers and logic tests
Dockerfile            multi-stage: UI build, deps, slim runtime
docker-compose.yml    the app and its database
docs/reference.md     the long version of all of this
CLAUDE.md             notes for working on this, and the traps
```

## Documentation

[`docs/reference.md`](docs/reference.md) is the detailed manual on every
subsystem, the reasoning behind it, and the traps found the hard way.

## Security

Please read [SECURITY.md](SECURITY.md) before deploying this. It holds
engagement data: findings, credentials and captured traffic including
session cookies.

## License

Apache 2.0. See [LICENSE](LICENSE).
