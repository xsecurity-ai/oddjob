# Oddjob

**Authorized penetration testing and red teaming only.** Nation-state
actors and criminal hacking groups — as defined under US law — are not
authorized to use this toolset. See [Authorized use](#authorized-use).

---

## What is this

Oddjob is where an engagement's data lives: projects, targets, services,
findings, credentials, captured web traffic and the reports that come out
of it. One place where "what do we know about this host" has one answer.

It owes its shape to [**lair-framework**](https://github.com/lair-framework/lair),
which got the important idea right years ago — that a team needs a shared
datastore for an engagement, not a folder of everyone's scan output. Lair
is where this starts from. What Oddjob adds is the rest: the parts of
every collaboration platform that were worth keeping, taken honestly and
put in one place — Faraday's importer breadth, Dradis's reporting,
Ghostwriter's engagement structure, the proxy-history handling you only
get from living in Burp — plus the things none of them do, like an agent
that can read and write the engagement, and Drones.

**You can use it two ways, and the second is optional:**

| | what you run | what you get |
|---|---|---|
| **As a reporter** | Oddjob alone | Import what your tools already produced. Triage, deduplicate, merge, write findings, generate the report. Nothing of yours ever touches the target. |
| **As an active engagement** | Oddjob **+ Drones** | The above, plus enumeration you drive from the UI. Drones run the scanners, on your infrastructure, and the results import themselves. |

If you only ever import files, you never need a Drone. The whole agent
side is additive — there is no degraded mode, no nagging, and no feature
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
back, which import themselves into the project. A Drone **dials out** —
nothing listens on the internet, and nothing needs to be exposed to add
one.

Drones are **tied to a project**. A Drone enrolled on ACME takes tasking
from ACME, and everything it finds lands in ACME. It cannot be borrowed
by another engagement.

→ **[Drones have their own README](drone/README.md)** — what they are,
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

### Docker — do it this way

Everything, including PostgreSQL and the migrations, in one command.

```bash
git clone https://github.com/xsecurity-ai/oddjob && cd oddjob
cp .env.example .env            # set POSTGRES_PASSWORD
docker compose up -d            # app + database, migrations applied on boot
open http://127.0.0.1:8000
```

First run creates the admin account. Everything after that needs a
session.

That is the whole install. You get PostgreSQL rather than SQLite — which
matters the moment a long import and a background worker want to write at
the same time — the UI already built, and the Drone binaries for every
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
brute-force lockout — put this behind a VPN or an authenticating proxy
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
**[Drone README](drone/README.md)** — read it before deploying one.

---

## What Oddjob does with the data

- **Import** nmap, masscan, Nessus, Metasploit, Burp (issues *and* proxy
  history), Nikto, Nuclei, httpx, and five C2 frameworks. Formats are
  detected from the file.
- **One row per captured exchange**, not per URL — the same endpoint
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
| `cloud` | whatever the provider uses — hostname, ARN, resource path | optional | meaningful |

The distinction is not cosmetic. A blank IP on a *host* means "not
resolved yet" — a gap in our coverage. On a mobile app it means there is
nothing to resolve. Recording which is which is what stops an app
appearing in a report as an unscanned server.

## Importing at scale

The importers stream. A 2.5 GB Burp proxy history — 357,276 transactions
across 1,611 hosts — parses in about 9 seconds at a flat ~360 MB, and
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
about an engagement, draft remediation for findings one at a time, and —
over Slack Socket Mode — reply when someone @-mentions it. It is
read-only unless writes are explicitly enabled, and scoped to a single
engagement: a question asked in one channel cannot be answered with
another's data.

Socket Mode means the app opens the connection outward, so nothing has to
be exposed to the internet.

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

The backend suite needs `frontend/dist` to exist — it checks that the
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

[`docs/reference.md`](docs/reference.md) is the detailed manual — every
subsystem, the reasoning behind it, and the traps found the hard way.

## Security

Please read [SECURITY.md](SECURITY.md) before deploying this. It holds
engagement data: findings, credentials and captured traffic including
session cookies.

## License

Apache 2.0. See [LICENSE](LICENSE).
