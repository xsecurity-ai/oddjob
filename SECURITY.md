# Security

## Reporting a vulnerability

Email **security@xsecurity.dev** with enough detail to reproduce it.
Please do not open a public issue for anything exploitable.

You can expect an acknowledgement within three working days and an
assessment within ten. If you want to disclose publicly, tell us when —
we would rather coordinate than be surprised, and we will not ask you to
wait indefinitely.

## What this software holds

Oddjob is an engagement data store. A deployment in use contains:

- findings, including unfixed ones, for systems belonging to a client
- credentials recovered during testing
- captured HTTP requests and responses, **including session cookies and
  authorization headers**
- scope documents and client contact details

Treat an Oddjob instance as being as sensitive as the engagements inside
it. A compromise is a client-notification event, not an internal
inconvenience.

## Deploying it safely

**Do not expose it to the internet.** There is no rate limiting, no
brute-force lockout and no WAF in front of it. Run it on a host reachable
only over a VPN or a private network. The Slack integration uses Socket
Mode specifically so that answering questions does not require an inbound
port.

**Set `site.base_url` to an `https://` URL.** HSTS, `upgrade-insecure-
requests` and the `Secure` flag on the session cookie are all derived
from it. Left on plain http they are deliberately switched off, because
sending HSTS from a dev server teaches the browser to refuse the thing
you are developing.

**Keep `.secret` secret.** It signs session tokens; anyone holding it can
mint a session for any user. It is generated on first run and is in
`.gitignore`.

**Back up the database, and treat the backup the same way.** It is the
engagement.

## What is deliberately dangerous

Some of this tool's behaviour would be a vulnerability in other software
and is the point here. It is bounded, and the bounds matter:

- **Request replay** sends an arbitrary HTTP request you have edited.
  The destination host must already be a target in the same engagement.
  Without that restriction the endpoint is an authenticated open proxy
  for anyone with an account.
- **The agent** can read everything in an engagement and, when
  `agent.allow_writes` is on, create notes, targets and findings. A
  reader cannot gain write access through it whatever the site setting
  says. Over Slack it is always read-only.
- **Imported files are untrusted.** XML is parsed with `defusedxml`:
  external entities are refused and internal entity expansion is blocked
  — a 331-byte document expands to 1 MB without it.

## Secrets in this repository

There are none, and there should never be. `.gitignore` excludes the
database, `.secret`, `pg.env`, `.env`, keys and scanner output. Tokens
appearing in source are documentation placeholders such as
`xoxb-project-override`.

Hostnames in tests and examples use `*.acme.example` and similar. **Do
not commit a real client's hostnames, IP ranges or findings**, including
in a test fixture or a code comment. This repository is public; a client
name in it discloses who the engagement was with.

## Supported versions

This is pre-1.0 and moves quickly. Fixes land on `main`; there are no
maintained release branches yet.
