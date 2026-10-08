# Putting Oddjob on a host people can reach

Oddjob holds findings, credentials and captured traffic including
session cookies. It has **no rate limiting, no brute-force lockout and
no WAF of its own** — see [SECURITY.md](../SECURITY.md). On a laptop
bound to loopback that is fine. On something with a public DNS name it
is not, and the proxy in this directory is what makes up the
difference.

Read this before exposing it, not after.

---

## What ends up where

```
    internet                  the host                  containers
   ─────────┐
            │  :443 TLS   ┌─────────┐   127.0.0.1:8000  ┌──────────┐
   browser ─┼────────────►│  nginx  ├──────────────────►│  oddjob  │
            │             └─────────┘                   └────┬─────┘
   drones  ─┘              rate limits                       │ db:5432
                           TLS                          ┌────▼─────┐
                                                        │ postgres │
                                                        └──────────┘
```

**Postgres is never published.** Not to the internet, not to the LAN.
The compose file binds it to `127.0.0.1` so a `psql` on the host works
and nothing else can reach it. If you do not need that, delete the
`ports:` block from the `db` service entirely — the app reaches it over
the compose network either way.

---

## 1. The stack

```bash
cp .env.example .env
# POSTGRES_PASSWORD: generate it, do not choose it
#   openssl rand -base64 30
# BIND_ADDRESS stays 127.0.0.1 — nginx is the only thing that should
# reach the app directly.
docker compose up -d
curl -s localhost:8000/api/auth/setup-required     # {"setup_required":true}
```

## 2. TLS and the proxy

```bash
cp deploy/nginx/oddjob.conf        /etc/nginx/sites-available/oddjob
cp deploy/nginx/oddjob-proxy.conf  /etc/nginx/snippets/
sed -i 's/oddjob.example.com/YOUR-HOST/g' /etc/nginx/sites-available/oddjob
ln -s /etc/nginx/sites-available/oddjob /etc/nginx/sites-enabled/

certbot --nginx -d YOUR-HOST
nginx -t && systemctl reload nginx
```

## 3. The step everyone forgets

In **Site Config → `site.base_url`**, set `https://YOUR-HOST`.

This is not cosmetic. It decides:

- whether the session cookie carries **Secure** — leave it `http://`
  behind TLS and the cookie ships without it;
- whether **HSTS** is sent at all;
- what host **magic sign-in links** point at. Wrong here and you email
  somebody a link to `127.0.0.1`.

## 4. Create the admin account immediately

The first visit to a fresh install creates the first account with no
authentication, because there is nobody to authenticate as yet. Between
`docker compose up` and that first visit, anyone who reaches the host
can claim it.

Do it before the DNS record exists, or over an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 you@host     # then open localhost:8000
```

---

## Checks worth running once it is up

```bash
# Postgres must not answer from anywhere but the host itself.
nmap -Pn -p 5432,5433 YOUR-HOST          # expect filtered/closed

# The app must not be reachable except through nginx.
curl -m 5 http://YOUR-HOST:8000/         # expect a timeout or refusal

# Sign-in is rate limited. The seventh attempt in a minute is a 429.
for i in $(seq 1 8); do
  curl -s -o /dev/null -w "%{http_code} " -X POST \
    -H 'Content-Type: application/json' \
    -d '{"username":"x","password":"y"}' https://YOUR-HOST/api/auth/login
done; echo

# TLS, HSTS and the Secure cookie.
curl -sI https://YOUR-HOST/ | grep -i strict-transport-security
```

Expect the login loop to read `401 401 401 401 401 401 429 429`. If it
is `401` all the way, the limit is not applied and the install is a
password-guessing target.

---

## Drones

Drones reach Oddjob over the same public name, and nothing about them
needs to change beyond `DRONE_SERVER=https://YOUR-HOST`. They are
deliberately **not** inside the login rate-limit zone: a fleet
heartbeats every few seconds and submits results in bursts after a long
scan, and throttling that drops findings from work that has already run
against someone's estate. They authenticate with a signed agent key
rather than a password, so they are not the brute-force surface.

## Which image to run

CI publishes to Docker Hub as `cr0n1c/oddjob` and `cr0n1c/drone`, both
`linux/amd64` and `linux/arm64`:

| tag | moves | what it is |
|---|---|---|
| `src-<key>` | never | one exact source tree. The durable name. |
| `develop-<sha>` | never | the `develop` build for one commit |
| `nightly-<date>` | never | the `nightly` build for one date |
| `develop` | every merge to main | what main currently is |
| `nightly` | 03:17 UTC | what a promotion draws from |
| `vX.Y.Z`, `latest` | on promotion | a release, by hand |

`develop` and `nightly` are the same bytes whenever the source has not
changed between them — the scheduled run retags rather than rebuilds,
so there is no second build that merely ought to match.

**Run an immutable tag in anything you care about.** `develop` moves
under you, which is the point of it and the reason not to pin
production to it:

```bash
# what is :develop right now
docker buildx imagetools inspect cr0n1c/oddjob:develop \
  --format '{{json .Manifest.Digest}}'
```

A promotion is `Actions → promote → Run workflow`, choosing `minor` or
`major`. It retags by digest and never rebuilds, so the version number
lands on bytes somebody has actually run.

## What this still does not give you

- **No IP allowlist.** If only your team should reach it, say so in
  nginx (`allow`/`deny`) or put it behind a VPN. A login form is a
  thinner boundary than not being reachable at all.
- **No audit of the proxy itself.** nginx's access log is the only
  record of requests that never reached the app, including the ones the
  rate limiter turned away.
- **No backups.** `pgdata` is a Docker volume. Losing it loses the
  engagement.
