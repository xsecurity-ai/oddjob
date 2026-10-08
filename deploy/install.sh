#!/usr/bin/env bash
# Put Oddjob behind nginx on a host with a public name.
#
#   sudo ./deploy/install.sh oddjob.example.com
#
# Idempotent: safe to re-run after fixing whatever it complained about.
# It will not overwrite an existing .env, and it will not touch an
# nginx config it did not write.
set -euo pipefail

HOST="${1:-}"
if [[ -z "$HOST" ]]; then
    echo "usage: $0 <public-hostname>   e.g. $0 oddjob.example.com" >&2
    exit 2
fi
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mstopped: %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run with sudo — it writes to /etc/nginx"

say "Checking what is here"
command -v docker >/dev/null || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is missing"
command -v nginx  >/dev/null || die "nginx is not installed (apt install nginx)"

# Port 80 is not automatically ours. On a host that doubles as
# engagement infrastructure it is often an OAST callback listener, and
# taking it would silently drop proof of a vulnerability somebody is
# mid-way through demonstrating.
PORT80="$(ss -lntp 2>/dev/null | grep -E ':80 ' || true)"
if [[ -n "$PORT80" ]] && ! grep -q nginx <<<"$PORT80"; then
    echo "  something other than nginx is already on port 80:"
    sed 's/^/    /' <<<"$PORT80"
    die "free port 80, or install this on a different host"
fi

# DNS has to resolve before certbot can prove anything.
say "Checking DNS for $HOST"
RESOLVED="$(getent hosts "$HOST" | awk '{print $1}' | head -1 || true)"
if [[ -z "$RESOLVED" ]]; then
    die "$HOST does not resolve. Add the A record first — certbot's
    HTTP-01 challenge needs the name to point here before it will
    issue anything."
fi
echo "  $HOST -> $RESOLVED"
case "$RESOLVED" in
    10.*|192.168.*|172.1[6-9].*|172.2*.*|172.3[01].*|127.*)
        echo "  NOTE: that is a private address. If this is meant to be"
        echo "        reachable from the internet, the PUBLIC record is"
        echo "        the one that matters and certbot will use it." ;;
esac

say "Configuring the stack"
cd "$REPO"
if [[ -f .env ]]; then
    echo "  .env exists, leaving it alone"
else
    cp .env.example .env
    # Generated, not chosen. A password somebody types in is a
    # password somebody reuses.
    PW="$(openssl rand -base64 30 | tr -d '\n/+=' | cut -c1-32)"
    sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PW}|" .env
    grep -q '^BIND_ADDRESS=' .env \
        && sed -i "s|^BIND_ADDRESS=.*|BIND_ADDRESS=127.0.0.1|" .env \
        || echo "BIND_ADDRESS=127.0.0.1" >> .env
    chmod 600 .env
    echo "  wrote .env with a generated database password (0600)"
fi

say "Starting Oddjob and Postgres"
docker compose up -d --build
for _ in $(seq 1 60); do
    if curl -fsS -m 2 http://127.0.0.1:8000/api/auth/setup-required >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
curl -fsS -m 5 http://127.0.0.1:8000/api/auth/setup-required >/dev/null \
    || die "the app did not come up — docker compose logs app"
echo "  app answering on 127.0.0.1:8000"

say "Installing the nginx config"
install -m 0644 "$REPO/deploy/nginx/oddjob-proxy.conf" /etc/nginx/snippets/
sed "s/oddjob\.example\.com/${HOST}/g" "$REPO/deploy/nginx/oddjob.conf" \
    > /etc/nginx/sites-available/oddjob
ln -sf /etc/nginx/sites-available/oddjob /etc/nginx/sites-enabled/oddjob

# certbot has not run yet, so the cert paths in the vhost do not exist
# and `nginx -t` would fail on them. Serve the challenge over :80
# first, get the cert, then enable the TLS server block.
if [[ ! -s "/etc/letsencrypt/live/${HOST}/fullchain.pem" ]]; then
    say "Getting a certificate"
    command -v certbot >/dev/null || die "certbot is not installed (apt install certbot python3-certbot-nginx)"
    # Comment out the TLS vhost for the moment so nginx can start.
    awk '/^server \{$/{n++} n==2{print "#"$0; next} {print}' \
        /etc/nginx/sites-available/oddjob > /tmp/oddjob.http-only
    cp /tmp/oddjob.http-only /etc/nginx/sites-available/oddjob
    nginx -t && systemctl reload nginx
    certbot certonly --webroot -w /var/www/html -d "$HOST" --agree-tos -n \
        --register-unsafely-without-email \
        || die "certbot failed — is $HOST pointing at this host, and is :80 reachable from the internet?"
    # Put the real config back now the cert exists.
    sed "s/oddjob\.example\.com/${HOST}/g" "$REPO/deploy/nginx/oddjob.conf" \
        > /etc/nginx/sites-available/oddjob
fi

nginx -t || die "nginx rejected the config"
systemctl reload nginx
echo "  nginx reloaded"

say "Done — two things left, and both matter"
cat <<EOF

  1. Set site.base_url to https://${HOST} in Site Config.

     Not cosmetic. It decides whether the session cookie carries
     Secure, whether HSTS is sent, and what host magic sign-in links
     point at.

  2. Create the admin account NOW, before anyone else does.

     A fresh install hands the first account to whoever asks, because
     there is nobody to authenticate as yet. The name is public and
     the port is open.

         https://${HOST}/

  Then check it behaves:

     for i in \$(seq 1 8); do curl -s -o /dev/null -w "%{http_code} " \\
       -X POST -H 'Content-Type: application/json' \\
       -d '{"username":"x","password":"y"}' \\
       https://${HOST}/api/auth/login; done; echo

  Expect 401 up to the limit then 429. All 401s means the rate limit
  is not applied, and this install is a password-guessing target.

EOF
