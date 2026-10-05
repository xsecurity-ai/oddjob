"""Live tests for the outbound integrations, and the proof that one passed.

Saving credentials that have never been exercised is how a site ends up with
an SMTP password that silently fails at 2am, when the only thing that needed
it was a password-reset link. So the config screen tests first and saves
second.

The proof has to be bound to the exact values tested, or the control is
theatre: test with a working password, then save a different one. So a pass
issues a short-lived signed token carrying a digest of precisely the values
that were exercised, and the save recomputes that digest from what it is
about to write and refuses if it does not match.

Secrets are digested, never carried in the token.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import httpx
import jwt

from .mailer import send_mail
from .security import ALGO, SECRET

TOKEN_TTL_MINUTES = 30

# The credential keys whose change demands a fresh pass. Deliberately not the
# whole group: changing the allowed-domains list cannot break authentication,
# and forcing a test for it would train people to click past the gate.
GATE_KEYS: dict[str, tuple[str, ...]] = {
    "smtp": ("smtp.host", "smtp.port", "smtp.security", "smtp.username",
             "smtp.password", "smtp.from_address"),
    "google": ("auth.google_client_id", "auth.google_client_secret",
               "auth.google_redirect_uri"),
    "postgres": ("db.external_url",),
}

# Turning a provider ON is itself gated: it is the moment the credentials
# start being relied on. Turning it off never needs a test.
ENABLE_KEY: dict[str, str] = {"google": "auth.google_enabled"}

GATED_KEYS = {k for ks in GATE_KEYS.values() for k in ks} | set(ENABLE_KEY.values())


def digest(provider: str, values: dict) -> str:
    """A stable fingerprint of the credential set, secrets included by hash."""
    h = hashlib.sha256()
    for key in GATE_KEYS[provider]:
        v = values.get(key)
        h.update(key.encode())
        h.update(b"\x00")
        h.update(("" if v is None else str(v)).encode())
        h.update(b"\x1e")
    return h.hexdigest()


def issue_token(provider: str, values: dict) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"p": provider, "d": digest(provider, values),
                       "iat": now, "exp": now + timedelta(minutes=TOKEN_TTL_MINUTES)},
                      SECRET, algorithm=ALGO)


def token_matches(token: str | None, provider: str, values: dict) -> tuple[bool, str]:
    if not token:
        return False, (f"{provider} credentials changed — run Test first "
                       f"(no proof of a successful test was supplied)")
    try:
        claims = jwt.decode(token, SECRET, algorithms=[ALGO])
    except jwt.ExpiredSignatureError:
        return False, f"the {provider} test result has expired — run Test again"
    except jwt.PyJWTError:
        return False, f"the {provider} test result is not valid — run Test again"
    if claims.get("p") != provider:
        return False, f"that test result is for {claims.get('p')!r}, not {provider!r}"
    if claims.get("d") != digest(provider, values):
        return False, (f"the {provider} settings changed after the test — "
                       f"run Test again on the values you are saving")
    return True, "ok"


# --------------------------------------------------------------- the tests
async def run_test(provider: str, values: dict, to: str | None = None) -> tuple[bool, str]:
    if provider == "smtp":
        return await _smtp(values, to)
    if provider == "google":
        return await _google(values)
    if provider == "postgres":
        return await _postgres(values)
    raise KeyError(provider)


async def _postgres(cfg: dict) -> tuple[bool, str]:
    """Actually connect and ask the server who it is.

    Read-only: one `SELECT version()` and a look at whether the schema is
    already there. A config test must never write to somebody else's
    database — the point is to find out whether we *can* reach it, and a
    test that leaves a table behind is a test that cannot be run twice.
    """
    from .dsn import BadDsn
    from .dsn import parse as parse_dsn

    raw = str(cfg.get("db.external_url") or "").strip()
    if not raw:
        return False, "no connection string configured"
    try:
        d = parse_dsn(raw)
    except BadDsn as e:
        return False, str(e)

    try:
        import asyncpg
    except ImportError:
        return False, ("the asyncpg driver is not installed on the server "
                       "(uv add asyncpg)")

    import asyncio
    conn = None
    try:
        conn = await asyncio.wait_for(asyncpg.connect(
            host=d.host, port=d.port, user=d.user, password=d.password,
            database=d.database,
            ssl="require" if "sslmode=require" in (d.params or "") else None,
        ), timeout=15)
        version = await conn.fetchval("SELECT version()")
        # Is this database already carrying a Oddjob schema? Pointing at
        # one that is empty and one that is already populated are very
        # different situations, and the operator should be told which.
        n_tables = await conn.fetchval(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_schema = current_schema()")
        can_create = await conn.fetchval(
            "SELECT has_schema_privilege(current_schema(), 'CREATE')")
    except asyncio.TimeoutError:
        return False, f"timed out connecting to {d.summary} after 15s"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        if conn is not None:
            try:
                await conn.close()
            except Exception:
                pass

    short = str(version or "").split(" on ")[0]
    warn = "" if can_create else " — WARNING: this user cannot CREATE in the schema"
    return True, (f"connected to {d.summary} · {short} · "
                  f"{n_tables} table(s) in the current schema{warn}")


async def _smtp(cfg: dict, to: str | None) -> tuple[bool, str]:
    """Send a real message. Checking that the host field is non-empty proves
    nothing; the failures that matter are auth, TLS and relaying."""
    if not cfg.get("smtp.host"):
        return False, "no SMTP host configured"
    if not to:
        return False, "a recipient address is required to test SMTP"
    try:
        await send_mail(cfg, to,
                        f"{cfg.get('site.name') or 'Oddjob'} — SMTP test",
                        "This is a test message from Oddjob.\n\n"
                        "If you received it, invitations and magic sign-in links "
                        "will work.\n")
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    return True, f"sent to {to} — confirm it arrived before relying on it"


async def _google(cfg: dict) -> tuple[bool, str]:
    """Exercise the client credentials without a user present.

    Google's token endpoint distinguishes a bad client from a bad grant, so
    deliberately redeeming an invalid code is a real test of the id/secret
    pair: `invalid_client` means the credentials are wrong, `invalid_grant`
    means they were accepted and only the (intentionally junk) code was not.
    """
    cid = str(cfg.get("auth.google_client_id") or "").strip()
    secret = str(cfg.get("auth.google_client_secret") or "").strip()
    redirect = str(cfg.get("auth.google_redirect_uri") or "").strip()
    if not cid:
        return False, "no Google client ID configured"
    if not secret:
        return False, "no Google client secret configured"
    if not redirect.startswith(("http://", "https://")):
        return False, "the redirect URI must be an absolute http(s) URL"
    if not redirect.rstrip("/").endswith("/api/auth/google/callback"):
        return False, ("the redirect URI must end in /api/auth/google/callback — "
                       "that is the only path this app handles")

    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post("https://oauth2.googleapis.com/token", data={
                "code": "oddjob-configuration-probe",
                "client_id": cid, "client_secret": secret,
                "redirect_uri": redirect, "grant_type": "authorization_code"})
    except Exception as e:
        return False, f"could not reach Google: {type(e).__name__}: {e}"

    try:
        err = (r.json() or {}).get("error", "")
    except Exception:
        return False, f"unexpected reply from Google (HTTP {r.status_code})"

    if err == "invalid_grant":
        # The only success path: Google authenticated the client, then
        # rejected the throwaway code exactly as it should.
        return True, (f"client {cid[:14]}… accepted by Google; "
                      f"redirect URI is well-formed")
    if err == "invalid_client":
        return False, "Google rejected the client ID/secret pair"
    if err == "redirect_uri_mismatch":
        return False, (f"the client is valid but {redirect} is not registered "
                       f"for it in the Google console")
    return False, f"Google said: {err or f'HTTP {r.status_code}'}"
