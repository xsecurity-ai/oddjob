"""Parsing, masking and validating a Postgres connection string.

**Masking is the point of this module.** A DSN is one string that mixes
things an operator must be able to see — which host, which database, which
user — with one thing nobody should ever render: the password. Treating the
whole string as a write-only secret (the way the SMTP password is handled)
would mean the config screen could never show you *which database you are
pointed at*, which is exactly the thing you check before trusting it. So
the DSN is stored whole and returned with only the password replaced.

The masking is done on the parsed URL, not with a regex over the raw text.
A password containing `@`, `:` or `/` — which is common, because password
generators do not know about URL syntax — defeats every regex approach, and
a mask that leaks the tail of a password on some inputs is worse than no
mask at all, because it is trusted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit

MASK = "•" * 8          # ••••••••

#: Drivers we can actually talk to. `postgres://` is the historical alias
#: libpq still accepts, so it is accepted here and normalised.
_SCHEMES = {
    "postgres": "postgresql+asyncpg",
    "postgresql": "postgresql+asyncpg",
    "postgresql+asyncpg": "postgresql+asyncpg",
    "postgresql+psycopg": "postgresql+asyncpg",
    "postgresql+psycopg2": "postgresql+asyncpg",
}


class BadDsn(ValueError):
    pass


@dataclass
class Dsn:
    raw: str                 # exactly what was supplied, password included
    scheme: str              # normalised SQLAlchemy driver URL scheme
    user: str | None
    password: str | None
    host: str
    port: int
    database: str
    params: str              # query string, verbatim

    @property
    def masked(self) -> str:
        """Safe to render, log and return over the API.

        Not percent-encoded: this form exists to be read by a person, and
        encoding the mask turns it into %E2%80%A2 repeated eight times.
        """
        return _render(self, self.password and MASK, encode=False)

    @property
    def url(self) -> str:
        """The real URL, normalised to the async driver. Never displayed."""
        return _render(self, self.password, encode=True)

    @property
    def summary(self) -> str:
        who = f"{self.user}@" if self.user else ""
        return f"{who}{self.host}:{self.port}/{self.database}"


def _render(d: Dsn, password: str | None, *, encode: bool) -> str:
    auth = ""
    if d.user:
        auth = quote(d.user, safe="") if encode else d.user
        if password:
            # MUST be percent-encoded. parse() decodes it, so a password
            # like `te:st@pw/1` comes back with the very characters that
            # delimit a URL; writing it back raw produces a string that
            # re-parses with the host set to "pw". The mask has no special
            # characters, which is why this only bites on the real URL —
            # i.e. only in production, only on some passwords.
            auth += ":" + (quote(password, safe="") if encode else password)
        auth += "@"
    netloc = f"{auth}{d.host}:{d.port}"
    return urlunsplit((d.scheme, netloc, f"/{d.database}", d.params, ""))


def parse(raw: str) -> Dsn:
    """-> Dsn, or raise BadDsn naming what is wrong.

    Accepts the URL form. The libpq keyword form (`host=… dbname=…`) is
    converted first, because that is what `psql` prints and what people
    paste.
    """
    s = (raw or "").strip()
    if not s:
        raise BadDsn("empty connection string")

    if "://" not in s and "=" in s:
        s = _from_keywords(s)

    parts = urlsplit(s)
    scheme = (parts.scheme or "").lower()
    if scheme not in _SCHEMES:
        raise BadDsn(
            f"{scheme or 'that'!r} is not a Postgres connection string — "
            f"expected one starting postgresql:// or postgres://")

    host = (parts.hostname or "").strip()
    if not host:
        raise BadDsn("no host in the connection string")
    try:
        port = parts.port or 5432
    except ValueError:
        raise BadDsn("the port is not a number")

    database = unquote((parts.path or "").lstrip("/"))
    if not database:
        raise BadDsn("no database name — expected …:5432/dbname")
    if "/" in database:
        raise BadDsn(f"{database!r} does not look like a database name")

    # urlsplit already percent-decodes these, which is what we want: the
    # stored value is the real credential, and re-encoding happens on render.
    user = unquote(parts.username) if parts.username else None
    password = unquote(parts.password) if parts.password else None

    return Dsn(raw=raw.strip(), scheme=_SCHEMES[scheme], user=user,
               password=password, host=host, port=port, database=database,
               params=parts.query or "")


_KW = re.compile(r"(\w+)\s*=\s*('[^']*'|\"[^\"]*\"|\S+)")


def _from_keywords(s: str) -> str:
    """`host=db.x port=5432 dbname=app user=u password=p` -> a URL."""
    kv = {}
    for m in _KW.finditer(s):
        kv[m.group(1).lower()] = m.group(2).strip("'\"")
    host = kv.get("host") or kv.get("hostaddr")
    db = kv.get("dbname") or kv.get("database")
    if not host or not db:
        raise BadDsn("keyword connection string needs at least host= and dbname=")
    auth = ""
    if kv.get("user"):
        auth = quote(kv["user"], safe="")
        if kv.get("password"):
            auth += ":" + quote(kv["password"], safe="")
        auth += "@"
    extra = "&".join(f"{k}={quote(v, safe='')}" for k, v in kv.items()
                     if k in ("sslmode", "application_name", "connect_timeout"))
    return (f"postgresql://{auth}{host}:{kv.get('port', '5432')}/{quote(db, safe='')}"
            + (f"?{extra}" if extra else ""))


def mask(raw: str) -> str:
    """Mask a DSN, falling back to total redaction if it will not parse.

    An unparseable string must not be echoed back: the reason it did not
    parse may well be that the password contains something unexpected, and
    printing it to prove the point is not a trade worth making.
    """
    try:
        return parse(raw).masked
    except BadDsn:
        return MASK if raw and raw.strip() else ""


def is_masked(raw: str) -> bool:
    """Did this value come back from us rather than from the operator?

    The config form round-trips the masked string, so a save that has not
    touched the field would otherwise store `••••••••` as the password and
    break the connection in a way that looks like a server fault.
    """
    return MASK in (raw or "")
