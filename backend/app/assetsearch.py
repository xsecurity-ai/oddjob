"""Searching the JavaScript the client's pages actually load.

`web_assets.body` holds the bundle when the agent was asked to pull
it back. This is what makes having it worth the storage: a minified
bundle is where an application keeps the list of endpoints nobody
links to, the feature flags, the role names, and -- routinely -- a
key somebody meant to keep on the server.

**Two ways to ask.**

  * `text`   -- a literal. What a person types, matched verbatim.
  * `secrets`-- the built-in patterns below, which is the question
                most people actually came to ask.

There is deliberately no third mode taking a regular expression
from the caller. See `compile_pattern` for why, and for what it
would take to offer one safely.

**Everything here returns snippets, never a body.** A bundle is
megabytes and a finding is forty characters; shipping the whole file
so the browser can find the line is the kind of thing that works on
one asset and falls over on a project. The snippet carries enough
either side to judge the hit.

**Minified code has no lines.** A whole bundle is frequently one
line 800 KB long, so an offset is reported rather than a line
number, and the snippet is a window around the offset. Reporting
"line 1" for every hit in the file would be accurate and useless.

A note on what this costs. The bodies are client source code, which
is confidential, and the whole point of the `secrets` mode is that
they contain credentials. That was already true of the stored
request/response on `web_addresses`; this makes it true of more
rows. The gate is the same as the rest of the module -- a user who
cannot see the project cannot read its bundles -- and nothing here
is ever logged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Characters either side of a hit. Enough to see what the value is
#: attached to without returning the file.
CONTEXT = 90

#: Per asset. A pattern that matches a minified bundle's every
#: variable name should report that it did, not return ten thousand
#: snippets.
MAX_PER_ASSET = 25

#: Across the whole search, so one request cannot be made to scan a
#: project's entire corpus of bundles.
MAX_ASSETS = 500

#: A search term is a term, not an expression. See `compile_pattern`.
MAX_PATTERN = 200


class BadPattern(ValueError):
    """The search expression cannot be used."""


@dataclass
class Hit:
    """One match inside one asset."""
    #: Byte offset into the body. Not a line: see the module docstring.
    offset: int
    snippet: str
    #: Which built-in pattern fired, for a `secrets` search.
    rule: str = ""
    #: What the rule is worth. `firm` means the shape is unambiguous
    #: -- an AWS key id is not anything else. `loose` means it is a
    #: guess that still finds real things, and most of what it finds
    #: in minified code is not one.
    confidence: str = "firm"


@dataclass
class AssetHits:
    asset_id: int
    url: str
    hits: list[Hit] = field(default_factory=list)
    #: True when the cap cut the list short, so "25 hits" is never
    #: mistaken for "exactly 25 hits".
    capped: bool = False


#: The built-in patterns, as (rule, confidence, regex).
#:
#: Shape-based and deliberately narrow. A rule that matches anything
#: resembling a word teaches people to ignore the whole feature, and
#: a feature people ignore is worse than one that is not there --
#: they stop looking at the real hits too.
#:
#: The `loose` rules are kept because they are the ones that actually
#: find a bespoke application's own key. They are labelled rather
#: than hidden, so a reader knows which list they are reading.
SECRET_RULES: tuple[tuple[str, str, str], ...] = (
    ("aws-access-key-id", "firm", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("google-api-key", "firm", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack-token", "firm", r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b"),
    ("slack-webhook", "firm",
     r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/"
     r"[0-9A-Za-z]+"),
    ("stripe-secret-key", "firm", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    ("github-token", "firm", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("private-key-block", "firm",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("jwt", "firm",
     r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("azure-storage-key", "firm",
     r"\bDefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;"
     r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    # The loose ones. A minified bundle renames every local, but it
    # does NOT rename an object key that goes over the wire, which is
    # why `apiKey:"..."` survives minification and is worth asking
    # about.
    ("assigned-secret", "loose",
     r"""(?i)\b(?:api[_-]?key|apikey|secret|passwd|password|auth[_-]?token"""
     r"""|access[_-]?token|client[_-]?secret|private[_-]?key)\b"""
     r"""\s*[:=]\s*["'`]([^"'`\s]{12,100})["'`]"""),
    ("bearer-literal", "loose",
     r"""["'`]Bearer\s+[A-Za-z0-9_\-.=]{16,}["'`]"""),
    ("basic-auth-url", "loose",
     r"\bhttps?://[A-Za-z0-9._%+-]+:[^@\s/\"'`]{4,}@[A-Za-z0-9.-]+"),

    # ---- vendor shapes, secretlint's recommended preset ----------
    # Each is unambiguous: the prefix and length belong to one
    # issuer, so a match is a credential rather than a guess.
    ("npm-token", "firm", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("sendgrid-key", "firm",
     r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b"),
    ("shopify-token", "firm", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    ("telegram-bot-token", "firm", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{32,34}\b"),
    ("gitlab-pat", "firm", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    ("openai-key", "firm", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b"),
    ("anthropic-key", "firm", r"\bsk-ant-[A-Za-z0-9_\-]{24,}\b"),
    ("twilio-key", "firm", r"\bSK[0-9a-fA-F]{32}\b"),
    ("mailgun-key", "firm", r"\bkey-[0-9a-f]{32}\b"),
    ("square-token", "firm", r"\b(?:sq0atp|sq0csp|EAAA)[A-Za-z0-9_\-]{20,}\b"),
    ("algolia-admin-key", "loose",
     r"""(?i)\balgolia[_-]?(?:admin[_-]?)?(?:api[_-]?)?key\b"""
     r"""\s*[:=]\s*["\'`]([A-Za-z0-9]{32})["\'`]"""),
    ("gcp-service-account", "firm",
     r'"type"\s*:\s*"service_account"'),
    ("aws-secret-access-key", "loose",
     r"""(?i)\baws[_-]?secret[_-]?access[_-]?key\b"""
     r"""\s*[:=]\s*["\'`]([A-Za-z0-9/+=]{40})["\'`]"""),

    # The operator's own grep, kept verbatim in intent: a named
    # credential field assigned a long opaque literal. Narrower
    # charset than `assigned-secret` above and a higher floor, so
    # it fires on fewer things and is worth more when it does.
    ("assigned-opaque-secret", "loose",
     r"""(?i)\b(?:api[_-]?key|token|secret|password)\b["\'`]?"""
     r"""\s*[:=]\s*["\'`]([A-Za-z0-9_\-]{20,})["\'`]"""),
)

#: Compiled once. These run against every byte of every bundle.
_COMPILED: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (rule, conf, re.compile(pat)) for rule, conf, pat in SECRET_RULES)

def compile_pattern(q: str, mode: str) -> re.Pattern[str]:
    """The caller's term as a literal matcher, or `BadPattern`.

    **A caller cannot supply a regular expression, and that is the
    whole design rather than a missing feature.**

    This did accept one. `(a+)+$` against a megabyte of minified
    JavaScript does not finish, Python's `re` has no timeout, and
    `re` holds the GIL while it backtracks -- so one search could
    hang a worker. The first version tried to screen the dangerous
    shapes out with another regex, and that was worse in two ways
    CodeQL named exactly: the screen cannot be complete (`py/regex-
    injection`), and the screen was ITSELF quadratic against a string
    of many `(` (`py/polynomial-redos`). A guard that can hang while
    deciding whether something might hang is not a guard.

    There is no safe way to run an arbitrary user regex on this
    engine. A linear-time engine (RE2) would make it safe by
    construction and is the way to bring the feature back; a cleverer
    screen is not.

    So: every search is a literal. `re.escape` means the compiled
    pattern holds no user-controlled syntax at all, which removes
    both findings at the source rather than arguing with them. The
    built-in `secrets` rules are still regexes -- fixed ones, written
    here, matched against no user input.
    """
    q = (q or "").strip()
    if not q:
        raise BadPattern("nothing to search for")
    if len(q) > MAX_PATTERN:
        raise BadPattern(f"the search term is longer than {MAX_PATTERN} "
                         "characters")
    if mode != "text":
        raise BadPattern(
            f"unknown search mode {mode!r}. Searches are literal; use "
            "the secrets scan for pattern matching.")
    # Literal, always. Someone searching for `api.key(` is not writing
    # a regex and should not be told their brackets are unbalanced.
    return re.compile(re.escape(q), re.IGNORECASE)


def snippet_at(body: str, start: int, end: int) -> str:
    """`CONTEXT` characters either side of a match, on one line.

    Newlines and tabs are flattened because the point is to read one
    hit, and a bundle that does have newlines would otherwise make a
    three-line snippet out of a twelve-character match.
    """
    a = max(0, start - CONTEXT)
    b = min(len(body), end + CONTEXT)
    text = body[a:b].replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s{2,}", " ", text).strip()
    return ("…" if a > 0 else "") + text + ("…" if b < len(body) else "")


def search_body(body: str, pattern: re.Pattern[str], *,
                rule: str = "", confidence: str = "firm",
                limit: int = MAX_PER_ASSET) -> tuple[list[Hit], bool]:
    """-> (hits, capped). One pattern against one body."""
    hits: list[Hit] = []
    for m in pattern.finditer(body or ""):
        if len(hits) >= limit:
            return hits, True
        hits.append(Hit(offset=m.start(),
                        snippet=snippet_at(body, m.start(), m.end()),
                        rule=rule, confidence=confidence))
    return hits, False


def scan_secrets(body: str, limit: int = MAX_PER_ASSET,
                 ) -> tuple[list[Hit], bool]:
    """Every built-in rule against one body, firm rules first.

    Ordered so that a bundle carrying both an AWS key and forty
    `token:"..."` assignments reports the AWS key, rather than
    spending the cap on the guesses and cutting off the certainty.
    """
    hits: list[Hit] = []
    capped = False
    for conf in ("firm", "loose"):
        for rule, c, pat in _COMPILED:
            if c != conf:
                continue
            got, cut = search_body(body, pat, rule=rule, confidence=c,
                                   limit=limit - len(hits))
            hits.extend(got)
            capped = capped or cut
            if len(hits) >= limit:
                return hits[:limit], True
    return hits, capped
