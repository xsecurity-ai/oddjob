"""Run opengrep and detect-secrets over recovered asset files.

Server-side, not on a ghost. The files are already here, the
scanners are static analysis over text, and running them on the
agent would mean shipping a client's source back out to whichever
box happened to be free.

**Secrets are kept out of the finding.** A `vulns` row is readable
by every member of the project, listed, searched, exported into
reports and pasted into Slack; a credential in its description is a
credential in all of those places. What the row records is the
detector that fired, the file and line, a redaction, and a
fingerprint of the match so the same secret is recognised across
sweeps. The value itself goes in `finding_secrets`, behind a role
check and an audit entry -- see `routers/findings.reveal_secret`.
The redaction keeps the first and last two characters, which is
enough to tell two keys apart by eye and not enough to use.

**Neither scanner is given the network.** opengrep runs offline
against a bundled ruleset -- the obvious `--config=auto` fetches
from semgrep.dev -- and detect-secrets is a library running in
this process with no verification step at all. Nothing here
authenticates a found credential against its provider: that would
be a live authentication attempt against a third party nobody has
authorised, from our egress.

Subprocesses are given an argument list, never a shell string: the
runtime image is distroless and has no shell, and a filename out of
a source map is attacker-influenced text.

trufflehog was here and is not any more. See the git history: it
was in the image, the sweep called it, and it reported nothing
across 28,705 files -- because the binary had been deleted from the
running container and `available()` had been answering False the
whole time. The silence read as "no secrets in the estate". That is
exactly what `available()` and the `ok` flag below exist to prevent,
and it still took an operator asking why the number was zero.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass

log = logging.getLogger("oddjob.assetscan")

#: Where the binaries are. Overridable so a developer without them
#: installed can point at their own, and so the test suite can prove
#: the absent-scanner path.
OPENGREP = os.environ.get("ODDJOB_OPENGREP", "/usr/local/bin/opengrep")

#: opengrep's pre-extracted interpreter, unpacked at image build.
#:
#: `opengrep_manylinux` is a self-extracting wrapper, not a static
#: binary: on first run it writes ~84MB into $HOME/.cache/opengrep/.
#: The runtime image is distroless and runs as uid 10001 with HOME=/,
#: so that write fails and opengrep will not start at all. The cache
#: is built into the image and HOME is set for THIS SUBPROCESS only
#: -- changing it for the whole container would alter the
#: environment of everything else for the sake of one tool.
OPENGREP_HOME = os.environ.get("ODDJOB_OPENGREP_HOME", "/opt/opengrep")

#: Rules, bundled into the image. NOT `--config=auto`, which fetches
#: from semgrep.dev on every scan -- a third-party request per file,
#: from a server holding a client's source. Proved by running with
#: `--network none`: ConnectionError to semgrep.dev/c/auto.
OPENGREP_RULES = os.environ.get("ODDJOB_OPENGREP_RULES",
                                "/opt/opengrep-rules")

#: The environment opengrep needs, and why each part of it.
#:
#: HOME         its pre-extracted interpreter lives there
#: PYTHONUTF8   the bundled interpreter defaults to ASCII in a
#:              distroless image, which has no locale set, and dies
#:              with UnicodeDecodeError on the first rule file
#:              containing a non-ASCII character -- which is most of
#:              them, because rule messages use typographic quotes
#: LANG/LC_ALL  belt and braces for anything reading the locale
#:              rather than the Python-specific switch
#:
#: Found by running it, not by reading about it.
OPENGREP_ENV = {
    "HOME": OPENGREP_HOME,
    "PYTHONUTF8": "1",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}

#: A scan that will not finish is a scan that blocks the sweep.
#:
#: The original 120s was per FILE and hid a real problem: against
#: the whole rule corpus every file ran to the timeout, a 25-file
#: batch took the best part of an hour, and the sweep never
#: committed -- so fetching advanced while scanning recorded
#: nothing at all and looked idle.
#: Per BATCH now, not per file -- one invocation covers the whole
#: batch, so this is the ceiling on a sweep's slow half rather than
#: on one file.
TIMEOUT = 300.0


#: Which rule directories apply to a file, by extension.
#:
#: `OPENGREP_RULES` is the whole semgrep-rules corpus -- every
#: language, thousands of rules. Pointing opengrep at all of it to
#: scan one .js file is what made every scan hit the timeout: it
#: loads and compiles the lot per invocation. Narrowing to the
#: relevant languages is the difference between a second and a
#: timeout, measured in production.
_RULES_BY_EXT = {
    ".js": ("javascript", "typescript"),
    ".jsx": ("javascript", "typescript"),
    ".mjs": ("javascript", "typescript"),
    ".cjs": ("javascript", "typescript"),
    ".ts": ("typescript", "javascript"),
    ".tsx": ("typescript", "javascript"),
    ".vue": ("javascript", "typescript"),
    ".json": ("generic",),
    ".css": ("generic",),
    ".html": ("html", "javascript"),
    ".py": ("python",),
}

#: When the extension says nothing. `generic` is the language-less
#: ruleset; it is small and finds the things that are not
#: language-specific anyway.
_RULES_DEFAULT = ("generic",)


def rules_for(path: str) -> list[str]:
    """-> rule directories to scan this file against, that EXIST.

    Non-existent directories are dropped rather than passed: opengrep
    exits non-zero on a config path it cannot read, which would turn
    a missing ruleset into "this file has no findings".
    """
    ext = os.path.splitext(path)[1].lower()
    names = _RULES_BY_EXT.get(ext, _RULES_DEFAULT)
    out = []
    for n in names:
        d = os.path.join(OPENGREP_RULES, n)
        if os.path.isdir(d):
            out.append(d)
    return out

#: Cap on findings kept from one file. A pathological file can match
#: a loose rule thousands of times, and ten thousand rows about one
#: bundle buries every other finding in the project.
MAX_PER_FILE = 200

#: opengrep severity -> ours. `info` is the floor: a finding we do
#: not have a mapping for is still recorded, just not amplified.
_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "info",
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low"}


@dataclass(frozen=True)
class Finding:
    """One thing a scanner said, in our vocabulary."""
    scanner: str                 # opengrep | detect-secrets
    rule: str
    title: str
    severity: str
    path: str
    line: int | None
    detail: str
    #: Stable across sweeps for the same finding in the same place,
    #: so re-scanning amends instead of duplicating.
    fingerprint: str
    #: The matched credential, for the caller to store SEPARATELY
    #: from the finding. Never put in `title` or `detail`: those are
    #: listed, searched, exported and pasted into Slack. See
    #: models.FindingSecret and the reveal endpoint.
    secret: str | None = None


#: detect-secrets findings that are entropy rather than a named
#: vendor shape. Reported at a lower severity: a high-entropy
#: string in minified JavaScript is very often a hash, a sourcemap
#: fragment or a minified identifier, and treating those as equal
#: to an AWS key is how a report becomes unreadable.
_ENTROPY_TYPES = ("Base64 High Entropy String", "Hex High Entropy String")


#: Minimum length for anything we will call a credential.
#:
#: Measured, not guessed: the first production run flagged the
#: literal `true` (4 characters) and a run of Windows HRESULT codes
#: like `8004341E` (8). Nothing issued as a credential is this
#: short -- the shortest real API keys are around 16 -- so this one
#: rule removes a whole class without touching anything real.
MIN_SECRET_LEN = 12

#: Values that are never a credential whatever a detector says.
_NOT_SECRETS = frozenset({
    "true", "false", "null", "undefined", "nan", "none", "nil",
    "password", "secret", "token", "changeme", "example", "test",
    "placeholder", "redacted", "xxxxxxxx", "your_api_key_here",
})

#: A Windows HRESULT: `0x8......` written bare. `Constants.js` in a
#: Microsoft login bundle is full of them and detect-secrets reads
#: every one as a keyword-assigned secret.
_HRESULT = re.compile(r"^8[0-9A-Fa-f]{7}$")

#: A hex string of exactly the same length, over and over, is a
#: generated identifier -- a build id, a flight id, a resource
#: hash. 42 of the first 43 entropy findings on the estate were
#: 20-character lowercase hex from one Microsoft bundle.
_UNIFORM_HEX = re.compile(r"^[0-9a-f]{16,24}$")

#: Bare hex at exactly a digest's length: MD5, SHA-1, SHA-256.
#:
#: The same argument as `_UNIFORM_HEX` at the lengths that actually
#: dominate. 2,479 of 3,365 findings on the estate were these, and
#: 2,278 came from one file: `elliptic.min.js`, whose 64-character
#: constants are the secp256k1 curve parameters --
#: `79be667ef9dcbbac...` is the generator point Gx, a published
#: value in every implementation of that curve. Public by
#: definition, and reported 2,278 times.
#:
#: Entropy detectors ONLY, like `_UNIFORM_HEX`. A named vendor
#: pattern matching a hex string means an issuer's shape was
#: recognised, which is evidence; entropy matching one means only
#: that hex is varied, which every digest also satisfies.
#:
#: What this gives up: a 256-bit key written as bare hex looks
#: exactly like a SHA-256 of nothing in particular, and this drops
#: it. That is the trade -- and it is the right way round, because
#: on measured data the hash outnumbers the key by better than a
#: thousand to one, and a reviewer who cannot see past 2,479 curve
#: constants will not find the one key either.
_DIGEST_HEX = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")

#: ASP.NET Core Data Protection, which is what `CfDJ8` prefixes.
#:
#: Antiforgery tokens, encrypted cookies and the like: issued to
#: the browser on purpose, rotated per request or per session, and
#: useless to anyone without the server's key ring. 134 on the
#: estate, all distinct, all of them a new "secret" on every sweep.
_ASPNET_DP = re.compile(r"^CfDJ8[A-Za-z0-9_\-]{20,}$")

#: Subresource Integrity, as written in a `integrity=` attribute.
#:
#: Published ON PURPOSE: the whole point of SRI is that the page
#: tells the browser, in public, what hash the asset must have.
#: Reporting one as a leaked secret is reporting a thing designed
#: to be read.
_SRI = re.compile(r"^sha(?:256|384|512)-")

#: A reCAPTCHA or hCaptcha SITE key, which is also public by
#: design -- it is rendered into the markup so the widget can
#: load. The half that matters is the secret key, which stays on
#: the server and never appears in an asset we fetched.
#:
#: Google's site keys are `6L` followed by 38 base64url
#: characters; hCaptcha's are a UUID, which `_UNIFORM_HEX` does
#: not reach and detect-secrets' own `is_potential_uuid` already
#: removes.
_CAPTCHA_SITE_KEY = re.compile(r"^6L[A-Za-z0-9_-]{38}$")

#: A build number joined to a content digest: `1456_<22 chars>`.
#:
#: The 22 characters after the underscore are exactly a base64url
#: 128-bit digest -- 16 bytes is 22 unpadded characters, and every
#: one of the 25 on the estate was that length to the character.
#: A decimal build number prefixed to a content hash is a
#: cache-busting scheme; no issuer emits a credential in that
#: shape. Anchored to 22 rather than a range so it stays a
#: statement about digests and not a catch-all for anything with
#: an underscore in it.
_CACHEBUSTER = re.compile(r"^\d{3,6}_[A-Za-z0-9_-]{22}$")

#: Every character different, over a long string: a codec table,
#: not a key.
#:
#: This is the birthday bound rather than a pattern. A generated
#: 32-character credential drawn from a 64-character alphabet
#: repeats some character with probability ~0.9996; all-distinct
#: happens about four times in ten thousand. An alphabet constant
#: -- `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef…+/=`, which is what nine
#: of these were -- is all-distinct by construction, because that
#: is what makes it an alphabet.
MIN_ALPHABET_LEN = 32


def shannon(value: str) -> float:
    """Bits of entropy per character. Low means structured."""
    if not value:
        return 0.0
    import math
    n = len(value)
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


#: Below this, a keyword-matched value is a word rather than a key.
#:
#: Measured on the estate's own false positives: the survivors of
#: the first pass were English UI strings out of a localisation
#: bundle ("The password you entered...") and telemetry event names
#: (`eOTT_OneTimeCode`). Both are structured text and score well
#: under this; a generated credential scores above it because that
#: is what makes it a credential.
MIN_KEYWORD_ENTROPY = 3.2

#: Longest a high-entropy string can be and still be a credential.
#:
#: Measured on 1,498 entropy findings from a live estate: 163 were
#: over 200 characters and the commonest single length was 452 --
#: inline source-map fragments, base64 fonts and data URIs. Nothing
#: is ISSUED at that size. JWTs are the one long credential and they
#: have their own detector and an `eyJ` prefix, so they do not come
#: through here.
MAX_ENTROPY_LEN = 200

#: How many entropy hits one file may produce before none of them is
#: credible.
#:
#: A file holding fifty high-entropy strings is a file full of
#: generated data, not a file with a secret in it. A real leaked
#: credential is one or two in a file.
#:
#: Twelve because of where the real distribution falls, not because
#: it is a round number: across the same estate the per-file counts
#: were 311, 5, 4, 3, 3, 3, 3, 3, 2, 2 and nine files with 1. There
#: is nothing at all between 5 and 311, so any cap in that gap
#: separates the blob from the rest, and a low one leaves no room
#: for a file that genuinely holds a handful.
MAX_ENTROPY_PER_FILE = 12

#: A bare `www.`/host-looking string with a path. Caught separately
#: from `://` because minified code frequently holds the scheme and
#: the host as two literals.
_URLISH = re.compile(r"^(?:https?|ftp|wss?):", re.I)

#: Characters that join words into a name. Not `:`; a colon has its
#: own meanings and the underscore run is enough to recognise the
#: shape without it.
_WORD_JOINERS = re.compile(r"[-_.]+")


def _compound_identifier(v: str) -> bool:
    """Is this words joined by separators rather than a generated value?

    `ForeignTaxResidency_Investorsummary_Deceased_Message_YES_WARNING`
    is a message constant. `Notification-sc-1ok6jey-0.gigMLv.Pending`
    is a resource key. Both have respectable entropy, both contain a
    credential-ish word somewhere, and neither is a secret.

    The test is structural: split on the joiners, and ask how many
    pieces are PURELY alphabetic and long enough to be a word. A
    generated token has none -- base64 and hex both mix digits
    through every segment -- while a name made of words has several.

    Deliberately requires three segments and two words. Two is the
    shape of a real prefixed credential (`sk_live_...`, `ghp_...`),
    where exactly one segment is a word and the rest is the value.

    **The trade, said plainly:** a passphrase-style secret —
    `correct-horse-battery-staple` — is this shape and would be
    dropped. That is a real cost. It is worth paying because on the
    estate this was measured against, the shape appeared 1,498 times
    and was a credential none of them.
    """
    if not v:
        return False
    parts = [p for p in _WORD_JOINERS.split(v) if p]
    if len(parts) < 3:
        return False
    words = [p for p in parts if len(p) >= 3 and p.isalpha()]
    return len(words) >= 2


def implausible_secret(value: str, detector: str) -> str | None:
    """-> why this is not a credential, or None if it might be.

    Deliberately conservative about the entropy detectors and
    permissive about the named ones: a vendor regex matching means
    the string has an issuer's shape, which is evidence. Entropy
    only means the characters are varied, which a hash satisfies
    just as well as a key.
    """
    v = (value or "").strip()
    if not v:
        return "empty"
    if len(v) < MIN_SECRET_LEN:
        return f"too short to be a credential ({len(v)} characters)"
    if v.lower() in _NOT_SECRETS:
        return "a literal, not a value"
    if _HRESULT.match(v):
        return "a Windows HRESULT error code, not a credential"
    # The next four are about what the string IS, so they hold
    # whichever detector produced it: a published hash is published
    # whether entropy or a keyword found it.
    if _SRI.match(v):
        return "a Subresource Integrity hash, which is published on purpose"
    if _CAPTCHA_SITE_KEY.match(v):
        return "a CAPTCHA site key, which is public by design"
    if _CACHEBUSTER.match(v):
        return "a build number and a content digest -- a cache-buster"
    if len(v) >= MIN_ALPHABET_LEN and len(set(v)) == len(v):
        return (f"{len(v)} characters with no repeat -- an alphabet "
                f"table rather than a generated value")
    # Nothing issued as a credential contains whitespace. This one
    # rule removes the whole class of English prose that a keyword
    # detector picks up from a localisation file -- `password: "The
    # password you entered is incorrect"` is a message ABOUT a
    # password, which is exactly what the keyword matched on.
    if any(ch.isspace() for ch in v):
        return "contains whitespace, so it is prose rather than a value"
    # A keyword match only says a credential-ish WORD was nearby;
    # the value still has to look generated. See the note on
    # MIN_KEYWORD_ENTROPY for what this does and does not catch.
    if detector not in _ENTROPY_TYPES:
        e = shannon(v)
        if e < MIN_KEYWORD_ENTROPY:
            return (f"too structured to be generated "
                    f"({e:.1f} bits/char) — an identifier or a message")
        # No digits at all. Issued credentials essentially always
        # mix them in; a run of words joined by underscores is a
        # symbol somebody typed. On the estate this separated
        # `eOTT_OneTimePassword` and `eOTT_NoPasswordAccountLogin`
        # -- telemetry event names -- from a base64 JWT that has
        # digits throughout and is worth looking at.
        if not any(ch.isdigit() for ch in v):
            return "no digits, so an identifier rather than a key"
    # Only for the entropy detectors. A named vendor shape that
    # happens to be hex is still a vendor shape.
    if detector in _ENTROPY_TYPES and _UNIFORM_HEX.match(v):
        return ("a fixed-length hex identifier -- a build or telemetry "
                "id rather than a credential")
    if detector in _ENTROPY_TYPES and _DIGEST_HEX.match(v):
        return (f"bare hex at exactly a digest's length ({len(v)} "
                f"characters) -- a hash or a published constant")
    if _ASPNET_DP.match(v):
        return ("an ASP.NET Data Protection token -- issued to the "
                "browser on purpose and rotated per request")
    # A URL is not a credential. It may CARRY one in a query
    # parameter, and that parameter is its own finding with its own
    # value; the whole URL is a location. `\/` because the detector
    # reads string literals out of JavaScript, where a URL arrives
    # JSON-escaped.
    if "://" in v or ":\\/\\/" in v or _URLISH.match(v):
        return "a URL, which is a location rather than a credential"
    # Likewise a path. A beacon or CDN path is slash-separated
    # base64-looking junk and reads exactly like a token to a
    # detector that only sees characters.
    if v.startswith("/") and v.count("/") >= 3:
        return "a URL path, not a credential"
    if _compound_identifier(v):
        return ("separator-joined words -- a resource key, message "
                "constant or config name rather than a generated value")
    # Only for entropy. A vendor shape this long would be a vendor
    # shape and is somebody else's problem to be wrong about.
    if detector in _ENTROPY_TYPES and len(v) > MAX_ENTROPY_LEN:
        return (f"{len(v)} characters -- too long to be an issued "
                f"credential; at this size it is a source-map fragment, "
                f"an embedded font or a data URI")
    return None


def scan_detect_secrets(path: str, body: str,
                        limit: int = MAX_PER_FILE) -> list[Finding]:
    """Yelp's detect-secrets over one file's text.

    In-process, because it is a Python library and this is a Python
    runtime -- no subprocess, no binary, no network. It carries
    both halves of the job: named vendor regexes AND Shannon
    entropy over string literals, which is what catches a
    credential belonging to no issuer we have a pattern for.

    The secret itself is kept out of the finding: what the row
    carries is the detector, the line, and a hash.
    """
    out: list[Finding] = []
    try:
        import tempfile

        from detect_secrets.core import scan as ds_scan
        from detect_secrets.settings import default_settings
    except Exception as e:                             # noqa: BLE001
        log.warning("assetscan: detect-secrets unavailable (%s)", e)
        return out

    try:
        with tempfile.TemporaryDirectory(prefix="oddjob-ds-") as d:
            import os as _os
            fp = _os.path.join(d, "subject" + (_os.path.splitext(path)[1][:8]
                                               or ".txt"))
            with open(fp, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(body)
            with default_settings():
                for sec in ds_scan.scan_file(fp):
                    kind = str(sec.type)
                    entropy = kind in _ENTROPY_TYPES
                    why = implausible_secret(
                        getattr(sec, "secret_value", "") or "", kind)
                    if why:
                        # Dropped, not downgraded. A finding that is
                        # definitely not a credential is not a weak
                        # finding, it is noise, and the operator
                        # reviewing 182 of these found every one a
                        # false positive.
                        log.debug("assetscan: dropped %s in %s: %s",
                                  kind, path, why)
                        continue
                    out.append(Finding(
                        scanner="detect-secrets", rule=kind,
                        title=f"{kind} in {path}"[:1000],
                        severity="low" if entropy else "high",
                        path=path, line=sec.line_number,
                        detail=(
                            f"Detector: {kind}. "
                            + ("Found by entropy, not by a known credential "
                               "shape -- minified JavaScript contains a lot "
                               "of high-entropy text that is not a secret, "
                               "so this needs an eye on it. "
                               if entropy else
                               "Matches a known credential shape. ")
                            + "The full value is stored against this "
                              "finding and is shown by the Reveal button, "
                              "which is recorded in the audit log.")[:4000],
                        # On the secret's own hash, which
                        # detect-secrets already computes, so the
                        # same credential is one finding across
                        # files and sweeps and the value is never
                        # written down.
                        fingerprint=fingerprint("detect-secrets", kind,
                                                sec.secret_hash),
                        # detect-secrets keeps the value on the
                        # object; `secret_hash` is what it reports
                        # by default, and the raw string is here.
                        secret=getattr(sec, "secret_value", None)))
                    if len(out) >= limit:
                        break
    except Exception as e:                             # noqa: BLE001
        # Never fatal: a scanner that fell over has examined
        # nothing, and the caller reports that rather than treating
        # it as a clean file.
        log.warning("assetscan: detect-secrets failed on %s (%s)", path, e)
    return _drop_entropy_blobs(path, out)


def _drop_entropy_blobs(path: str, found: list[Finding]) -> list[Finding]:
    """A file full of high-entropy strings has no secret in it.

    It is a sprite sheet, a font, a source map, a wordlist or a
    table of generated ids. A real leaked credential is one or two
    in a file; three hundred is the file's nature rather than a
    mistake somebody made.

    Applied per FILE and only to the entropy detectors. A file with
    forty AWS keys in it is a different thing entirely and every one
    of them is kept.
    """
    entropy = [f for f in found if f.rule in _ENTROPY_TYPES]
    if len(entropy) <= MAX_ENTROPY_PER_FILE:
        return found
    # Said at info, not debug. Dropping 311 findings from one file
    # is a decision somebody may want to disagree with, and it
    # should be possible to find out that it happened.
    log.info("assetscan: %s produced %d high-entropy strings, which is a "
             "generated file rather than a leak; all of them dropped",
             path, len(entropy))
    return [f for f in found if f.rule not in _ENTROPY_TYPES]


def available() -> dict[str, bool]:
    """Which scanners are actually present.

    Reported rather than assumed. A sweep that runs with a scanner
    missing has not proved a file has no secrets in it -- it has
    proved nothing -- and the caller has to be able to say so.

    This is not theoretical. trufflehog shipped in the image, was
    deleted from the running container by something outside this
    codebase, and this function answered False for weeks while the
    sweep reported clean files.
    """
    try:
        import detect_secrets  # noqa: F401
        ds = True
    except Exception:                                  # noqa: BLE001
        ds = False
    return {
        "opengrep": bool(shutil.which(OPENGREP) or os.path.exists(OPENGREP)),
        "detect-secrets": ds,
    }


def redact(secret: str) -> str:
    """`sk-ant-api03-abcdef...` -> `sk…ef` plus a length.

    Enough to tell two findings apart by eye; not enough to use. The
    length is included because it is often the quickest way to
    recognise which kind of credential it is without holding one.
    """
    s = (secret or "").strip()
    if not s:
        return "(empty)"
    if len(s) <= 6:
        return f"…({len(s)} chars)"
    return f"{s[:2]}…{s[-2:]} ({len(s)} chars)"


def fingerprint(*parts: object) -> str:
    """A stable id for a finding, without storing what it found."""
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8", "replace"))
        h.update(b"\x00")
    return h.hexdigest()[:32]


def _rule_name(check_id: str) -> str:
    """`opt.opengrep-rules.javascript.lang.security.eval` -> the last part.

    opengrep derives `check_id` from the path of the config it was
    given, so pointing it at /opt/opengrep-rules/javascript puts the
    whole filesystem path into every rule name -- and from there into
    the title of every finding, which is what a client reads. The
    rule's own name is what identifies it; where our container
    happens to keep the file is not.
    """
    s = (check_id or "").strip()
    for prefix in ("opt.opengrep-rules.", "opt.opengrep_rules."):
        if s.startswith(prefix):
            return s[len(prefix):]
    return s


def parse_opengrep(raw: str, path: str) -> list[Finding]:
    """opengrep `--json` output -> findings.

    Tolerant: a scanner that changes its output shape must degrade
    to "found nothing I could read", loudly, rather than crashing a
    sweep halfway through a project.
    """
    out: list[Finding] = []
    try:
        doc = json.loads(raw or "{}")
    except ValueError:
        log.warning("assetscan: opengrep output for %s was not JSON", path)
        return out
    for r in (doc.get("results") or [])[:MAX_PER_FILE]:
        check = _rule_name(str(r.get("check_id") or "rule"))
        extra = r.get("extra") or {}
        sev = _SEV.get(str(extra.get("severity") or "").upper(), "info")
        line = ((r.get("start") or {}).get("line"))
        msg = str(extra.get("message") or check).strip()
        # The path opengrep REPORTED, falling back to the caller's.
        # A batch scans many files in one run, so the caller cannot
        # know which file a result belongs to -- it passes "" and
        # reads this. Taking the argument instead meant every
        # finding came back with an empty path, failed to map to a
        # file, and was silently dropped: the scanners ran, found
        # things, and the sweep recorded nothing.
        where = str(r.get("path") or "") or path
        out.append(Finding(
            scanner="opengrep", rule=check,
            title=f"{check} in {where}"[:1000],
            severity=sev, path=where,
            line=int(line) if isinstance(line, int) else None,
            detail=msg[:4000],
            fingerprint=fingerprint("opengrep", check, path, line)))
    return out


async def _run(argv: list[str], stdin: bytes,
               env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Exec a scanner. Argument list, never a shell string.

    The runtime image has no shell at all, so a shell string would
    not merely be unsafe, it would not run -- and the inputs here
    include filenames taken from a source map, which is
    attacker-influenced text.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **(env or {})})
    try:
        so, se = await asyncio.wait_for(proc.communicate(stdin),
                                        timeout=TIMEOUT)
    except TimeoutError:
        proc.kill()
        return -1, "", "timed out"
    return (proc.returncode or 0,
            so.decode("utf-8", "replace"), se.decode("utf-8", "replace"))
