"""What a scan was configured to look for, as a comparable identity.

`app/lifecycle.py` can say a finding was resolved: a tool that
reports this kind of thing looked at the host again and did not
report it. That claim has a hole in it, and this closes it.

    nuclei -severity critical,high      found CVE-2021-44228
    nuclei -severity critical           did not

The second run is not evidence the first finding is gone. It was
configured not to look. Same tool, same host, later timestamp,
and `resolved` would have been said out loud.

The same applies to a gobuster run against a shorter wordlist, an
nmap over a narrower port range, and a nuclei whose templates were
updated between runs. In every case the absence is a fact about the
configuration, not about the client's estate.

# What goes in the manifest, and what does not

Only what changes WHAT CAN BE FOUND.

    in    the template filters, the script categories, the port
          range, the wordlist, the severity floor
    out   concurrency, rate limits, timeouts, retries, output
          format, the User-Agent

A rate limit changes how long a scan takes and how it looks from
the far end. It does not change which findings the run is capable
of reporting, and putting it in the manifest would make every
engagement that tuned its pacing incomparable with itself.

This is the difference between a manifest and a command line, and
it is the whole reason this is a curated projection rather than
`sha256(argv)`.

# Three answers, again

Comparing two manifests gives three results and not two:

    same        the run that cleared it looked for the same things
    different   it did not, and we know that
    unknown     one side or the other recorded no configuration

`unknown` is the state of every scan imported before this existed
and of every file a person uploads by hand, and it is not the same
as `different`. See `lifecycle.verdict`, which reports a weaker
`resolved` for the first and refuses to resolve at all for the
second.
"""
from __future__ import annotations

import hashlib
import json
import shlex

#: Per tool, the arguments that select WHAT is looked for.
#:
#: A flag absent from its tool's set is dropped, which is the
#: decision this file exists to make: `-rate 1000` and `-c 50` do
#: not belong in an identity that two runs are compared on.
#:
#: Each entry maps the flag to the number of VALUES it takes. 0 is a
#: switch whose presence is itself a selection -- `-sU` adds UDP
#: ports to what a scan can find.
SELECTORS: dict[str, dict[str, int]] = {
    "nmap": {
        "-p": 1, "--ports": 1, "--top-ports": 1,
        "--script": 1, "--script-args": 1,
        # Each adds a protocol or a technique, and therefore a class
        # of finding the run can report.
        "-sU": 0, "-sS": 0, "-sT": 0, "-sV": 0, "-sC": 0, "-A": 0,
        "-O": 0, "-6": 0,
        "--version-intensity": 1, "--version-all": 0, "--version-light": 0,
    },
    "nuclei": {
        "-severity": 1, "-s": 1,
        "-tags": 1, "-etags": 1, "-exclude-tags": 1,
        "-t": 1, "-templates": 1, "-template-id": 1, "-id": 1,
        "-exclude-templates": 1, "-et": 1,
        "-protocol-type": 1, "-type": 1,
        "-include-tags": 1, "-itags": 1,
        # Changes the corpus wholesale.
        "-new-templates": 0, "-automatic-scan": 0,
    },
    "masscan": {"-p": 1, "--ports": 1, "--top-ports": 1},
    "gobuster": {"-w": 1, "--wordlist": 1, "-x": 1, "--extensions": 1,
                 "-s": 1, "--status-codes": 1},
    "httpx": {"-ports": 1, "-p": 1, "-path": 1, "-paths": 1},
    "katana": {"-depth": 1, "-d": 1, "-jc": 0, "-js-crawl": 0,
               "-kf": 1, "-known-files": 1},
}

#: Flags that look like selectors and are not. Listed explicitly so
#: that a reader of SELECTORS can see what was considered and
#: rejected, rather than inferring it from an absence.
NOT_SELECTORS = (
    "-rate", "-c", "-concurrency", "-timeout", "-retries", "-bs",
    "--min-rate", "--max-rate", "-T0", "-T1", "-T2", "-T3", "-T4",
    "-T5", "-o", "-oJ", "-oX", "-json", "-silent", "-H", "-proxy",
)


def _tokens(args: str | None) -> list[str]:
    """A command line, split the way a shell would. Never run."""
    if not args:
        return []
    try:
        return shlex.split(args)
    except ValueError:
        # An unbalanced quote. Whitespace is a worse split but it is
        # better than discarding the configuration entirely, and
        # anything derived from it is only ever compared to itself.
        return args.split()


def selectors(tool: str, args: str | None) -> dict[str, str]:
    """The selection-relevant part of one command line.

    -> {flag: value}, where a switch has the value "". Unknown flags
    are dropped, as is everything positional: a target is not part
    of what the run looked FOR.
    """
    table = SELECTORS.get((tool or "").strip().lower())
    if not table:
        return {}
    toks, out = _tokens(args), {}
    i = 0
    while i < len(toks):
        t = toks[i]
        # `-severity=high` as well as `-severity high`.
        if "=" in t and t.startswith("-"):
            flag, _, val = t.partition("=")
            if flag in table:
                out[flag] = val
            i += 1
            continue
        takes = table.get(t)
        if takes is None:
            i += 1
            continue
        if takes == 0:
            out[t] = ""
            i += 1
            continue
        out[t] = toks[i + 1] if i + 1 < len(toks) else ""
        i += 2
    return out


def _canonical(d: dict) -> str:
    """Stable text for a dict, so the hash does not depend on order.

    Values are normalised too: `-severity critical,high` and
    `-severity high,critical` select the same templates and must not
    produce two identities.
    """
    out = {}
    for k, v in sorted(d.items()):
        s = str(v).strip()
        if "," in s:
            s = ",".join(sorted(p.strip() for p in s.split(",") if p.strip()))
        out[k] = s
    return json.dumps(out, sort_keys=True, separators=(",", ":"))


def digest(text: str | None) -> str:
    """A short, stable id for a blob -- a wordlist, a template set.

    Short because it goes in a column and is only ever compared for
    equality; nothing here needs collision resistance against an
    adversary, and a 64-character hash in a debug line nobody can
    read is its own cost.
    """
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


def build(tool: str, args: str | None = None,
          extra: dict | None = None) -> tuple[str, dict]:
    """-> (hash, what went into it).

    The detail is returned and stored alongside, because a hash that
    cannot be explained is a hash nobody will trust when it says two
    runs differ. "Configuration changed" is only actionable if
    somebody can see WHICH part.
    """
    parts: dict = {"tool": (tool or "").strip().lower()}
    parts.update(selectors(tool, args))
    for k, v in sorted((extra or {}).items()):
        if v not in (None, ""):
            parts[k] = str(v)
    return hashlib.sha256(
        _canonical(parts).encode()).hexdigest()[:32], parts


def differences(a: dict | None, b: dict | None) -> list[str]:
    """What changed between two manifests, in words.

    Used only to explain a refusal. The decision itself is the hash
    comparison -- deriving it from this would mean two ways of
    answering one question, which is how they come to disagree.
    """
    a, b = a or {}, b or {}
    out = []
    for k in sorted(set(a) | set(b)):
        if a.get(k) == b.get(k):
            continue
        was, now = a.get(k), b.get(k)
        if was is None:
            out.append(f"{k} {now!r} was added")
        elif now is None:
            out.append(f"{k} {was!r} was dropped")
        else:
            out.append(f"{k}: {was!r} -> {now!r}")
    return out
