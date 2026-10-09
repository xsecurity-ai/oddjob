"""What has actually been scanned on a port, and what that makes redundant.

An operator who scans a host with `-sS` and later asks for `-sV` wants
the `-sV`: the first scan learned that the port answers, the second
learns what is behind it. An operator who scans with `-sV` and later
asks for `-sS` wants nothing -- the question `-sS` asks has already
been answered, with more besides. Re-running it is packets at a
client's estate that buy no information.

So techniques are ranked, and a request is skipped where an
equal-or-stronger one has already covered that port:

    syn      (-sS)  the port answered a half-open probe
    connect  (-sT)  a full handshake completed, so something accepted it
    version  (-sV)  the service was interrogated and identified

Each step is strictly more than the one above it, which is what makes
the order a total one and the rule simple:

    done -sS, want -sT  ->  run it     (a handshake was never completed)
    done -sT, want -sV  ->  run it     (nothing was ever identified)
    done -sT, want -sS  ->  skip
    done -sV, want -sS  ->  skip
    done -sV, want -sT  ->  skip

# Why coverage is not read off the services table

A `Service` row exists only where something was found. A scan of
1-65535 that finds one open port leaves one row, and "was 8080 ever
looked at?" is then unanswerable -- absent and closed look identical.
Coverage has to record what was *attempted*, which is why it is stored
as the port ranges a scan covered rather than as the ports it found.

Ranges, not one row per port: a full TCP scan of one host is otherwise
65,535 rows per technique.

# Why the technique comes from the scan output, not the request

Asking nmap for `-sS` without raw sockets gets a connect scan. nmap
says so in its own XML -- `<scaninfo type="connect">` -- and does not
error. Recording the request would therefore record a syn scan that
never happened.

Getting that backwards in the safe direction is merely wasteful: if a
connect scan is recorded as `syn`, a later `-sT` runs again
needlessly. Getting it backwards the other way is the one that costs
something real, because a `-sT` that never happened would be skipped
forever. So where the evidence is ambiguous this module records the
WEAKER technique.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Ranked weakest to strongest. The value is the whole ordering; the
#: name is what is stored, because a stored integer would be unreadable
#: in the database and would silently shift if a level were inserted.
LEVELS: dict[str, int] = {"syn": 1, "connect": 2, "version": 3}

#: nmap's `<scaninfo type=...>` vocabulary, mapped to ours. Only the
#: TCP techniques that tell us a port is reachable are here.
#:
#: `ack` and `window` are deliberately absent: they map firewall rules
#: rather than services, so an ACK scan reaching a port establishes
#: nothing about whether anything is listening and must not suppress a
#: later -sS.
SCANINFO_TYPES: dict[str, str] = {
    "syn": "syn",
    "connect": "connect",
}


def rank(technique: str) -> int:
    """Strength of a technique, 0 for anything unrecognised.

    Zero rather than an exception: an nmap version that invents a new
    scan type should leave coverage unchanged, not stop an import of
    results that are otherwise fine.
    """
    return LEVELS.get(technique, 0)


def subsumes(done: str, want: str) -> bool:
    """Does having run `done` make `want` redundant on the same port?"""
    d, w = rank(done), rank(want)
    return d > 0 and w > 0 and d >= w


def technique_from_scan(scaninfo_type: str | None, args: str | None) -> str | None:
    """What a scan actually did, from nmap's own record of it.

    `scaninfo_type` is `<scaninfo type=>`; `args` is the command line
    nmap reports in `<nmaprun args=>`. The type decides how the port
    was reached and `-sV` in the arguments promotes it, because version
    detection is layered on top of a syn or connect scan rather than
    being a scan type of its own.

    Returns None when nothing recognisable ran, which leaves coverage
    untouched.
    """
    base = SCANINFO_TYPES.get((scaninfo_type or "").strip().lower())
    if base is None:
        return None
    if _has_flag(args, "-sV"):
        return "version"
    return base


def _has_flag(args: str | None, flag: str) -> bool:
    """Is `flag` a whole token in the command line?

    Tokenised rather than `in`: `-sV` is a substring of `-sVersion`-ish
    nonsense and, more plausibly, of a file path in `-oX`. A false
    positive here records a version scan that never happened and
    suppresses a real one for good.
    """
    return bool(args) and flag in args.split()


@dataclass(frozen=True)
class Range:
    """A closed port range that one technique covered."""

    technique: str
    lo: int
    hi: int

    def contains(self, port: int) -> bool:
        return self.lo <= port <= self.hi


def parse_ports(spec: str | None) -> list[tuple[int, int]]:
    """Read nmap's `<scaninfo services=>` list into ranges.

    The format is `22,80,8000-8100`. Returned merged and sorted, so
    coverage of `1-100,50-200` is stored as one range rather than two
    overlapping ones that every later query has to reconcile.

    Unreadable fragments are skipped rather than raising: a coverage
    record is an optimisation, and failing an import of real scan
    results over a malformed port list would be the wrong trade.
    """
    out: list[tuple[int, int]] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        lo_s, _, hi_s = part.partition("-")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
        except ValueError:
            continue
        if lo > hi:
            lo, hi = hi, lo
        lo, hi = max(1, lo), min(65535, hi)
        if lo <= hi:
            out.append((lo, hi))
    return merge(out)


def merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and coalesce, joining ranges that touch as well as overlap.

    `1-79` and `80-100` become `1-100`: they are contiguous in a space
    of integers, and leaving them separate would make a later
    "is 1-100 fully covered" check answer no.
    """
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def covered(existing: list[Range], port: int, want: str) -> bool:
    """Has `port` already been covered by `want` or something stronger?"""
    return any(r.contains(port) and subsumes(r.technique, want) for r in existing)


def needed(ports: list[int], existing: list[Range], want: str) -> list[int]:
    """Which of `ports` still need `want` running against them.

    The whole point of the module, in one call: hand it the ports an
    operator asked to scan and what is already known about the host,
    and it returns the subset that would actually learn something.
    """
    return [p for p in ports if not covered(existing, p, want)]


def expand(ranges: list[tuple[int, int]], cap: int = 65535) -> list[int]:
    """Ranges to individual ports, for callers that need the list.

    Bounded by `cap` so a caller that hands in `1-65535` and iterates
    cannot be surprised; the range form is the one to prefer.
    """
    out: list[int] = []
    for lo, hi in ranges:
        for p in range(lo, min(hi, cap) + 1):
            out.append(p)
            if len(out) >= cap:
                return out
    return out
