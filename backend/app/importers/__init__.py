"""Scanner and C2 output importers.

Each module turns one tool's output into the shared IR in `model.py`; the
ingest path in `routers/scans.py` is written once against that IR.

`detect()` sniffs a document so a caller can hand over a file without also
having to say what produced it — operators have directories full of mixed
output, and making them classify each one by hand is how the wrong parser
gets pointed at the wrong file.
"""
from __future__ import annotations

from . import burp, burphistory, c2, httpx_json, masscan, metasploit, nessus, nikto, nmap, nuclei
from .model import (
    ImportError_,
    ParsedCredential,
    ParsedHost,
    ParsedImplant,
    ParsedNote,
    ParsedScan,
    ParsedService,
    ParsedVuln,
)

#: The IR types are re-exported here on purpose: a caller writing against
#: importers should not have to know the dataclasses live one module down.
#: Named explicitly so they read as the package's surface rather than as
#: imports nothing in this file happens to use.
__all__ = [
    "ORDER",
    "REGISTRY",
    "STREAMABLE",
    "ImportError_",
    "ParsedCredential",
    "ParsedHost",
    "ParsedImplant",
    "ParsedNote",
    "ParsedScan",
    "ParsedService",
    "ParsedVuln",
    "detect",
    "detect_file",
    "parse",
    "streamer",
    "unknown_format_message",
]

#: name -> (label, parse(text) -> ParsedScan)
REGISTRY = {
    "nmap":        ("nmap XML (-oX)", nmap.parse),
    "masscan":     ("masscan XML/JSON/list", masscan.parse),
    "nessus":      ("Nessus .nessus (v2)", nessus.parse),
    "metasploit":  ("Metasploit db_export -f xml", metasploit.parse),
    "burphistory": ("Burp proxy HTTP history (Save items)", burphistory.parse),
    "burp":        ("Burp Suite issue XML", burp.parse),
    "nikto":       ("Nikto JSON or XML", nikto.parse),
    "nuclei":      ("Nuclei JSONL (-jsonl)", nuclei.parse),
    "httpx":       ("httpx JSONL (-json)", httpx_json.parse),
    "cobaltstrike": ("Cobalt Strike beacons", c2.parse_cobaltstrike),
    "mythic":      ("Mythic callbacks", c2.parse_mythic),
    "merlin":      ("Merlin agents", c2.parse_merlin),
    "sliver":      ("Sliver sessions/beacons", c2.parse_sliver),
    "havoc":       ("Havoc demons", c2.parse_havoc),
}

ORDER = list(REGISTRY)


def detect(text: str) -> str | None:
    """Best guess at which importer handles `text`, or None.

    Checked most-specific first. Returning None is a real answer: guessing
    wrong produces a confident import of nonsense, which is worse than
    asking the caller which tool it came from.
    """
    for name in ORDER:
        mod_detect = _DETECTORS.get(name)
        if mod_detect and mod_detect(text):
            return name
    return None


_DETECTORS = {
    "nmap": nmap.looks_like,
    "masscan": masscan.looks_like,
    "nessus": nessus.looks_like,
    "metasploit": metasploit.looks_like,
    "burphistory": burphistory.looks_like,
    "burp": burp.looks_like,
    "nikto": nikto.looks_like,
    "nuclei": nuclei.looks_like,
    "httpx": httpx_json.looks_like,
    "cobaltstrike": c2.looks_like_cobaltstrike,
    "mythic": c2.looks_like_mythic,
    "merlin": c2.looks_like_merlin,
    "sliver": c2.looks_like_sliver,
    "havoc": c2.looks_like_havoc,
}


def parse(text: str, fmt: str = "auto") -> tuple[str, ParsedScan]:
    """-> (format name, ParsedScan). Raises ImportError_ on a bad document."""
    if fmt in ("", "auto", None):
        found = detect(text)
        if not found:
            raise ImportError_(unknown_format_message())
        fmt = found
    if fmt not in REGISTRY:
        raise ImportError_(f"unknown format {fmt!r}. Supported: {', '.join(REGISTRY)}")
    return fmt, REGISTRY[fmt][1](text)


#: Formats that can be read from a file a chunk at a time instead of
#: being loaded whole. Only worth doing where the document is a long
#: flat list of records -- a Burp history is 357k `<item>`s, while an
#: nmap run is a few thousand hosts and fits in memory comfortably.
#:
#: `stream(path, chunk)` yields ParsedScan pieces; `hosts(path)` returns
#: {host: count} cheaply, for the strict-mode survey.
STREAMABLE = {
    "burphistory": (burphistory.stream, burphistory.hosts_in),
    "burp": (burp.stream, burp.hosts_in),
}


def detect_file(path: str) -> str | None:
    """Detect the format of a file without reading all of it."""
    from .safexml import peek
    return detect(peek(path, 8192))


def streamer(fmt: str):
    """-> (stream, hosts) for `fmt`, or None if it must be read whole."""
    return STREAMABLE.get(fmt)


def unknown_format_message() -> str:
    """The 'what is this file' error, in one place.

    It was written out at each call site, so a new importer appeared in
    some of the lists and not others.
    """
    return ("could not tell what produced this. Supported: "
            + ", ".join(f"{k} ({v[0]})" for k, v in REGISTRY.items()))
