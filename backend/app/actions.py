"""Action runners — the seam where real probes get plugged in.

Each entry in RUNNERS takes a Service (plus its host) and returns a Result.
Adding nmap later means replacing one function body; nothing else moves.

                        *** SAFETY INTERLOCK ***

Every runner here is an ACTIVE PROBE: it sends packets to a host that belongs
to someone else. Two things gate that, and both are deliberate:

  1. ODDJOB_ALLOW_ACTIVE_PROBES must be explicitly true. Default off, so a
     fresh deployment cannot touch anything just because somebody clicked a
     button in a UI they were exploring.
  2. is_in_scope() must pass. It is a stub that currently refuses everything,
     because this app has no scope document. Whoever wires nmap in must also
     wire this to the real gate — in the ACME repo that is
     `scripts/intake/gate.py: assert_testable(host)`.

Returning "unavailable" rather than probing is the correct behaviour until
both are satisfied. An unconfigured install that quietly port-scans a client
estate because a grid had a button on it is the failure mode being designed
out here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Awaitable, Callable


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


ACTIVE_PROBES_ALLOWED = _flag("ODDJOB_ALLOW_ACTIVE_PROBES")


@dataclass
class Result:
    status: str                 # done | failed | unavailable
    result: str | None = None
    error: str | None = None
    # Fields to write back onto the Service row, e.g. {"banner": "nginx/1.27"}
    patch: dict | None = None


@dataclass
class Subject:
    host: str
    port: int
    protocol: str
    service_id: int
    project_code: str


def is_in_scope(subject: Subject) -> tuple[bool, str]:
    """Scope gate. Refuses everything until wired to a real scope source.

    Oddjob has no scope document of its own, so there is nothing here that
    could legitimately say yes. Fail closed: a gate that defaults to
    permitting is not a gate.
    """
    return False, (
        "no scope source is configured, so no host can be confirmed in scope. "
        "Wire is_in_scope() to the engagement's gate before enabling probes."
    )


async def grab_banner(s: Subject) -> Result:
    """Read the service banner.

    STUB. The intended implementation shells out to nmap:

        nmap -Pn -sV --version-intensity 5 -p <port> <host>

    and parses the service/product/version/banner out of the XML. Until that
    exists this reports `unavailable` rather than guessing, because a blank
    banner written into the record would be indistinguishable from a real
    observation of an empty banner.
    """
    if not ACTIVE_PROBES_ALLOWED:
        return Result(
            status="unavailable",
            error=("active probes are disabled. Set ODDJOB_ALLOW_ACTIVE_PROBES=true "
                   "to permit them, and wire is_in_scope() first."),
        )
    ok, why = is_in_scope(s)
    if not ok:
        return Result(status="unavailable", error=f"refused by scope gate: {why}")

    # --- nmap goes here -------------------------------------------------
    return Result(
        status="unavailable",
        error=(f"no banner-grab backend is installed for {s.host}:{s.port}/{s.protocol}. "
               f"nmap integration pending."),
    )


RUNNERS: dict[str, Callable[[Subject], Awaitable[Result]]] = {
    "grab_banner": grab_banner,
}
