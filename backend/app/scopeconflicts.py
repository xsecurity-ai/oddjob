"""Where a scope document contradicts itself.

A host named in the IN list whose recorded address is named in the
OUT list. The gate refuses it -- out wins, because the traffic
would still reach an excluded machine -- and the refusal says so,
but the contradiction stays in the document until somebody
resolves it.

**This is not rare and it is not a tidy-up.** One engagement had
891 of them across 264 hosts, from a single scope import: the
client supplied a list of names to test and a list of addresses
not to touch, and they overlap wherever a named application lives
on an excluded box. Until each is resolved, those hosts are
silently untestable -- the operator sees the name in their own
in-scope list and reasonably concludes the tool is broken.

**The two shapes point in opposite directions**, which is why this
reports them separately rather than offering one button:

  - an address used by ONE in-scope host. The exclusion was very
    likely about that host, so the NAME is the entry that should
    go.
  - an address SHARED by several in-scope hosts. That is a CDN
    edge, an anycast address or shared hosting, and the exclusion
    was about the shared infrastructure rather than about the
    applications on it -- so the ADDRESS is the entry that should
    go.

Guessing one rule for both is how an engagement either scans a box
the client excluded or drops coverage it was authorised for.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ProjectScope, Target, TargetAddress, target_address_links

#: Two aliases of the scope table: one row has to match the IN list
#: by name and the OUT list by address in the same query.
_in = ProjectScope.__table__.alias("scope_in")
_out = ProjectScope.__table__.alias("scope_out")


@dataclass
class Conflict:
    """One host that is in scope by name and out of scope by address."""
    host: str
    address: str
    #: The in-scope entry naming the host, and the out-of-scope entry
    #: naming the address. Both carried so a resolution names the row
    #: it is deleting rather than matching on a value that moved.
    in_entry_id: int
    in_entry: str
    out_entry_id: int
    out_entry: str
    #: How many in-scope hosts share this address. One means the
    #: exclusion was about this host; several means it was about
    #: shared infrastructure.
    shared_with: int

    @property
    def kind(self) -> str:
        return "shared" if self.shared_with > 1 else "single"

    @property
    def suggestion(self) -> str:
        """Which entry the evidence points at removing."""
        return "out_entry" if self.shared_with > 1 else "in_entry"


async def find(session: AsyncSession, project_id: int) -> list[Conflict]:
    """Every contradiction in one project's lists.

    Exact matches only -- an fqdn entry equal to the host, an ip
    entry equal to a recorded address. Wildcards and CIDRs are
    deliberately not expanded here: a `*.acme.example` that covers
    a host whose address falls in an excluded /24 is a judgement
    about intent, and this reports the cases where the document
    says both things about the SAME string. Those are the ones
    somebody typed, and the ones an operator can act on without
    re-deriving what the client meant.
    """
    rows = (await session.execute(
        select(Target.host, TargetAddress.address,
               _in.c.id, _in.c.value, _out.c.id, _out.c.value)
        .select_from(Target)
        .join(target_address_links,
              target_address_links.c.target_id == Target.id)
        .join(TargetAddress,
              TargetAddress.id == target_address_links.c.address_id)
        .join(_in, (_in.c.project_id == Target.project_id)
              & _in.c.included.is_(True)
              & (_in.c.kind == "fqdn")
              & (_in.c.value == Target.host))
        .join(_out, (_out.c.project_id == Target.project_id)
              & _out.c.included.is_(False)
              & _out.c.kind.in_(("ipv4", "ipv6"))
              & (_out.c.value == TargetAddress.address))
        .where(Target.project_id == project_id))).all()

    # How many in-scope hosts each address serves, counted over the
    # conflicts themselves: the question is "is this address shared
    # by hosts the engagement was told to test", not "how many rows
    # mention it".
    per_address: dict[str, set[str]] = {}
    for host, address, *_rest in rows:
        per_address.setdefault(address, set()).add(host)

    out = [
        Conflict(host=host, address=address,
                 in_entry_id=in_id, in_entry=in_val,
                 out_entry_id=out_id, out_entry=out_val,
                 shared_with=len(per_address[address]))
        for host, address, in_id, in_val, out_id, out_val in rows
    ]
    out.sort(key=lambda c: (-c.shared_with, c.address, c.host))
    return out


def entries_to_remove(conflicts: list[Conflict],
                      strategy: str) -> tuple[set[int], str]:
    """Which scope rows a strategy would delete. -> (ids, what it does).

    `suggested` is the only one that reads the evidence: it drops
    the exclusion where an address is shared by several in-scope
    hosts, and the name where it serves one. The other two are
    uniform and are there because an operator may know something
    the counts do not.
    """
    if strategy == "suggested":
        ids = {c.out_entry_id if c.kind == "shared" else c.in_entry_id
               for c in conflicts}
        return ids, ("drops the exclusion where an address is shared by "
                     "several in-scope hosts, and the name where it "
                     "serves one")
    if strategy == "keep_exclusions":
        return ({c.in_entry_id for c in conflicts},
                "drops every conflicting NAME, so nothing new becomes "
                "testable and the contradiction goes")
    if strategy == "keep_names":
        return ({c.out_entry_id for c in conflicts},
                "drops every conflicting ADDRESS EXCLUSION, which makes "
                "those hosts testable")
    raise ValueError(f"unknown strategy {strategy!r}")
