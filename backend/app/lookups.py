"""Deciding what a finished DNS lookup means, before anything is written.

Every lookup result used to become a question for a human. Under the
old model it had to: `Target.ip_address` held one string, so a forward
lookup returning four addresses was four candidates for one slot, and
a reverse lookup returning six names was six candidates for one `host`.
The dropdown existed because the schema could only hold one answer.

With addresses many-to-many, most of those questions stop being
questions. A host with four addresses has four addresses. This module
says which results are still genuinely ambiguous and which are not, and
it does so as a pure function of the result — no database, no I/O — so
the boundary is testable and arguable rather than tangled into a route.

Three outcomes, and the names matter:

    AUTO      deterministic. Apply it; tell the operator what was done.
    CHOICE    genuinely ambiguous. A human picks.
    BLOCKED   nothing to pick. The scope list refuses it, or a human
              already refused it, or the lookup found nothing. Reported,
              never applied, and NOT presented as a decision — the fix
              is a scope edit, not a dropdown.

**The boundary, and why it falls where it does.**

*Forward lookup (name -> addresses).* Always AUTO. Adding an address to
a target the project already holds creates no asset, points no scanner
anywhere new, and asserts nothing except that the name resolved there.
N addresses means the host has N addresses. Each address is still gated
individually; refused ones are reported and not written.

*Reverse lookup (address -> names), ONE name.* AUTO. The target is
named by its address and the lookup says what it is called. The address
and the name are the same asset — we already hold it — so the gate is
asked `check(name, ip=the address)`, which is precisely what that
parameter is for. If the name is already a target, this is the merge the
operator ruled on.

*Reverse lookup, SEVERAL names.* The address answers to several names,
which is itself the evidence that it is SHARED — a CDN edge, a load
balancer, a hosting tenant list. So no one of them is "the host at that
address", and none gets to borrow the address's standing: each name is
gated on its own name alone. Then:

  - exactly one name survives the gate -> AUTO, as the single-name case.
    The project's own scope document resolved the ambiguity, which is
    the most meaningful tiebreak available and is deterministic.
  - several survive, and exactly one of them is already a target ->
    AUTO. The project has already committed to that name for this host;
    the address-named row merges into it and the rest are created as
    leads.
  - several survive and none (or more than one) is already a target ->
    CHOICE. Creating the leads is not in doubt and is not asked about;
    WHICH name takes over the address-named row is, and nothing in the
    data decides it. Ordering them lexicographically or by label count
    would be a coin toss wearing a rule, and the row that wins is where
    every future finding for that address lands.

*`partial: true`.* A source did not answer, so the list is a floor and
not a set. The handling is deliberately asymmetric:

  - forward: still AUTO. The decision is not about how many addresses
    there are; each address that came back is independently true, and
    adding is additive. A missing address means we add fewer, never
    that we added a wrong one. The partiality is recorded on the
    timeline so the record does not read as a complete answer.
  - reverse: never automatic, always CHOICE. Here the decision IS about
    cardinality — one name means "rename it", several mean "the address
    is shared" — and a floor cannot tell the two apart. A partial result
    showing one name may be a shared address whose other tenants the
    dead source would have named, and renaming the row on that is
    exactly the wrong-and-automatic outcome.

*Already refused by a human.* A name with a rejected `DomainCandidate`
row is a decision somebody made; the row exists so the question is not
asked twice. Auto-adding it would reverse that silently. BLOCKED.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

AUTO = "auto"
CHOICE = "choice"
BLOCKED = "blocked"

#: Kinds whose output this module knows how to read.
LOOKUP_KINDS = ("reverse_ip", "nslookup")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").split("%", 1)[0].strip().strip("[]"))
        return True
    except ValueError:
        return False


@dataclass
class Decision:
    """What should happen to one finished lookup result."""
    #: auto | choice | blocked
    verdict: str
    #: One sentence an operator can read before it happens, or has
    #: happened. "2 added" with no names is not something anyone can
    #: check, so this names them.
    plan: str
    #: Names or addresses that would be written. For a reverse result
    #: this is the allowed subset, never the raw list.
    apply: list[str] = field(default_factory=list)
    #: For reverse AUTO: the name that takes over the address-named row.
    takeover: str | None = None
    #: Why each rejected entry was rejected, by name. Always reported,
    #: never silently dropped — a name the gate refused is a fact the
    #: operator needs in order to fix the scope list.
    refused: dict[str, str] = field(default_factory=dict)


def decide_forward(addresses: list[str], allowed, partial: bool) -> Decision:
    """A name's addresses. `allowed(addr) -> reason or None`.

    `allowed` returns None to permit and a sentence to refuse, so the
    refusal carries the scope entry that caused it rather than a bare
    False. Each address is asked about separately: invariant one is
    that nothing is approved because something beside it was.
    """
    ok: list[str] = []
    refused: dict[str, str] = {}
    for a in addresses:
        if not is_ip(a):
            refused[a] = f"{a!r} is not an IP address"
            continue
        why = allowed(a)
        if why:
            refused[a] = why
        elif a not in ok:
            ok.append(a)

    if not ok:
        if refused:
            return Decision(BLOCKED, _refusal_line(refused), refused=refused)
        return Decision(BLOCKED, "the lookup returned no addresses")

    floor = " (a source did not answer, so this is a floor, not a total)" \
        if partial else ""
    plan = f"add {len(ok)} address(es): {', '.join(ok)}{floor}"
    if refused:
        plan += ". " + _refusal_line(refused)
    # Partial changes nothing here. Each address that came back is true
    # on its own, and adding one neither creates an asset nor asserts
    # that the list is complete. See the module docstring.
    return Decision(AUTO, plan, apply=ok, refused=refused)


def decide_reverse(names: list[str], allowed, partial: bool,
                   is_target) -> Decision:
    """An address's names. `allowed(name)`, `is_target(name) -> bool`.

    `allowed` is called with the NAME ALONE and the caller must not pass
    the address along with it when there is more than one name. That is
    the shared-hosting rule in the module docstring, and it is the
    difference between "this CIDR is in scope so its PTR records are
    ours" and the truth, which is that a scope document listing a range
    says nothing about who else is renting space in it.
    """
    ok: list[str] = []
    refused: dict[str, str] = {}
    for n in names:
        if is_ip(n):
            # A reverse lookup that hands the address back is not a
            # result; it is the resolver saying it has nothing.
            refused[n] = (f"{n} is an address, not a name — a reverse lookup "
                          f"returning the address back is not a result")
            continue
        why = allowed(n)
        if why:
            refused[n] = why
        elif n not in ok:
            ok.append(n)

    if not ok:
        if refused:
            return Decision(BLOCKED, _refusal_line(refused), refused=refused)
        return Decision(BLOCKED, "the lookup returned no names")

    if partial:
        # The whole branch below turns on how many names there are, and
        # a floor does not answer that. See the module docstring.
        return Decision(
            CHOICE,
            f"{len(ok)} name(s) came back but a source did not answer, so "
            f"the list is a floor. Whether this address is shared is "
            f"exactly what is unknown, so which name owns the row is not "
            f"something to guess at: {', '.join(ok)}",
            apply=ok, refused=refused)

    if len(ok) == 1:
        plan = (f"name the target {ok[0]}"
                if not is_target(ok[0])
                else f"merge into the existing target {ok[0]}")
    else:
        established = [n for n in ok if is_target(n)]
        if len(established) != 1:
            return Decision(
                CHOICE,
                f"{len(ok)} names answer at this address, so it is shared. "
                f"They can all be added, but which one takes over the "
                f"address-named row is not something the data decides: "
                f"{', '.join(ok)}",
                apply=ok, refused=refused)
        plan = (f"merge into {established[0]}, which this project already "
                f"holds, and add the other {len(ok) - 1}: "
                + ", ".join(n for n in ok if n != established[0]))

    out = Decision(AUTO, plan, apply=ok,
                   takeover=ok[0] if len(ok) == 1
                   else next(n for n in ok if is_target(n)),
                   refused=refused)
    if refused:
        out.plan += ". " + _refusal_line(refused)
    return out


def _refusal_line(refused: dict[str, str]) -> str:
    """Names the refusals. Never a count — a count cannot be acted on."""
    return "not added: " + "; ".join(
        f"{k} ({v})" for k, v in sorted(refused.items()))
