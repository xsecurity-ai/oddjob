"""The rules of engagement, as config the tool enforces.

A scope list is already enforced config here: `app/scopegate.py`
turns "these hosts and no others" from a sentence in a document into
a gate every packet-sending path goes through. The rest of the same
document was not enforced at all.

An authorisation letter says three things, and Oddjob could only
read one of them:

    hosts        -> app/scope.py, enforced since the beginning
    dates        -> nothing
    techniques   -> nothing

So an engagement that ended on the 14th went on scanning on the
20th, and a client who wrote "no intrusive testing" got nuclei
templates that send payloads, because nothing in the system knew
those two sentences existed. Both are enforced here, at the same two
points scope is: when a task is queued, and again when it is handed
out.

**Two points, not one.** The same reason scope has two. A task
queued inside the window and dispatched a week later is a task that
runs outside the window, and the queue-time check cannot see that
coming. An engagement that ends while 4,000 tasks are queued must
stop, not drain.

# Impact, and why it is per kind

Every task kind is classified by what running it does TO THE TARGET.
Not by how dangerous the tool is in general, and not by what it
finds -- by what it leaves behind.

    read_only        the target is not altered. A SYN sweep, a DNS
                     query, a GET.
    state_changing   something at the far end moves: a form is
                     submitted, a payload is sent, a session is
                     created or destroyed.
    destructive      unbounded, or specifically able to break
                     something.

The ceiling is a project setting and the gate refuses anything above
it. "No intrusive testing" becomes `max_impact = read_only` and the
tool enforces it, including against the operator who forgot.

**The classification is conservative on purpose.** Where a kind is
arguable it is classified upward. A `katana` crawl is
`state_changing` and not `read_only` because a crawler follows links
-- and a link can be `/logout`, `/admin/users/14/delete` or a form
that sends mail. It usually does nothing of the sort. "Usually" is
not the standard a client's authorisation letter is held to.
"""
from __future__ import annotations

from datetime import UTC, datetime

#: What running one task kind does to the target.
#:
#: Every kind in `TASK_KINDS` must appear here -- a kind missing from
#: this table would be a kind the ceiling does not apply to, which is
#: the shape of bug `scopegate.TARGET_KEYS` just had. `missing()`
#: below is asserted by the test suite.
IMPACT: dict[str, str] = {
    # ---- read_only: the target is not altered -------------------
    #: A SYN sweep. The handshake is never completed, so nothing at
    #: the far end accepts a connection.
    "masscan": "read_only",
    #: A CONNECT scan, so it DOES complete the handshake and appears
    #: in the application's logs. Still read-only: being seen is not
    #: being changed, and an entry in an access log is not a state
    #: the client has to undo.
    "portscan": "read_only",
    #: DNS, and nothing but DNS.
    "amass": "read_only",
    "nslookup": "read_only",
    "reverse_ip": "read_only",
    #: GET and HEAD against paths that may or may not exist. A 404 is
    #: not a change.
    "httpx": "read_only",
    "gobuster": "read_only",
    #: The same request with a different Host header.
    "vhost": "read_only",
    #: Technology fingerprinting. The templates in this profile read
    #: banners and response shapes; they do not send payloads --
    #: which is the entire reason it is a separate kind from
    #: `nuclei`.
    "nuclei_tech": "read_only",

    # ---- state_changing: something at the far end moves ----------
    #: `--script default,safe,vuln`. nmap itself draws this line: the
    #: `safe` category is the one it guarantees will not crash a
    #: service or change its state, and `vuln` is explicitly outside
    #: it. Several of those scripts send the trigger.
    "nmap": "state_changing",
    #: A crawler follows links, and a link can be `/logout`,
    #: `/admin/users/14/delete` or a form that sends mail. It usually
    #: does nothing of the sort; "usually" is not the standard an
    #: authorisation letter is held to.
    "katana": "state_changing",
    #: Templates that send payloads. That is what they are for.
    "nuclei": "state_changing",
    #: Narrower than `nuclei` -- only the CVEs already matched to
    #: something on the host -- but confirming a CVE means sending
    #: the thing that triggers it, which is the same act.
    "nuclei_confirm": "state_changing",

    # ---- not pointed at the client at all ------------------------
    #: Installs a tool on the ghost's own host. Nothing leaves it.
    "install": "internal",

    # ---- destructive ---------------------------------------------
    #: An operator's command, run as the ghost, inside the client's
    #: estate. There is no way to classify what it will do, and
    #: "unknown" at the top of the range is the only honest place to
    #: put it: a ceiling that does not stop the unbounded thing is
    #: not a ceiling.
    "shell": "destructive",
}

#: Worst first is wrong here -- the order is what "at most" means.
RANK: dict[str, int] = {
    "internal": 0,
    "read_only": 1,
    "state_changing": 2,
    "destructive": 3,
}

#: How each one reads in a sentence.
LABEL: dict[str, str] = {
    "internal": "does not touch the client",
    "read_only": "read-only",
    "state_changing": "state-changing",
    "destructive": "destructive",
}

#: What a project allows when it has not said. Permissive, which is a
#: deliberate choice and not an oversight: this setting arrived after
#: engagements were already running, and a default that silently
#: stopped a live scan would be a worse failure than the one it
#: prevents. A project that wants the ceiling sets it.
DEFAULT_CEILING = "destructive"


def missing(kinds) -> list[str]:
    """Kinds with no classification. -> sorted, for an assertion.

    A kind absent from `IMPACT` is a kind the ceiling cannot apply
    to, and it would be absent silently. The test suite fails the
    build on a non-empty answer, so adding a runner forces a
    decision about what it does to a client.
    """
    return sorted(k for k in kinds if k not in IMPACT)


def impact_of(kind: str) -> str:
    """What this kind does to the target.

    An unknown kind answers `destructive`, not `read_only`. A kind
    nobody classified is a kind nobody thought about, and guessing
    downward turns the oversight into permission.
    """
    return IMPACT.get((kind or "").strip(), "destructive")


def impact_refusal(kind: str, ceiling: str | None) -> str | None:
    """-> why the ceiling refuses this kind, or None."""
    ceiling = (ceiling or DEFAULT_CEILING).strip() or DEFAULT_CEILING
    if ceiling not in RANK:
        # A value nothing recognises is not permission. Treated as
        # the strictest setting rather than ignored, so a typo in a
        # project's config cannot open the gate.
        return (f"this project's technique ceiling is set to {ceiling!r}, "
                f"which is not a value this tool knows; nothing will run "
                f"until it is corrected")
    mine = impact_of(kind)
    if RANK[mine] <= RANK[ceiling]:
        return None
    return (f"a {kind} task is {LABEL[mine]}, and this engagement permits "
            f"at most {LABEL[ceiling]} techniques")


def window_refusal(starts_at: datetime | None, ends_at: datetime | None,
                   now: datetime | None = None) -> str | None:
    """-> why the engagement's dates refuse this, or None.

    Both ends are optional and NULL means unbounded, which is what
    every project had before these columns existed.

    The comparison is in UTC because the columns are. An engagement
    window written in a client's local time is a conversion the
    operator makes when they type it, once, rather than something
    this re-derives per task from a timezone nobody recorded.
    """
    now = now or datetime.now(UTC)
    if starts_at is not None:
        s = starts_at if starts_at.tzinfo else starts_at.replace(tzinfo=UTC)
        if now < s:
            return (f"this engagement has not started: authorisation runs "
                    f"from {s:%Y-%m-%d %H:%M} UTC")
    if ends_at is not None:
        e = ends_at if ends_at.tzinfo else ends_at.replace(tzinfo=UTC)
        if now > e:
            return (f"this engagement ended at {e:%Y-%m-%d %H:%M} UTC; "
                    f"authorisation to test has expired")
    return None


def refusal(project, kind: str, now: datetime | None = None) -> str | None:
    """Everything the rules of engagement say about one task. -> why not.

    The dates are checked first. "The engagement is over" is the
    more useful sentence of the two when both apply, and an operator
    who reads only the technique ceiling will go and change it.
    """
    why = window_refusal(getattr(project, "engagement_starts_at", None),
                         getattr(project, "engagement_ends_at", None), now)
    if why:
        return why
    return impact_refusal(kind, getattr(project, "max_impact", None))
