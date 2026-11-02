"""Asking the model to write a proof, and checking what it wrote.

Structurally the same worker as `remediate.py` and for the same
reasons: one finding at a time, worst first, a pause between them,
failure bounded per finding. Scanners deliver findings in bulk and
firing those at a model concurrently saturates a shared inference
server and burns a rate-limited quota in minutes.

What is different is what comes back. Remediation is prose and the
worst a bad one does is read oddly. A proof is a **template that will
be sent at a client's production system**, so what the model returns
is checked before it is stored and checked again by the Ghost before
it is run:

    here        it must parse as YAML, declare an `http` block, carry
                at least one matcher, and contain none of the
                constructs that would make it something other than a
                read-mostly HTTP check
    on the Ghost `nuclei -validate` before the first request, and the
                `code` protocol is never enabled

**The template is not trusted because a model wrote it.** It is
trusted because of what a nuclei HTTP template can and cannot
express, and these checks are what keep it inside that.

Nothing here runs anything. The worker writes the template and queues
a `poc` task; the Ghost runs it and `pocwork.apply_result` records
the verdict.
"""
from __future__ import annotations

import json
import re

import yaml

#: Protocols that are not "send an HTTP request and match the reply".
#: `code` executes commands on the agent, `javascript` runs a script
#: engine, and the network/ssl ones open arbitrary sockets. None of
#: them is something a generated proof should reach for, and all of
#: them are refused rather than filtered: a template asking for one
#: is a template that misunderstood the job.
FORBIDDEN_BLOCKS = ("code", "javascript", "network", "ssl", "websocket",
                    "whois", "dns", "file", "headless")

#: Matchers are what make a proof a proof. A template with none runs,
#: reports nothing, and would be recorded as "did not reproduce" --
#: an answer about our template rather than about the finding.
_NEEDS = ("matchers",)

MAX_TEMPLATE = 16_000

#: The placeholder an authenticating proof uses in place of the
#: credential. nuclei substitutes it from `-var secret=...`, which the
#: Ghost supplies at run time from a value it fetches with its own
#: identity. The value is never in the template, the task args, or the
#: prompt.
SECRET_VAR = "{{secret}}"


def _paths(doc: dict) -> list[str]:
    """Every request target in the template's `http` block.

    Both spellings: `path:` (a list of URLs, normally rooted at
    `{{BaseURL}}`) and `raw:` (a whole HTTP request, which carries its
    own Host line and is therefore a way to address any server at
    all).
    """
    out: list[str] = []
    http = doc.get("http")
    for entry in (http if isinstance(http, list) else [http]):
        if not isinstance(entry, dict):
            continue
        for key in ("path", "raw"):
            v = entry.get(key)
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, list):
                out += [x for x in v if isinstance(x, str)]
    return out

SYSTEM = """You write a single nuclei template that proves one penetration-test
finding is still present on one host.

Reply with YAML and nothing else. No prose, no explanation, no markdown
fences.

The template MUST:
  - have an `id`, an `info` block with `name` and `severity`, and one
    `http` block
  - use `{{BaseURL}}` for the target rather than a hard-coded host
  - carry at least one matcher that is specific to THIS finding

The template MUST NOT:
  - use the `code`, `javascript`, `network`, `ssl`, `dns`, `file` or
    `headless` protocols — only `http`
  - try to exploit, write, delete or change anything. It is a check,
    not an attack: request what demonstrates the condition and match
    on the evidence in the reply.
  - match on something every host returns. A matcher on `status: 200`
    alone proves the host is up, not that the finding is real.

If the finding cannot be proved by an HTTP request and a matcher — it
needs a login you do not have, or it is a configuration fact rather
than a reachable condition — reply with exactly:

    cannot-prove: <one short sentence saying why>
"""

#: What the model says when the finding is not provable this way.
#: A real answer and recorded as one: "we could not write a check for
#: this" is different from "we wrote one and it failed".
CANNOT = "cannot-prove"


class Rejected(Exception):
    """The model returned something that must not be stored or run."""


def clean(text: str) -> str:
    """Strip the model's conversational habits off a template."""
    t = (text or "").strip()
    # Thinking models wrap their answer; take what is after the block.
    if "</think>" in t:
        t = t.split("</think>", 1)[1].strip()
    # Fenced output, with or without a language tag.
    fence = re.match(r"^```[a-zA-Z]*\s*\n(.*?)\n?```\s*$", t, re.S)
    if fence:
        t = fence.group(1).strip()
    return t


def check(text: str, carries_secret: bool = False) -> str:
    """-> the template, or raise Rejected with a usable reason.

    Parsed rather than pattern-matched. A template is YAML and the
    question "does this declare a `code` block" is a question about
    the document, not about whether the characters `code:` appear in
    it -- a matcher looking for the word "code" in a response would
    trip a substring check and is perfectly legitimate.

    `carries_secret` applies the extra rules a template gets when it
    will be handed a live client credential at run time. They are
    stricter than the ordinary ones and deliberately so: an ordinary
    proof that reached the wrong host sends a probe, and this one
    would send the key.
    """
    t = clean(text)
    if not t:
        raise Rejected("the model returned nothing")
    if t.lower().startswith(CANNOT):
        raise Rejected(t[:300])
    if len(t) > MAX_TEMPLATE:
        raise Rejected(f"the template is {len(t)} bytes, over the "
                       f"{MAX_TEMPLATE} limit")
    try:
        doc = yaml.safe_load(t)
    except yaml.YAMLError as e:
        raise Rejected(f"not valid YAML: {str(e)[:200]}") from e
    if not isinstance(doc, dict):
        raise Rejected("the template is not a YAML mapping")

    bad = [k for k in FORBIDDEN_BLOCKS if k in doc]
    if bad:
        # Named, not silently stripped. A template reaching for `code`
        # misunderstood the job, and editing it into something that
        # runs would be guessing at what it meant to do.
        raise Rejected(
            f"the template declares {', '.join(sorted(bad))}, which "
            f"is not an HTTP check — only `http` is allowed")
    if "http" not in doc:
        raise Rejected("the template has no `http` block, so it sends nothing")
    if not doc.get("id"):
        raise Rejected("the template has no `id`")

    if carries_secret:
        # ---- where the credential may be sent --------------------
        #
        # Every request has to be rooted at `{{BaseURL}}`, which is
        # the target Oddjob chose and already scope-checked. A
        # hard-coded host would be this template deciding for itself
        # where a live credential goes, and the obvious destination
        # for a leaked key -- the third-party service that issued it
        # -- is exactly the thing the engagement's scope does not
        # cover. Refused rather than rewritten: a template reaching
        # elsewhere misunderstood the job.
        # `raw` carries its own request line and Host header, so it
        # can address another server even while starting with
        # {{BaseURL}}. There is no safe way to allow it here.
        if any(isinstance(e, dict) and e.get("raw")
               for e in (doc["http"] if isinstance(doc["http"], list)
                         else [doc["http"]])):
            raise Rejected(
                "an authenticating proof may not use `raw`: it carries its "
                "own Host line, so the check could send the credential to "
                "a server other than the one being tested")
        targets = _paths(doc)
        if not targets:
            raise Rejected("the template names no request path")
        stray = [t for t in targets if not t.lstrip().startswith("{{BaseURL}}")]
        if stray:
            raise Rejected(
                "an authenticating proof may only send to {{BaseURL}}, and "
                f"this one addresses {stray[0][:80]!r}. The credential would "
                f"go somewhere the engagement did not authorise.")
        # ---- and that it actually tests the credential ------------
        if SECRET_VAR not in t:
            raise Rejected(
                f"the template never uses {SECRET_VAR}, so it does not "
                f"present the credential and cannot show whether it still "
                f"works — which is the only thing this proof was for")

    blob = json.dumps(doc.get("http"), default=str)
    for needed in _NEEDS:
        if needed not in blob:
            raise Rejected(
                f"the template has no `{needed}`. Without one it would run, "
                f"match nothing, and be recorded as 'did not reproduce' — "
                f"which would be a statement about the template rather "
                f"than about the finding.")
    return t
