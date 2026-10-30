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


def check(text: str) -> str:
    """-> the template, or raise Rejected with a usable reason.

    Parsed rather than pattern-matched. A template is YAML and the
    question "does this declare a `code` block" is a question about
    the document, not about whether the characters `code:` appear in
    it -- a matcher looking for the word "code" in a response would
    trip a substring check and is perfectly legitimate.
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

    blob = json.dumps(doc.get("http"), default=str)
    for needed in _NEEDS:
        if needed not in blob:
            raise Rejected(
                f"the template has no `{needed}`. Without one it would run, "
                f"match nothing, and be recorded as 'did not reproduce' — "
                f"which would be a statement about the template rather "
                f"than about the finding.")
    return t
