"""What the model is allowed to have written.

A proof is a template that will be SENT at a client's production
system, so what comes back from the model is checked before it is
stored. These are the checks. No server and no model: the whole
point is which strings are refused.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.agent.pocbuild import (  # noqa: E402
    FORBIDDEN_BLOCKS,
    MAX_TEMPLATE,
    Rejected,
    check,
    clean,
)

passed = failed = 0


def ck(label, cond, got=None):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {label}" + (f" {got}" if got is not None else ""))
    else:
        failed += 1
        print(f"  FAIL  {label}" + (f" {got}" if got is not None else ""))


def refused(text) -> str | None:
    try:
        check(text)
        return None
    except Rejected as e:
        return str(e)


GOOD = """id: poc-cve-2026-1
info:
  name: admin console reachable without authentication
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin-servlet/api/"
    matchers:
      - type: word
        words:
          - '"authenticated":true'
"""

print("== a good template is accepted, unchanged ==")
ck("it comes back", check(GOOD).startswith("id: poc-cve-2026-1"))
ck("...with the matcher intact", '"authenticated":true' in check(GOOD))

print("\n== the model's conversational habits are stripped ==")
ck("a fence comes off",
   check("```yaml\n" + GOOD + "```").startswith("id:"))
ck("...an untagged fence too", check("```\n" + GOOD + "```").startswith("id:"))
ck("...and a thinking block",
   check("<think>I should write a template</think>\n" + GOOD)
   .startswith("id:"))
ck("clean() is what does it, and is idempotent",
   clean(clean("```yaml\n" + GOOD + "```")) == clean(GOOD))

print("\n== only `http`: every other protocol is refused by name ==")
# `code` executes commands ON THE AGENT. The others open sockets of
# the template's choosing. A generated proof reaches for none of
# them, and one that does misunderstood the job -- so it is refused
# rather than edited into something that runs.
for block in FORBIDDEN_BLOCKS:
    why = refused(f"id: x\ninfo:\n  name: a\n{block}:\n  - engine: [sh]\n")
    ck(f"`{block}` is refused", why is not None and block in why,
       (why or "NOT REFUSED")[:52])

print("\n== and it has to be a check that can report something ==")
ck("no http block",
   "sends nothing" in (refused("id: x\ninfo:\n  name: a\n") or ""))
# The important one. A template with no matcher runs, reports
# nothing, and is recorded as "did not reproduce" -- which is a
# statement about our template, not about the finding.
_nomatch = "id: x\ninfo:\n  name: a\nhttp:\n  - method: GET\n    path: ['a']\n"
why = refused(_nomatch)
ck("no matchers is refused", why is not None)
ck("...and the reason says why that is dangerous",
   "did not reproduce" in (why or ""), (why or "")[:70])
ck("no id", "no `id`" in (refused(
    "info:\n  name: a\nhttp:\n  - method: GET\n    matchers: [{type: word}]\n")
    or ""))

print("\n== a substring is not a declaration ==")
# `code` appearing inside a MATCHER is legitimate -- a template
# looking for the word "code" in a response is an ordinary thing to
# write. The document is parsed, not grepped.
_word = """id: x
info:
  name: a
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["error code", "javascript:"]
"""
ck("a matcher may contain the word `code`", refused(_word) is None,
   refused(_word))

print("\n== bounds and non-answers ==")
ck("empty is refused", refused("") is not None)
ck("whitespace is refused", refused("   \n  ") is not None)
ck("not YAML is refused", "not valid YAML" in (refused("{nope") or ""))
ck("a YAML scalar is not a template",
   "not a YAML mapping" in (refused("just a string") or ""))
# "We could not write a check for this" is a real answer and is
# distinct from "we wrote one and it failed".
why = refused("cannot-prove: this needs an authenticated session")
ck("cannot-prove is refused and keeps its reason",
   why is not None and "authenticated session" in why, (why or "")[:60])
ck("...including when the model fences it",
   refused("```\ncannot-prove: no\n```") is not None)
_huge = GOOD + ("# " + "x" * 200 + "\n") * 200
ck("an oversized template is refused",
   str(MAX_TEMPLATE) in (refused(_huge) or ""), len(_huge))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
