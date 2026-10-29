"""Making a conversation fit the model that has to read it.

The thread belongs to the engagement, so every turn of it is re-sent
on every message -- and a turn is not just what somebody typed. It is
the tool calls the model made and the rows those calls returned, and
`tools.MAX_ROWS` is 200. A dozen questions into a real engagement that
is a hundred thousand tokens of JSON, and the request stops being
accepted at all:

    ContextWindowExceededError: request (134784 tokens) exceeds the
    available context size (131072 tokens)

Which is a hard failure, not a degradation: the agent simply stops
answering, and it stops for everyone on the project at once, because
the thread is shared.

# What gets dropped, and why that order

**Tool results first, oldest first.** A tool result is the one thing
in a conversation that can be REGENERATED -- the model can call the
tool again, against data that is fresher than the copy being dropped.
What a person asked and what the model answered cannot be recovered
from anywhere, so they are kept to the last.

**And the drop is said out loud.** A model reading a thread with a
hole in it, and no indication there is a hole, will answer from what
it half-remembers. The placeholder tells it the rows were there and
are gone, which turns a wrong answer into a second tool call.

Whole turns are only dropped once every old tool result has already
gone, and the newest exchange is never dropped: a request that cannot
fit the question being asked has nothing useful to send.

# Counting

Without a tokenizer for whichever model is configured -- and the
local ones change -- this counts characters and divides. Four
characters per token is the usual English figure and JSON runs a
little denser, so the budget carries real headroom rather than
pretending to be exact. Being approximately right and under is the
job; being exactly right and over is a 400.
"""
from __future__ import annotations

import json

#: Characters per token, assumed. Deliberately optimistic-low so the
#: estimate comes out HIGH and trims sooner: guessing 4 when the true
#: figure is 3.5 means believing a request is smaller than it is,
#: which is the one direction that fails.
CHARS_PER_TOKEN = 3.0

#: What replaces a tool result that had to go. Names the tool, so the
#: model knows what to call again rather than guessing.
DROPPED = ("[{tool}'s earlier output was dropped to fit this model's "
           "context window. Call it again if you still need it.]")


def estimate(messages: list[dict], system: str = "") -> int:
    """Roughly how many tokens these messages will cost."""
    return int((len(system) + sum(_size(m) for m in messages))
               / CHARS_PER_TOKEN)


def _size(m: dict) -> int:
    c = m.get("content")
    if isinstance(c, str):
        n = len(c)
    elif c is None:
        n = 0
    else:
        # A tool-calling round carries structured content, and the
        # provider serialises it to JSON on the wire -- so that is
        # what it costs, not `len(str(...))` of a Python repr.
        n = len(json.dumps(c, default=str))
    # Tool calls live beside the content, not in it.
    if m.get("tool_calls"):
        n += len(json.dumps(m["tool_calls"], default=str))
    # Role, delimiters, the per-message overhead every provider adds.
    return n + 24


def _tool_name(m: dict, by_id: dict[str, str]) -> str:
    return by_id.get(str(m.get("tool_call_id") or ""), "the tool")


def fit(messages: list[dict], budget_tokens: int,
        system: str = "") -> tuple[list[dict], int]:
    """-> (messages that fit, how many tool results were dropped).

    `budget_tokens` of 0 or less means no limit, which is what a
    deployment that has not configured one gets. The caller decides
    the number; this decides what goes.

    Never drops the last exchange. A request trimmed down past the
    question being asked has nothing worth sending, and failing
    loudly on an impossible budget beats answering a question nobody
    asked.
    """
    if budget_tokens <= 0 or estimate(messages, system) <= budget_tokens:
        return messages, 0

    out = [dict(m) for m in messages]
    # Which tool a result belongs to, so the placeholder can name it.
    by_id: dict[str, str] = {}
    for m in out:
        for call in m.get("tool_calls") or []:
            cid = str(call.get("id") or "")
            fn = (call.get("function") or {}).get("name")
            if cid and fn:
                by_id[cid] = str(fn)

    # The last exchange is everything from the final user message on.
    keep_from = 0
    for i in range(len(out) - 1, -1, -1):
        if out[i].get("role") == "user":
            keep_from = i
            break

    dropped = 0
    for i, m in enumerate(out):
        if estimate(out, system) <= budget_tokens:
            break
        if i >= keep_from or m.get("role") != "tool":
            continue
        text = DROPPED.format(tool=_tool_name(m, by_id))
        if m.get("content") == text:
            continue
        m["content"] = text
        dropped += 1

    # Still over with every old result gone: shed whole exchanges
    # from the front. The oldest question is the one least likely to
    # be what the current one is about.
    while estimate(out, system) > budget_tokens and keep_from > 0:
        out.pop(0)
        keep_from -= 1
    return out, dropped
