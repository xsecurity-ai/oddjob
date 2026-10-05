"""Talking to Anthropic and OpenAI, including OAuth tokens.

**The token-type distinction is the whole reason this file is interesting.**
Anthropic accepts two different credentials on two different headers:

  sk-ant-api…      an API key          ->  `x-api-key: <token>`
  sk-ant-oat…      an OAuth token,
                   e.g. from
                   `claude setup-token`->  `Authorization: Bearer <token>`
                                           plus `anthropic-beta: oauth-2025-04-20`

They are not interchangeable. Sending an OAuth token as `x-api-key` fails
with an authentication error that reads exactly like a wrong key, which is
a genuinely horrible afternoon. So the prefix decides the header, and the
UI says which kind it detected.

Everything here is HTTP against the public APIs — no vendor SDK. Two
providers, one loop, and no dependency that has to be upgraded in lockstep
with a model release.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
OAUTH_BETA = "oauth-2025-04-20"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
#: Local servers are often slow on first token while the model loads.
LOCAL_TIMEOUT = 600.0

TIMEOUT = 120.0


class AgentError(RuntimeError):
    pass


def anthropic_auth(token: str) -> tuple[dict[str, str], str]:
    """-> (headers, detected kind). See the module docstring."""
    t = (token or "").strip()
    if not t:
        raise AgentError("no Anthropic token configured")
    base = {"anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json"}
    # `claude setup-token` issues sk-ant-oat…; some flows mint plain OAuth
    # access tokens with no sk- prefix at all. Anything that is not clearly
    # an API key is treated as a bearer token, because that is the failure
    # that is recoverable: a bearer token sent as an API key is rejected
    # outright, while the reverse at least reports a clear 401.
    if t.startswith("sk-ant-api"):
        return {**base, "x-api-key": t}, "api-key"
    if t.startswith(("sk-ant-oat", "sk-ant-ort")) or not t.startswith("sk-ant-"):
        return ({**base, "authorization": f"Bearer {t}",
                 "anthropic-beta": OAUTH_BETA}, "oauth")
    return {**base, "x-api-key": t}, "api-key"


def token_kind(provider: str, token: str) -> str:
    """What the UI shows beside a stored token, without revealing it."""
    t = (token or "").strip()
    if not t:
        return "not set"
    if provider == "anthropic":
        try:
            return anthropic_auth(t)[1]
        except AgentError:
            return "not set"
    return "api-key"


@dataclass
class Step:
    """One turn of the loop, for the transcript the UI renders."""
    kind: str                      # text | tool | error
    text: str = ""
    tool: str | None = None
    args: dict = field(default_factory=dict)
    result: str | None = None


@dataclass
class Reply:
    text: str
    steps: list[Step] = field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: dict = field(default_factory=dict)
    #: The provider-shaped message list, handed back so the next request
    #: continues the same conversation without the UI having to model it.
    history: list = field(default_factory=list)


# --------------------------------------------------------------- anthropic
def _anthropic_tools(tools) -> list[dict]:
    return [{"name": t.name, "description": t.description,
             "input_schema": t.schema} for t in tools]


async def anthropic_chat(token: str, model: str, system: str,
                         messages: list, tools, runner, max_steps: int) -> Reply:
    headers, _kind = anthropic_auth(token)
    spec = _anthropic_tools(tools)
    by_name = {t.name: t for t in tools}
    steps: list[Step] = []
    usage: dict[str, Any] = {}
    convo = list(messages)

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for _ in range(max_steps + 1):
            body = {"model": model, "max_tokens": 4096, "system": system,
                    "messages": convo}
            if spec:
                body["tools"] = spec
            r = await client.post(ANTHROPIC_URL, headers=headers, json=body)
            if r.status_code != 200:
                raise AgentError(_http_error("Anthropic", r))
            data = r.json()
            for k, v in (data.get("usage") or {}).items():
                usage[k] = usage.get(k, 0) + v if isinstance(v, int) else v

            blocks = data.get("content") or []
            convo.append({"role": "assistant", "content": blocks})
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            if text.strip():
                steps.append(Step(kind="text", text=text))

            calls = [b for b in blocks if b.get("type") == "tool_use"]
            if not calls or data.get("stop_reason") != "tool_use":
                return Reply(text=text, steps=steps,
                             stop_reason=data.get("stop_reason") or "end_turn",
                             usage=usage, history=convo)

            results = []
            for c in calls:
                tool = by_name.get(c.get("name"))
                if tool is None:
                    out = json.dumps({"error": f"no tool named {c.get('name')!r}"})
                else:
                    out = await runner(tool, c.get("input") or {})
                steps.append(Step(kind="tool", tool=c.get("name"),
                                  args=c.get("input") or {}, result=out))
                results.append({"type": "tool_result", "tool_use_id": c.get("id"),
                                "content": out})
            convo.append({"role": "user", "content": results})

    # The cap exists so a confused model cannot spend an afternoon in a
    # loop; hitting it is reported rather than hidden.
    return Reply(text=_capped(max_steps), steps=steps, stop_reason="max_steps",
                 usage=usage, history=convo)


# ----------------------------------------------------------------- openai
def _openai_tools(tools) -> list[dict]:
    return [{"type": "function",
             "function": {"name": t.name, "description": t.description,
                          "parameters": t.schema}} for t in tools]


async def openai_chat(token: str, model: str, system: str,
                      messages: list, tools, runner, max_steps: int,
                      base_url: str | None = None) -> Reply:
    """OpenAI, and anything that speaks its chat-completions API.

    Ollama, LM Studio, llama.cpp's server, vLLM and LocalAI all expose this
    shape, which is why `base_url` is the only thing a local model needs —
    not a second provider implementation. A local server usually wants no
    key at all, so an empty token is allowed when a base URL is given.
    """
    local = bool(base_url)
    if not local and not (token or "").strip():
        raise AgentError("no OpenAI token configured")
    url = (base_url.rstrip("/") + "/chat/completions") if local else OPENAI_URL
    headers = {"content-type": "application/json"}
    if (token or "").strip():
        headers["authorization"] = f"Bearer {token.strip()}"
    spec = _openai_tools(tools)
    by_name = {t.name: t for t in tools}
    steps: list[Step] = []
    usage: dict[str, Any] = {}
    convo = [{"role": "system", "content": system}] + list(messages)

    async with httpx.AsyncClient(timeout=LOCAL_TIMEOUT if local else TIMEOUT) as client:
        for _ in range(max_steps + 1):
            body: dict[str, Any] = {"model": model, "messages": convo}
            if spec:
                body["tools"] = spec
            try:
                r = await client.post(url, headers=headers, json=body)
            except Exception as e:
                if local:
                    raise AgentError(
                        f"could not reach the local model server at "
                        f"{base_url}: {type(e).__name__}: {e}. The Oddjob "
                        f"server makes this request, not your browser — "
                        f"'localhost' means localhost to it.")
                raise
            if r.status_code != 200:
                raise AgentError(_http_error("the local server" if local
                                             else "OpenAI", r))
            data = r.json()
            for k, v in (data.get("usage") or {}).items():
                if isinstance(v, int):
                    usage[k] = usage.get(k, 0) + v

            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            convo.append(msg)
            text = msg.get("content") or ""
            if text.strip():
                steps.append(Step(kind="text", text=text))

            calls = msg.get("tool_calls") or []
            if not calls:
                if local and not steps and spec and not text.strip():
                    # A local model that returns nothing and calls nothing
                    # is almost always one without tool-calling support,
                    # which is a configuration mistake worth naming rather
                    # than returning an empty bubble.
                    raise AgentError(
                        f"{model} returned no answer and called no tools. "
                        f"Most likely it does not support tool calling — "
                        f"try a model that does (qwen3, llama3.1, mistral-nemo).")
                return Reply(text=text, steps=steps,
                             stop_reason=choice.get("finish_reason") or "stop",
                             usage=usage, history=convo[1:])

            for c in calls:
                fn = (c.get("function") or {})
                name = fn.get("name")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {}
                tool = by_name.get(name)
                if tool is None:
                    out = json.dumps({"error": f"no tool named {name!r}"})
                else:
                    out = await runner(tool, args)
                steps.append(Step(kind="tool", tool=name, args=args, result=out))
                convo.append({"role": "tool", "tool_call_id": c.get("id"),
                              "content": out})

    return Reply(text=_capped(max_steps), steps=steps, stop_reason="max_steps",
                 usage=usage, history=convo[1:])


def _capped(n: int) -> str:
    return (f"I stopped after {n} tool calls without reaching an answer. "
            f"That limit is there to stop a loop running away. Try a narrower "
            f"question, or raise it in Site Config.")


def _http_error(who: str, r: httpx.Response) -> str:
    """Turn a provider error into something that names the actual problem."""
    try:
        body = r.json()
        detail = (body.get("error") or {}).get("message") or json.dumps(body)[:300]
    except Exception:
        detail = r.text[:300]
    if r.status_code == 401:
        return (f"{who} rejected the credentials (401). For Anthropic, check "
                f"whether this is an API key (sk-ant-api…) or an OAuth token "
                f"from `claude setup-token` — they use different headers and "
                f"are not interchangeable. {detail}")
    if r.status_code == 404:
        return f"{who} does not know that model (404). {detail}"
    if r.status_code == 429:
        return f"{who} rate-limited this request (429). {detail}"
    return f"{who} returned HTTP {r.status_code}: {detail}"
