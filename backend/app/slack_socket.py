"""Answering questions in Slack, over Socket Mode.

Everything else in `app/slack.py` is outbound. This is the inbound
half: Slack opens nothing towards us, we open a websocket towards
Slack, which is why it works with the app bound to 127.0.0.1 and no
public endpoint, no TLS certificate and no request-signature
verification to get wrong.

The shape:

    POST apps.connections.open  (app-level token, xapp-…)
      -> a one-shot wss:// URL
    connect, then for each envelope
      -> ack it by envelope_id within 3 seconds, or Slack retries
      -> handle it

**Only mentions are answered.** Reading every message in the channel
would mean an engagement channel's whole conversation going to a model,
including whatever someone pasted from a client system. Being addressed
is the consent signal, and it is the user's own deliberate act.

**The answer is scoped to one engagement.** The channel decides which:
the agent gets exactly the tools that channel's project would give it,
so a question asked in one engagement's channel cannot be answered with
another's data. A channel that belongs to no project gets told so rather
than being answered from everything.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from .db import SessionLocal

log = logging.getLogger("oddjob.slack.socket")

#: Slack drops the socket if an envelope is not acknowledged quickly.
#: Acking first and working afterwards is the documented pattern.
ACK_DEADLINE = 3.0
#: Reconnect backoff, seconds. Slack rotates the URL roughly hourly and
#: closes the socket to say so, which is normal, not an error.
BACKOFF_START = 2.0
BACKOFF_MAX = 120.0


async def open_url(app_token: str) -> str:
    """Ask Slack for a websocket URL. Raises on refusal."""
    from .slack import API
    async with httpx.AsyncClient(timeout=20) as c:
        r = await c.post(f"{API}/apps.connections.open",
                         headers={"Authorization": f"Bearer {app_token}"})
        d = r.json()
    if not d.get("ok"):
        raise RuntimeError(f"apps.connections.open: {d.get('error')}")
    return d["url"]


def _question(event: dict) -> str:
    """The text with the bot mention stripped.

    Leaving `<@U123>` in makes the model answer the mention rather than
    the question surprisingly often.
    """
    import re
    return re.sub(r"<@[A-Z0-9]+>", "", event.get("text") or "").strip()


async def _project_for_channel(session, channel_id: str, channel_name: str | None):
    """Which engagement this channel belongs to, or None.

    Matched on the stored channel name. The id is not stored anywhere —
    projects record the human name — so the name is what we have, and a
    channel we cannot place is answered with a refusal rather than with
    data from somewhere else.
    """
    from sqlalchemy import select
    from .models import Project
    from .slack import normalise_channel

    want = normalise_channel(channel_name or "") or channel_id
    rows = (await session.execute(select(Project))).scalars().all()
    for p in rows:
        if (p.slack_channel or "").lower() == want:
            return p
    return None


async def answer(session, project, question: str) -> str:
    """Ask the engagement's agent, with that engagement's tools."""
    from .agent.providers import anthropic_chat, openai_chat
    from .agent.tools import build, run
    from .routers.agent import SYSTEM, WRITES_OFF, _resolve

    provider, token, model, _src, base_url, cfg = await _resolve(session, project)
    if provider != "local" and not token:
        return ("No model is configured for this engagement, so I cannot "
                "answer. Set one in Site Config → Agent.")
    if provider == "local" and not base_url:
        return "No local model server is configured, so I cannot answer."

    # Read-only, always. A question asked in a chat channel is not an
    # instruction to change the engagement's data, and the person
    # asking may not even be the one who typed it.
    #
    # `build` only constructs the write tools when the third argument
    # is true, so the stand-in is never dereferenced today. It exists
    # so that if that ever changes the attribution reads "agent(slack)"
    # instead of raising AttributeError on None.
    tools = build(session, project, _SlackActor(), False)
    system = SYSTEM.format(
        code=project.code, client=f" for {project.client}" if project.client else "",
        writes=WRITES_OFF)
    steps = max(1, min(int(cfg.get("agent.max_steps") or 12), 50))
    msgs = [{"role": "user", "content": question}]
    if provider == "anthropic":
        reply = await anthropic_chat(token, model, system, msgs, tools, run, steps)
    else:
        reply = await openai_chat(token, model, system, msgs, tools, run, steps,
                                  base_url=base_url)
    return (reply.text or "").strip() or "I had nothing to add."


class _SlackActor:
    """Stands in for the User the HTTP chat path has. See `answer`."""
    username = "slack"
    id = None


class Worker:
    """One websocket, restarted for as long as the app runs."""

    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.last: str | None = None
        self.connected = False

    def start(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

    async def _config(self) -> tuple[str, str, bool]:
        from .routers.settings import load_all
        async with SessionLocal() as s:
            cfg = await load_all(s)
        return (str(cfg.get("slack.app_token") or "").strip(),
                str(cfg.get("slack.bot_token") or "").strip(),
                bool(cfg.get("slack.answer_questions", False)))

    async def _loop(self) -> None:
        import websockets

        delay = BACKOFF_START
        while True:
            try:
                app_token, bot_token, on = await self._config()
                if not (on and app_token and bot_token):
                    self.connected = False
                    self.last = ("answering is off" if not on
                                 else "no app-level token (xapp-…)" if not app_token
                                 else "no bot token")
                    await asyncio.sleep(30)
                    continue

                url = await open_url(app_token)
                async with websockets.connect(url, open_timeout=20) as ws:
                    self.connected = True
                    self.last = "connected"
                    delay = BACKOFF_START
                    log.info("slack socket connected")
                    async for raw in ws:
                        await self._envelope(ws, raw, bot_token)
            except asyncio.CancelledError:
                raise
            except Exception as e:                   # noqa: BLE001
                self.connected = False
                self.last = f"{type(e).__name__}: {e}"[:300]
                log.warning("slack socket: %s — retrying in %.0fs", e, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, BACKOFF_MAX)

    async def _envelope(self, ws, raw: str, bot_token: str) -> None:
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        kind = msg.get("type")
        if kind == "hello":
            return
        if kind == "disconnect":
            # Slack rotating the URL. Closing makes the outer loop
            # reconnect, which is what it is asking for.
            await ws.close()
            return

        env = msg.get("envelope_id")
        if env:
            # Ack FIRST. Slack retries anything unacknowledged within a
            # few seconds, and a model call takes longer than that — a
            # slow answer would otherwise be asked three times.
            await ws.send(json.dumps({"envelope_id": env}))

        if kind != "events_api":
            return
        event = ((msg.get("payload") or {}).get("event")) or {}
        if event.get("type") != "app_mention":
            return
        if event.get("bot_id") or event.get("subtype"):
            return               # never answer ourselves or a system message

        asyncio.create_task(self._answer(event, bot_token))

    async def _answer(self, event: dict, bot_token: str) -> None:
        from .slack import post

        channel = event.get("channel") or ""
        # Reply in the thread it was asked in, starting one if needed:
        # an answer that lands loose in the channel loses its question.
        thread = event.get("thread_ts") or event.get("ts")
        question = _question(event)
        if not question:
            await post(bot_token, channel,
                       "Ask me something about this engagement.", thread_ts=thread)
            return

        try:
            async with SessionLocal() as session:
                name = await self._channel_name(bot_token, channel)
                project = await _project_for_channel(session, channel, name)
                if project is None:
                    await post(
                        bot_token, channel,
                        f"This channel is not linked to an engagement, so I "
                        f"will not guess which data to answer from. Set a "
                        f"project's Slack channel to `{name or channel}`.",
                        thread_ts=thread)
                    return
                text = await answer(session, project, question)
            await post(bot_token, channel, text, thread_ts=thread)
        except Exception as e:                       # noqa: BLE001
            log.exception("answering slack question failed")
            # Say so in the thread. Silence looks identical to the bot
            # being offline, and the person waits.
            await post(bot_token, channel,
                       f":warning: I could not answer that: "
                       f"`{type(e).__name__}: {e}`"[:600], thread_ts=thread)

    async def _channel_name(self, bot_token: str, channel_id: str) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                from .slack import API
                r = await c.post(
                    f"{API}/conversations.info",
                    headers={"Authorization": f"Bearer {bot_token}"},
                    json={"channel": channel_id})
                d = r.json()
            return ((d.get("channel") or {}).get("name")) if d.get("ok") else None
        except Exception:                            # noqa: BLE001
            return None


worker = Worker()
