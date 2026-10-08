"""The websocket Slack delivers inbound events over, and nothing else.

Everything in `app/slack.py` is outbound. This is the transport for the
inbound half; every *decision* about an inbound message lives in
`app/slackchat.py`, which is why that module can be tested without a
socket and this one is deliberately almost empty.

Socket Mode, not the Events API. Slack opens nothing towards us: we open
a websocket towards Slack, so this works with the app bound to 127.0.0.1
behind no public hostname, with no TLS certificate to obtain and no
request-signature or replay-window check to get subtly wrong. On a host
holding client engagement data, not adding an internet-facing endpoint
is worth more than the convenience of an HTTP handler.

The shape:

    POST apps.connections.open  (app-level token, xapp-…)
      -> a one-shot wss:// URL
    connect, then for each envelope
      -> ack it by envelope_id within 3 seconds, or Slack retries
      -> hand it to slackchat.on_event
"""
from __future__ import annotations

import asyncio
import json
import logging

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


class Worker:
    """One websocket, restarted for as long as the app runs.

    The single long-lived connection for the process, started from the
    lifespan in `main.py` beside the remediation worker. Deliberately
    not a second scheduler: it holds no session of its own between
    events, and each event opens and closes one.
    """

    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.last: str | None = None
        self.connected = False
        #: Our own Slack user id, resolved once per connection. Without
        #: it we cannot tell our own voice from anyone else's, so an
        #: unresolved identity means answering nothing at all — the
        #: alternative is a bot that replies to itself.
        self.bot_user_id: str | None = None

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

    async def _config(self) -> tuple[str, str, bool, dict]:
        from .routers.settings import load_all
        async with SessionLocal() as s:
            cfg = await load_all(s)
        return (str(cfg.get("slack.app_token") or "").strip(),
                str(cfg.get("slack.bot_token") or "").strip(),
                bool(cfg.get("slack.answer_questions", False)),
                cfg)

    async def _loop(self) -> None:
        import websockets

        from .slackchat import bot_identity

        delay = BACKOFF_START
        while True:
            try:
                app_token, bot_token, on, cfg = await self._config()
                if not (on and app_token and bot_token):
                    self.connected = False
                    self.last = ("answering is off" if not on
                                 else "no app-level token (xapp-…)" if not app_token
                                 else "no bot token")
                    await asyncio.sleep(30)
                    continue

                self.bot_user_id = await bot_identity(bot_token)
                if not self.bot_user_id:
                    # Said plainly and retried, rather than connecting
                    # and answering blind: every loop-safety rule in
                    # slackchat is anchored on knowing which user we are.
                    self.connected = False
                    self.last = ("auth.test did not return a user id — the "
                                 "bot token may be wrong; not answering "
                                 "until it does")
                    await asyncio.sleep(30)
                    continue

                url = await open_url(app_token)
                async with websockets.connect(url, open_timeout=20) as ws:
                    self.connected = True
                    self.last = f"connected as {self.bot_user_id}"
                    delay = BACKOFF_START
                    log.info("slack socket connected as %s", self.bot_user_id)
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
        if event.get("type") not in ("app_mention", "message"):
            return
        # An @-mention in a channel arrives TWICE, once as app_mention
        # and once as message, with the same ts. `slackchat.budget`
        # de-duplicates on (channel, ts), so both are forwarded and
        # exactly one is answered.
        asyncio.create_task(self._dispatch(event, bot_token))

    async def _dispatch(self, event: dict, bot_token: str) -> None:
        from .routers.settings import load_all
        from .slackchat import on_event
        try:
            # Read per message rather than per connection: a setting
            # changed in the UI has to take effect without waiting for
            # Slack to rotate the socket an hour from now, and the
            # settings that matter here are the ones that say what the
            # bot may do.
            async with SessionLocal() as s:
                cfg = await load_all(s)
            if not bool(cfg.get("slack.answer_questions", False)):
                return
            await on_event(event, bot_token, self.bot_user_id, cfg)
        except asyncio.CancelledError:
            raise
        except Exception:                            # noqa: BLE001
            log.exception("slack event dispatch failed")


worker = Worker()
