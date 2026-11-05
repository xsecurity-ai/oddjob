"""SMTP sending, shared by the config test and the magic-link flow."""
from __future__ import annotations

import asyncio
import contextlib
import smtplib
import ssl
from email.message import EmailMessage


class MailNotConfigured(RuntimeError):
    pass


def _send_sync(cfg: dict, to: str, subject: str, body: str) -> None:
    host = str(cfg.get("smtp.host") or "")
    if not host:
        raise MailNotConfigured("no SMTP host configured")
    port = int(cfg.get("smtp.port") or 587)
    sec = cfg.get("smtp.security") or "starttls"
    user, pwd = cfg.get("smtp.username"), cfg.get("smtp.password")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp.from_address") or user or "oddjob@localhost"
    msg["To"] = to
    # cte="7bit" for ASCII bodies, to stop quoted-printable inserting a soft
    # line break mid-URL. A sign-in link is ~84 characters; QP wraps at 76
    # and splits the token with a trailing "=", so anything that reads the
    # raw text — a plain-text client, a log, a human copy-pasting — gets a
    # link that silently does not work. Non-ASCII falls back to the default
    # encoding, where correctness matters more than line length.
    if body.isascii():
        msg.set_content(body, cte="7bit")
    else:
        msg.set_content(body)

    if sec == "tls":
        srv = smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context())
    else:
        srv = smtplib.SMTP(host, port, timeout=20)
    try:
        if sec == "starttls":
            srv.starttls(context=ssl.create_default_context())
        if user and pwd:
            srv.login(str(user), str(pwd))
        srv.send_message(msg)
    finally:
        # `quit()` on a connection the server has already dropped raises
        # SMTPServerDisconnected("please run connect() first") -- and from
        # a `finally`, that REPLACES whatever actually went wrong. The
        # operator is then told the cleanup failed and never learns that
        # the password was rejected, or the relay refused the sender, or
        # TLS would not negotiate.
        #
        # It was worth a real hour: a magic link that never arrived
        # reported only "please run connect() first", which describes
        # nothing an operator can act on and is not even true of the send.
        # Closing is best-effort; the send's own outcome is the fact.
        with contextlib.suppress(Exception):
            srv.quit()


async def send_mail(cfg: dict, to: str, subject: str, body: str) -> None:
    """smtplib is blocking; keep it off the event loop.

    Records the outcome, then re-raises. Callers that already handle a
    failure keep handling it; what changes is that an admin can see the
    failure happened at all. A magic link that is never delivered looks,
    from this side, exactly like one nobody clicked.
    """
    from . import servicehealth
    try:
        await asyncio.to_thread(_send_sync, cfg, to, subject, body)
    except Exception as e:                       # noqa: BLE001
        # The subject, not the body, and never the recipient: site
        # admins all read the health page, and "magic link for
        # someone@example.com" is a disclosure.
        await servicehealth.note("smtp", False, str(subject)[:120],
                                 f"{type(e).__name__}: {e}"[:300])
        raise
    await servicehealth.note("smtp", True, str(subject)[:120])
