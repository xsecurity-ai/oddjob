"""Site configuration. Site admins only.

Secrets are WRITE-ONLY. The API never returns an SMTP password or a Slack
token, only whether one is set. A config screen that renders secrets back
into an input box leaks them to anyone who reaches the page, gets a
screenshot, or reads the response in a proxy — and there is no reason to:
the only legitimate operation is replacing it.
"""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import audit
from ..db import get_session
from ..dsn import is_masked
from ..dsn import mask as dsn_mask
from ..events import broker
from ..models import Setting, User
from ..provider_tests import ENABLE_KEY, GATE_KEYS, issue_token, run_test, token_matches
from ..security import get_current_user, require_site_admin
from ..settings_spec import BY_KEY, GROUPS, SECRET_KEYS, SPEC

router = APIRouter(prefix="/api/settings", tags=["settings"])


class SettingsOut(BaseModel):
    spec: list[dict]
    groups: list[str]
    values: dict[str, object]
    # key -> whether a secret is currently stored. The value itself never ships.
    secrets_set: dict[str, bool]


class SettingsPatch(BaseModel):
    values: dict[str, object]
    # Proof that these exact credentials passed their Test, one per provider.
    # Absent is fine when nothing gated changed.
    test_tokens: dict[str, str] = {}


class TestRequest(BaseModel):
    """The values currently in the form, not the ones already saved.

    Testing the stored config would be useless here: the whole point is to
    find out whether what you just typed works, before it replaces something
    that does.
    """
    values: dict[str, object] = {}
    to: str | None = None          # SMTP recipient


class TestResult(BaseModel):
    ok: bool
    detail: str
    # Present only on success. Hand it back with the save.
    token: str | None = None


async def load_all(session: AsyncSession) -> dict[str, object]:
    """Every setting, defaults filled in. Secrets included — for internal use
    only; the HTTP layer strips them."""
    rows = {s.key: s.value for s in (await session.execute(select(Setting))).scalars()}
    out: dict[str, object] = {}
    for spec in SPEC:
        raw = rows.get(spec["key"])
        if raw is None:
            out[spec["key"]] = spec.get("default")
            continue
        if spec["type"] == "bool":
            out[spec["key"]] = raw == "1"
        elif spec["type"] == "number":
            try:
                out[spec["key"]] = int(raw)
            except ValueError:
                out[spec["key"]] = spec.get("default")
        else:
            out[spec["key"]] = raw
    return out


async def get_value(session: AsyncSession, key: str):
    return (await load_all(session)).get(key)


@router.get("", response_model=SettingsOut)
async def read_settings(_: User = Depends(require_site_admin),
                        session: AsyncSession = Depends(get_session)):
    values = await load_all(session)
    secrets_set = {k: bool(values.get(k)) for k in SECRET_KEYS}
    for k in SECRET_KEYS:
        values.pop(k, None)
    # A DSN is NOT write-only. Hiding it entirely would mean the config
    # screen could never show which database you are pointed at, which is
    # the thing you check before trusting it. Only the password is masked,
    # and the masking is done on the parsed URL — a regex over the raw
    # string leaks the tail of any password containing @ : or /.
    for k in DSN_KEYS:
        if values.get(k):
            values[k] = dsn_mask(str(values[k]))
    return SettingsOut(spec=SPEC, groups=GROUPS, values=values, secrets_set=secrets_set)


DSN_KEYS = {s["key"] for s in SPEC if s["type"] == "dsn"}


def merge_draft(stored: dict, draft: dict) -> dict:
    """The config that would result if `draft` were saved.

    A blank secret means "unchanged", exactly as the save path treats it, so
    the test exercises the stored password rather than an empty one — which
    is what makes "test, then save" agree with itself.
    """
    out = dict(stored)
    for key, val in draft.items():
        spec = BY_KEY.get(key)
        if spec is None:
            continue
        if spec["type"] == "secret" and (val is None or val == ""):
            continue
        # The form round-trips the masked string. Saving that verbatim
        # would store "••••••••" as the password and break the connection
        # in a way that looks like a server fault rather than a mistake.
        if spec["type"] == "dsn" and (val is None or val == "" or is_masked(str(val))):
            continue
        if spec["type"] == "bool":
            out[key] = bool(val)
        elif spec["type"] == "number":
            try:
                out[key] = int(val)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                pass
        else:
            out[key] = "" if val is None else str(val)
    return out


# The field that decides whether a provider is configured at all. Blanking it
# is how you turn the integration off, and that must not require a passing
# test — otherwise a bad password becomes impossible to remove.
_PRIMARY = {"smtp": "smtp.host", "google": "auth.google_client_id",
            "postgres": "db.external_url"}


def enforce_test_gate(stored: dict, effective: dict, tokens: dict[str, str]) -> None:
    """Refuse credentials that have not been proven to work.

    Only on change: editing the allowed-domains list, or any ungated setting,
    must not demand a round of testing nobody needs.
    """
    for provider, keys in GATE_KEYS.items():
        enable_key = ENABLE_KEY.get(provider)
        changed = any(effective.get(k) != stored.get(k) for k in keys)
        turning_on = bool(enable_key and effective.get(enable_key)
                          and not stored.get(enable_key))
        if not (changed or turning_on):
            continue
        if not str(effective.get(_PRIMARY[provider]) or "").strip():
            if turning_on:
                raise HTTPException(
                    409, f"{provider} cannot be enabled with no "
                         f"{BY_KEY[_PRIMARY[provider]]['label'].lower()} set")
            continue        # being switched off, not configured
        ok, why = token_matches(tokens.get(provider), provider, effective)
        if not ok:
            raise HTTPException(409, why)


class PublicDefaults(BaseModel):
    """The few settings a non-admin legitimately needs to see.

    The new-engagement dialog has to show what a channel will be called and
    whether it will be private, and anyone may create an engagement. Serving
    the whole settings object to do that would hand every user the SMTP
    host, the Google client ID and the rest of the site's configuration.
    """
    slack_channel_prefix: str = ""
    slack_default_private: bool = True


@router.get("/defaults", response_model=PublicDefaults)
async def public_defaults(_: User = Depends(get_current_user),
                          session: AsyncSession = Depends(get_session)):
    cfg = await load_all(session)
    return PublicDefaults(
        slack_channel_prefix=str(cfg.get("slack.channel_prefix") or ""),
        slack_default_private=bool(cfg.get("slack.default_private", True)))


@router.patch("", response_model=SettingsOut)
async def write_settings(body: SettingsPatch, user: User = Depends(require_site_admin),
                         session: AsyncSession = Depends(get_session)):
    unknown = set(body.values) - set(BY_KEY)
    if unknown:
        raise HTTPException(422, f"unknown setting(s): {sorted(unknown)}")

    stored = await load_all(session)
    enforce_test_gate(stored, merge_draft(stored, body.values), body.test_tokens)

    for key, val in body.values.items():
        spec = BY_KEY[key]
        # An empty string for a secret means "leave it alone", not "clear it".
        # Otherwise the UI — which cannot show the current value — would wipe
        # the token every time somebody saved an unrelated field.
        if spec["type"] == "secret" and (val is None or val == ""):
            continue
        # The form round-trips the masked string. Saving that verbatim
        # would store "••••••••" as the password and break the connection
        # in a way that looks like a server fault rather than a mistake.
        if spec["type"] == "dsn" and (val is None or val == "" or is_masked(str(val))):
            continue
        if spec["type"] == "bool":
            stored = "1" if val else "0"
        elif spec["type"] == "number":
            try:
                stored = str(int(val))  # type: ignore[arg-type]
            except (TypeError, ValueError) as e:
                raise HTTPException(422, f"{key} must be a number") from e
        elif spec["type"] == "select":
            if val not in spec["options"]:
                raise HTTPException(422, f"{key} must be one of {spec['options']}")
            stored = str(val)
        else:
            stored = "" if val is None else str(val)

        row = await session.get(Setting, key)
        if row is None:
            session.add(Setting(key=key, value=stored, updated_by=user.id))
        else:
            row.value, row.updated_by = stored, user.id

    # The KEYS that changed, never the values. Site settings are where
    # the bot tokens and the DSN live, and this table is readable by
    # every site admin — "slack.bot_token was changed" is the audit
    # fact; what it was changed to is a credential.
    await audit.record(
        session, "ui", "settings.update", user=user,
        detail=("changed: " + ", ".join(sorted(body.values))
                if body.values else "no keys changed"))
    await session.commit()
    # base_url, the allowed origins and the HSTS policy all feed the
    # security headers; recompute rather than making them need a restart.
    from ..headers import refresh as refresh_headers
    await refresh_headers(session)
    # No project: settings are installation-wide and the view is
    # site-admin only, so unlabelled delivery is the right audience.
    await broker.publish("settings", action="update")
    return await read_settings(user, session)


@router.delete("/{key}", status_code=204)
async def clear_setting(key: str, user: User = Depends(require_site_admin),
                        session: AsyncSession = Depends(get_session)):
    """Explicitly clear a value — the only way to remove a stored secret,
    since an empty PATCH is treated as 'unchanged'."""
    if key not in BY_KEY:
        raise HTTPException(404, f"unknown setting {key!r}")
    row = await session.get(Setting, key)
    if row:
        await session.delete(row)
    # Deleting a credential must not leave the feature switched on pointing at
    # nothing — that would be a way around the test gate, and it would present
    # users a sign-in button that cannot work.
    for provider, keys in GATE_KEYS.items():
        if key in keys and (enable := ENABLE_KEY.get(provider)):
            flag = await session.get(Setting, enable)
            if flag is not None:
                flag.value, flag.updated_by = "0", user.id
    await session.commit()
    # No project: settings are installation-wide and the view is
    # site-admin only, so unlabelled delivery is the right audience.
    await broker.publish("settings", action="clear")


# ------------------------------------------------------------------ tests
@router.post("/test/{provider}", response_model=TestResult)
async def test_provider(provider: str, body: TestRequest | None = None,
                        to: str | None = None,
                        user: User = Depends(require_site_admin),
                        session: AsyncSession = Depends(get_session)):
    """Exercise the draft credentials for real and, on success, issue the
    proof the save will demand.

    The token is bound to a digest of the exact values tested, so passing a
    test and then saving something else does not work.
    """
    if provider not in GATE_KEYS and provider != "slack":
        raise HTTPException(404, f"nothing to test for {provider!r}")
    body = body or TestRequest()
    effective = merge_draft(await load_all(session), body.values)

    if provider == "slack":
        # Not gated: a missing Slack token degrades one feature, it does not
        # lock anybody out, so requiring a pass before saving would be noise.
        ok, detail = await _slack(effective)
        return TestResult(ok=ok, detail=detail)

    ok, detail = await run_test(provider, effective, body.to or to or user.email)
    return TestResult(ok=ok, detail=detail,
                      token=issue_token(provider, effective) if ok else None)


async def _slack(cfg: dict) -> tuple[bool, str]:
    token = cfg.get("slack.bot_token")
    if not token:
        return False, "no Slack bot token configured"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post("https://slack.com/api/auth.test",
                             headers={"Authorization": f"Bearer {token}"})
        data = r.json()
    except Exception as e:
        return False, f"could not reach Slack: {type(e).__name__}: {e}"
    if not data.get("ok"):
        return False, f"Slack said: {data.get('error')}"
    return True, f"authenticated as {data.get('user')} on {data.get('team')}"
