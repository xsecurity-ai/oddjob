"""Screenshots from the Ghost's in-process browser.

`{"shots": [{"url": ..., "png_base64": ...}, ...], "failed": [...]}` --
the shape `ghost/internal/tasks/screenshot.go` writes.

**The image arrives as base64 and leaves here as bytes.** It cannot
travel any other way: the agent's result is one JSON document stored
in a text column on the way through, and a PNG contains NUL bytes,
which Postgres refuses in text outright. Decoding once, here, is also
the only place that can say whether what arrived is actually a PNG --
a field named `png_base64` holding something else is not a picture,
and storing it would put a file in the database that renders as
nothing and explains itself to nobody.

**Capped on the way in, twice.** An estate has reached 51,000 URLs;
one picture each at a couple of hundred kilobytes is already a
sizeable database, and nothing downstream of here would notice a task
that returned a thousand. The agent has its own caps -- this is the
server's, because the agent's are arguments an operator can raise and
this is the database.
"""
from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime

from ..weburl import BadUrl
from ..weburl import parse as parse_url
from .model import (
    ImportError_,
    ParsedScan,
    ParsedScreenshot,
    ParsedWebAddress,
)

#: What a PNG starts with. Checked rather than trusted: see above.
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

#: The biggest single image this will store, and the most it will
#: take from one task.
#:
#: The agent defaults to 3 MB an image and a 24 MB budget per task.
#: These are deliberately a little above that, so an operator who
#: raised the agent's limit for one job still lands rather than
#: silently losing the result -- and far enough below "whatever
#: arrived" that one task cannot decide how large this database gets.
MAX_IMAGE_BYTES = 4 * 1024 * 1024
MAX_SHOTS = 200


def looks_like(text: str) -> bool:
    head = text.lstrip()[:2000]
    if not head.startswith("{"):
        return False
    return '"shots"' in head and ('"viewport"' in head or '"browser"' in head)


def parse(text: str) -> ParsedScan:
    scan = ParsedScan(tool="screenshot")
    try:
        doc = json.loads(text or "")
    except ValueError as e:
        raise ImportError_(f"not a screenshot result: {e}") from e
    if not isinstance(doc, dict):
        raise ImportError_("a screenshot result is an object")

    shots = doc.get("shots")
    if not isinstance(shots, list):
        raise ImportError_("a screenshot result carries a `shots` list")

    seen: set[str] = set()
    for rec in shots[:MAX_SHOTS]:
        if not isinstance(rec, dict):
            continue
        raw = str(rec.get("url") or "").strip()
        if not raw:
            continue
        try:
            u = parse_url(raw)
        except BadUrl as e:
            scan.errors.append(f"{raw}: {e}")
            continue
        if u.url in seen:
            # One picture per URL. The agent should not send two, and
            # if it does the first is as good an answer as the
            # second -- what must not happen is two rows racing for
            # the same unique key inside one import.
            continue

        img = _image(rec, scan)
        if img is None:
            continue
        seen.add(u.url)

        status = rec.get("status")
        scan.screenshots.append(ParsedScreenshot(
            url=u.url, host=u.host, image=img,
            final_url=(str(rec["final_url"])[:4096]
                       if rec.get("final_url") else None),
            # A status of 0 is the agent saying the browser never
            # reported one, which is not a status. `omitempty` means
            # it is usually absent; this guards the case where it is
            # not.
            status_code=(int(status)
                         if isinstance(status, int) and status else None),
            title=(str(rec["title"])[:512] if rec.get("title") else None),
            # The IMAGE's type, which is not the page's. It is
            # `image/png` because `_image` has just verified the
            # magic bytes -- not because the record said so.
            content_type="image/png",
            width=(int(rec["width"]) if isinstance(rec.get("width"), int)
                   else None),
            height=(int(rec["height"]) if isinstance(rec.get("height"), int)
                    else None),
            sha256=(str(rec["sha256"])[:64] if rec.get("sha256") else None),
            captured_at=datetime.now(UTC)))

        # The URL itself, as well as the picture.
        #
        # `crawled=True`, unlike a crawl result: a browser did not
        # merely see this address mentioned, it asked for it and
        # drew what came back. That is the strongest evidence any
        # importer here produces that a page exists.
        #
        # It also gives the picture somewhere to be shown. The Web
        # view lists `web_addresses`, so a screenshot of a URL with
        # no row would be a photograph nobody can find -- and a URL
        # known only from a wordlist gets its status and title
        # filled in by this.
        scan.web.append(ParsedWebAddress(
            url=u.url, host=u.host, scheme=u.scheme, port=u.port,
            method="GET",
            status_code=(int(status)
                         if isinstance(status, int) and status else None),
            title=(str(rec["title"])[:512] if rec.get("title") else None),
            content_type=(str(rec.get("page_content_type") or "")[:128]
                          or None),
            webserver=(str(rec["server"])[:255] if rec.get("server") else None),
            crawled=True,
            notes="photographed in a browser"))

    # The pages that could not be photographed, carried through as
    # errors rather than dropped. "18 of 20" with no account of the
    # other two is the substitution this codebase treats as a bug:
    # absent and could-not-determine are different answers.
    failed = doc.get("failed")
    if isinstance(failed, list):
        for rec in failed[:MAX_SHOTS]:
            if not isinstance(rec, dict):
                continue
            scan.errors.append(
                f"{rec.get('url') or 'a page'}: "
                f"{rec.get('error') or 'could not be photographed'}")

    if not scan.screenshots:
        raise ImportError_(
            "the screenshot task returned no usable image"
            + (f" ({len(scan.errors)} page(s) could not be photographed)"
               if scan.errors else ""))
    return scan


def _image(rec: dict, scan: ParsedScan) -> bytes | None:
    """The PNG out of one record, or None with a reason recorded.

    Every refusal is appended to `scan.errors`. A picture that was
    taken and then dropped here is a fact about this import, and
    swallowing it would leave an operator comparing "20 captured" on
    the task against 17 rows in the table with nothing to explain the
    difference.
    """
    b64 = rec.get("png_base64") or rec.get("png") or ""
    if not isinstance(b64, str) or not b64:
        scan.errors.append(f"{rec.get('url')}: no image in the record")
        return None
    # The encoded form is 4/3 of the bytes: checked BEFORE decoding,
    # so a hostile or broken agent cannot make this process allocate
    # whatever it felt like sending.
    if len(b64) > MAX_IMAGE_BYTES // 3 * 4 + 16:
        scan.errors.append(
            f"{rec.get('url')}: the image is larger than the "
            f"{MAX_IMAGE_BYTES // 1024 // 1024} MB this will store")
        return None
    try:
        img = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        scan.errors.append(f"{rec.get('url')}: the image is not valid base64")
        return None
    if len(img) > MAX_IMAGE_BYTES:
        scan.errors.append(
            f"{rec.get('url')}: the image is {len(img)} bytes, past the "
            f"{MAX_IMAGE_BYTES} this will store")
        return None
    if not img.startswith(PNG_MAGIC):
        # Not pedantry. Whatever this is, it is not what the field
        # says it is, and the one thing worse than no screenshot is a
        # screenshot that is not a picture of anything.
        scan.errors.append(f"{rec.get('url')}: the image is not a PNG")
        return None
    return img


def without_images(text: str | None) -> str | None:
    """The same result with the base64 payloads taken out.

    Called once the images are in `web_screenshots`, because the
    agent's result is kept verbatim on the task row and that would
    otherwise be a SECOND copy of every picture -- the larger one,
    since base64 is 4/3 of the bytes, and the one that is never read.
    Across an estate photographed a page at a time it is the biggest
    thing in the database by a wide margin, and it answers no
    question: the image endpoint reads the table.

    Everything else about the capture stays: the URL, the status, the
    title, the digest, and the list of pages that failed. So the task
    still says exactly what it did, and `stored_in_database` says
    where the bytes went rather than leaving a reader to wonder
    whether they ever arrived.

    Returns the input unchanged if it cannot be read as one of these
    -- stripping is a tidy-up, and losing a result over it would be a
    far worse trade.
    """
    if not text:
        return text
    try:
        doc = json.loads(text)
    except ValueError:
        return text
    if not isinstance(doc, dict) or not isinstance(doc.get("shots"), list):
        return text
    changed = False
    for rec in doc["shots"]:
        if isinstance(rec, dict) and rec.pop("png_base64", None) is not None:
            rec["stored_in_database"] = True
            changed = True
    if not changed:
        return text
    return json.dumps(doc, indent=2)
