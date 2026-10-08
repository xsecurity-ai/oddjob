"""XML parsing for files we did not produce.

Every importer here reads a document that came from somewhere else — a
scanner run by someone else, a proxy history exported from another
engagement, a file a client emailed over. That is untrusted input, and
`xml.etree.ElementTree` is not safe for it.

Measured, not assumed:

* **External entities are already refused.** `<!ENTITY x SYSTEM
  "file:///etc/passwd">` raises a ParseError on this Python — expat is
  built without external entity loading, so XXE file disclosure does not
  work.
* **Internal entity expansion is not.** A 331-byte document expanded to
  1 MB in no measurable time, and each further nesting level multiplies
  by ten. Against a 64 MB upload limit that is a trivial way to exhaust
  the server's memory during an import.

So: defusedxml, which refuses entity references outright. DTDs
themselves are still allowed, because some real scanner output carries a
DOCTYPE without ever referencing an entity, and rejecting those would
turn a security fix into a compatibility break.
"""
from __future__ import annotations

from collections.abc import Iterator
from xml.etree.ElementTree import Element, ParseError  # nosemgrep: use-defused-xml

from defusedxml.ElementTree import fromstring as _defused
from defusedxml.ElementTree import iterparse as _defused_iterparse


def fromstring(text: str | bytes) -> Element:
    """Parse untrusted XML, or raise ParseError.

    defusedxml raises its own exception types for the attacks it blocks
    (EntitiesForbidden, ExternalReferenceForbidden). Those are translated
    to ParseError so every caller's existing `except ET.ParseError`
    handler reports them as "not valid XML" — which, for the operator
    holding the file, is the useful summary.
    """
    try:
        return _defused(text)
    except ParseError:
        raise
    except Exception as e:
        # DTDForbidden / EntitiesForbidden / ExternalReferenceForbidden
        raise ParseError(
            f"refused for safety: {type(e).__name__}. The document uses XML "
            f"entities, which are not processed here because an expanding "
            f"entity can exhaust the server's memory.") from e


def stream(path: str, tag: str, root_tag: str | None = None
           ) -> Iterator[tuple[Element, Element]]:
    """Yield `(element, root)` for every `<tag>` in a file, in bounded memory.

    `fromstring` builds the whole document before anything can look at
    it, which is fine for a 2 MB nmap run and impossible for a 2.5 GB
    Burp history — measured here at 357,276 items. This walks the file
    instead, and the caller clears each element when it is done:

        for el, root in stream(path, "item"):
            ...
            el.clear(); root.clear()

    Both clears matter. `el.clear()` alone still leaves the root holding
    a reference to every element it has seen, so memory grows exactly as
    it would with a full parse. With both, the 2.5 GB file parses in
    ~6.6 s at a flat 157 MB.

    The same defusedxml protection applies: entity references raise
    rather than expanding.
    """
    it = _defused_iterparse(path, events=("start", "end"))
    try:
        _, root = next(it)
    except StopIteration as e:
        raise ParseError("empty document") from e
    except ParseError:
        raise
    except Exception as e:
        raise ParseError(f"refused for safety: {type(e).__name__}") from e

    if root_tag and root.tag != root_tag:
        raise ParseError(f"expected <{root_tag}>, got <{root.tag}>")

    def walk():
        for event, el in it:
            if event == "end" and el.tag == tag:
                yield el, root
    try:
        yield from walk()
    except ParseError:
        raise
    except Exception as e:
        raise ParseError(
            f"refused for safety: {type(e).__name__}. The document uses XML "
            f"entities, which are not processed here.") from e


def peek(path: str, nbytes: int = 4000) -> str:
    """The first few KB of a file as text, for format detection.

    Detection only ever looks at the head, and reading a multi-gigabyte
    file into a string to decide what it is would defeat the point of
    streaming it afterwards.
    """
    with open(path, "rb") as fh:
        return fh.read(nbytes).decode("utf-8", errors="replace")
