"""JSON parsing that keeps what the value model judges (PRUVZ-97).

``json.loads`` with default hooks discards two distinctions this contract's
canonical layer must judge:

- ``-0`` parses to int ``0``, losing the negative zero the value model refuses;
- duplicate member names silently keep the last occurrence — one byte string
  that parses as two different documents, which a verifier refuses as unusable
  input (docs/VERIFIER.md).

``loads`` keeps both: ``-0`` becomes the float ``-0.0`` (which the canonical
layer refuses as NON_INTEGER_NUMBER, exactly like Node's ``JSON.parse``), and
a duplicate member raises DuplicateMemberError before anything downstream can
read either occurrence. ``Infinity``/``NaN`` are refused: they are not JSON.
"""

from __future__ import annotations

import json
from typing import Any


class DuplicateMemberError(ValueError):
    """One byte string that parses as two different documents."""


def _pairs_hook(pairs):
    seen = set()
    out = {}
    for key, value in pairs:
        if key in seen:
            raise DuplicateMemberError(
                f"duplicate member name {key!r}: one byte string that parses as two different "
                "documents is unusable input"
            )
        seen.add(key)
        out[key] = value
    return out


def _parse_int(text: str):
    if text == "-0":
        return -0.0
    return int(text)


def _parse_constant(text: str):
    raise ValueError(f"{text} is not JSON")


def loads(text: str) -> Any:
    """Parses JSON strictly: duplicate members refused, ``-0`` kept judgeable,
    non-JSON constants refused."""
    return json.loads(
        text,
        object_pairs_hook=_pairs_hook,
        parse_int=_parse_int,
        parse_constant=_parse_constant,
    )
