#!/usr/bin/env python3
"""Deterministic claim-scope normalization shared by SignalTrace specialists."""

from __future__ import annotations

import datetime as _dt
import decimal
import re
import unicodedata
from typing import Any, Mapping

FIELDS = (
    "entity", "predicate", "value", "unit", "plan", "version", "variant",
    "region", "date", "operation", "source_location",
)
QUALIFIERS = ("unit", "plan", "version", "variant", "region", "date", "operation")
RESULTS = {"compatible", "conflicting", "ambiguous", "insufficient-evidence"}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, decimal.Decimal)):
        try:
            return format(decimal.Decimal(str(value)).normalize(), "f")
        except decimal.InvalidOperation:
            return str(value)
    if isinstance(value, (list, tuple, set)):
        parts = sorted(filter(None, (_text(item) for item in value)))
        return " | ".join(parts) or None
    value = unicodedata.normalize("NFKC", str(value))
    value = re.sub(r"\s+", " ", value).strip().casefold()
    return value or None


def _date(value: Any) -> str | None:
    raw = _text(value)
    if not raw:
        return None
    candidate = raw.replace("z", "+00:00")
    try:
        return _dt.datetime.fromisoformat(candidate).date().isoformat()
    except ValueError:
        try:
            return _dt.date.fromisoformat(candidate).isoformat()
        except ValueError:
            return raw


def normalize_scope(claim: Mapping[str, Any] | None) -> dict[str, str | None]:
    """Return a stable object containing all and only the shared scope fields."""
    claim = claim or {}
    normalized = {field: _text(claim.get(field)) for field in FIELDS}
    normalized["date"] = _date(claim.get("date"))
    if normalized["unit"]:
        normalized["unit"] = normalized["unit"].upper()
    if normalized["region"]:
        normalized["region"] = normalized["region"].upper()
    return normalized


def compare_scopes(left: Mapping[str, Any] | None,
                   right: Mapping[str, Any] | None) -> str:
    """Compare two claims without dropping material qualifications."""
    a, b = normalize_scope(left), normalize_scope(right)
    if not a["entity"] or not a["predicate"] or not b["entity"] or not b["predicate"]:
        return "insufficient-evidence"
    if a["entity"] != b["entity"] or a["predicate"] != b["predicate"]:
        return "insufficient-evidence"
    for field in QUALIFIERS:
        if (a[field] is None) != (b[field] is None):
            return "ambiguous"
        if a[field] is not None and a[field] != b[field]:
            return "insufficient-evidence"
    if a["value"] is None or b["value"] is None:
        return "insufficient-evidence"
    return "compatible" if a["value"] == b["value"] else "conflicting"


if __name__ == "__main__":
    import json
    import sys
    payload = json.load(sys.stdin)
    print(json.dumps({
        "left": normalize_scope(payload.get("left")),
        "right": normalize_scope(payload.get("right")),
        "result": compare_scopes(payload.get("left"), payload.get("right")),
    }, sort_keys=True))
