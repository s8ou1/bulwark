"""Canonical JSON + digest helpers for reports, intents and audit entries.

Canonical form: UTF-8, keys sorted, no whitespace, integers/strings/bools/null/
lists/dicts only. Floats are REJECTED on purpose - float formatting differs
across languages and would make digests non-reproducible. Put decimals in
strings (e.g. "0.0123") or use integer micro-units.
"""
from __future__ import annotations

import json
from typing import Any

from .keccak import keccak256


class CanonicalError(ValueError):
    pass


def _check(obj: Any, path: str = "$") -> None:
    if obj is None or isinstance(obj, (bool, str)):
        return
    if isinstance(obj, int):
        return
    if isinstance(obj, float):
        raise CanonicalError(f"float not allowed at {path}")
    if isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check(v, f"{path}[{i}]")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalError(f"non-string key at {path}")
            _check(v, f"{path}.{k}")
        return
    raise CanonicalError(f"unsupported type {type(obj).__name__} at {path}")


def canonical_json(obj: Any) -> bytes:
    _check(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(obj: Any) -> bytes:
    """keccak256 of the canonical JSON encoding."""
    return keccak256(canonical_json(obj))


def digest_hex(obj: Any) -> str:
    return "0x" + digest(obj).hex()
