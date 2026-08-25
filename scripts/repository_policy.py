#!/usr/bin/env python3
"""Shared repository-tool and dependency-audit policy checks."""

from __future__ import annotations

import datetime
import json
import re
import sys
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_EXCEPTIONS_FILE = REPO_ROOT / "tools" / "rustsec-exceptions.json"
MINIMUM_PYTHON = (3, 13)
_ADVISORY_PATTERN = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
_EXCEPTION_FIELDS = {"advisory", "owner", "rationale", "expires"}


def require_supported_python(version: Sequence[int] = sys.version_info) -> None:
    """Reject repository-tool execution on an unsupported Python runtime."""
    actual = tuple(version[:2])
    if actual < MINIMUM_PYTHON:
        required = ".".join(str(part) for part in MINIMUM_PYTHON)
        current = ".".join(str(part) for part in actual)
        raise RuntimeError(
            f"repository tools require Python {required} or newer; got {current}"
        )


def load_audit_exceptions(
    path: Path = AUDIT_EXCEPTIONS_FILE,
    *,
    today: datetime.date | None = None,
) -> tuple[str, ...]:
    """Return validated, unexpired RustSec advisory exceptions."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read RustSec exception policy {path}: {error}") from error

    if not isinstance(document, dict) or set(document) != {"schema", "exceptions"}:
        raise RuntimeError("RustSec exception policy must contain schema and exceptions")
    if document["schema"] != 1 or not isinstance(document["exceptions"], list):
        raise RuntimeError("unsupported RustSec exception policy schema")

    current_date = datetime.date.today() if today is None else today
    advisories: list[str] = []
    for index, entry in enumerate(document["exceptions"]):
        label = f"RustSec exception {index}"
        if not isinstance(entry, dict) or set(entry) != _EXCEPTION_FIELDS:
            raise RuntimeError(f"{label} must contain exactly {sorted(_EXCEPTION_FIELDS)}")

        advisory = entry["advisory"]
        owner = entry["owner"]
        rationale = entry["rationale"]
        expires = entry["expires"]
        if not isinstance(advisory, str) or _ADVISORY_PATTERN.fullmatch(advisory) is None:
            raise RuntimeError(f"{label} has an invalid advisory identifier")
        if advisory in advisories:
            raise RuntimeError(f"duplicate RustSec exception for {advisory}")
        if not isinstance(owner, str) or not owner.strip():
            raise RuntimeError(f"{label} must name a non-empty owner")
        if not isinstance(rationale, str) or not rationale.strip():
            raise RuntimeError(f"{label} must include a non-empty rationale")
        if not isinstance(expires, str):
            raise RuntimeError(f"{label} must use an ISO-8601 expiry date")
        try:
            expiry_date = datetime.date.fromisoformat(expires)
        except ValueError as error:
            raise RuntimeError(f"{label} must use an ISO-8601 expiry date") from error
        if expiry_date <= current_date:
            raise RuntimeError(f"RustSec exception for {advisory} expired on {expires}")
        advisories.append(advisory)

    return tuple(advisories)
