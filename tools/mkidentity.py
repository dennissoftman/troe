#!/usr/bin/env python3
"""Provision nonzero, collision-free deployment identity IDs from the OS CSPRNG."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections.abc import Callable
from pathlib import Path

from mkcontent import RESERVED_FIXTURE_IDS, IdentityIds


def generate_identities(
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> IdentityIds:
    """Generate three distinct deployment IDs, with a bounded source retry count."""
    generated: list[bytes] = []
    for _ in range(64):
        candidate = random_bytes(16)
        if len(candidate) != 16:
            raise ValueError("OS CSPRNG returned an invalid identifier length")
        if (
            candidate != bytes(16)
            and candidate not in RESERVED_FIXTURE_IDS
            and candidate not in generated
        ):
            generated.append(candidate)
            if len(generated) == 3:
                return IdentityIds(*generated)
    raise RuntimeError("OS CSPRNG did not produce three usable identifiers")


def encode_identities(identities: IdentityIds) -> str:
    """Encode the canonical deployment identity file."""
    document = {
        "domain_id": identities.domain.hex(),
        "group_id": identities.group.hex(),
        "schema": 1,
        "user_id": identities.user.hex(),
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        identities = generate_identities()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            args.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
            destination.write(encode_identities(identities))
        print(f"deployment identities -> {args.output}")
        return 0
    except (OSError, RuntimeError, ValueError) as error:
        print(f"mkidentity: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
