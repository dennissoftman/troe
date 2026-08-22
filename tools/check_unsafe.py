#!/usr/bin/env python3
"""Inventory authored Rust `unsafe` tokens; fail unless the expected count matches."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TOKEN = re.compile(r"\bunsafe\b")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--expected", type=int, default=0)
    args = parser.parse_args()
    matches: list[str] = []
    for source in sorted(args.root.rglob("*.rs")):
        if "target" in source.parts:
            continue
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if TOKEN.search(line):
                matches.append(f"{source}:{number}: {line.strip()}")
    print(f"authored unsafe token count: {len(matches)}")
    for match in matches:
        print(match)
    if len(matches) != args.expected:
        print(f"expected {args.expected} unsafe tokens", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

