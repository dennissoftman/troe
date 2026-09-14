#!/usr/bin/env python3
"""Rebuild/check the embedded resident TLS consumers with the qualified C recipe."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

import thread_profile

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "kernel/src/resident/threading/probe"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--linker", default="ld.lld")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    profile = json.loads(thread_profile.PROFILE_FILE.read_text())
    for executable, kind, pin in (
        (args.cc, "clang", profile["clang_version"]),
        (args.linker, "lld", profile["lld_version"]),
    ):
        thread_profile.tool_identity(
            thread_profile.executable(executable), kind, pin, False
        )
    with tempfile.TemporaryDirectory(prefix="troe-resident-tls-") as temporary:
        for target in thread_profile.TARGETS:
            work = Path(temporary) / target
            work.mkdir()
            elf = thread_profile.compile_probe(
                work, target, (PROBE / "program.c").read_text(), args.cc, args.linker
            )
            generated = work / "program.kex"
            subprocess.run(
                [
                    "cargo",
                    "kex",
                    "convert",
                    str(elf),
                    str(generated),
                    "--target",
                    target,
                    "--threaded",
                    "--stack-pages",
                    "8",
                    "--heap-pages",
                    "0",
                ],
                cwd=ROOT,
                env=thread_profile.compiler_environment(),
                check=True,
            )
            retained = PROBE / f"program-{target}.kex"
            if args.check:
                if (
                    not retained.is_file()
                    or retained.read_bytes() != generated.read_bytes()
                ):
                    raise SystemExit(
                        f"embedded resident TLS artifact differs: {retained}"
                    )
            else:
                retained.write_bytes(generated.read_bytes())
            print(f"{target}: {thread_profile.file_digest(generated)}")


if __name__ == "__main__":
    main()
