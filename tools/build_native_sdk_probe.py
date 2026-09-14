#!/usr/bin/env python3
"""Rebuild/check the loaded Rust SDK and C TLS consumer with pinned tools."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

import thread_profile

ROOT = Path(__file__).resolve().parents[1]
CONSUMER = ROOT / "tests/native-thread-probe"
RETAINED = ROOT / "kernel/src/resident/threading/probe"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--linker", default="ld.lld")
    parser.add_argument("--ar", default="llvm-ar")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    profile = json.loads(thread_profile.PROFILE_FILE.read_text())
    compiler = thread_profile.executable(args.cc)
    linker = thread_profile.executable(args.linker)
    archive = thread_profile.executable(args.ar)
    thread_profile.tool_identity(compiler, "clang", profile["clang_version"], False)
    thread_profile.tool_identity(linker, "lld", profile["lld_version"], False)
    environment = thread_profile.compiler_environment()
    for name in ("RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        environment.pop(name, None)
    environment.update(CC=str(compiler), AR=str(archive), CARGO_INCREMENTAL="0")
    flags = [
        "-C",
        "relocation-model=pic",
        "-C",
        "code-model=small",
        "-C",
        f"linker={linker}",
        "-C",
        "link-arg=-pie",
        "-C",
        "link-arg=--no-relax",
        "-C",
        "link-arg=--no-dynamic-linker",
        "-C",
        "link-arg=--build-id=none",
        "-C",
        "link-arg=--no-eh-frame-hdr",
        "-C",
        "link-arg=-z",
        "-C",
        "link-arg=norelro",
        "-C",
        "link-arg=-z",
        "-C",
        "link-arg=separate-loadable-segments",
        "-C",
        "link-arg=-z",
        "-C",
        "link-arg=max-page-size=4096",
        "-C",
        f"link-arg=-T{thread_profile.LINKER_SCRIPT}",
        f"--remap-path-prefix={ROOT}=/troe",
    ]
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
    environment["CARGO_TARGET_DIR"] = str(ROOT / "target/native-sdk-probe")
    with tempfile.TemporaryDirectory(prefix="troe-native-sdk-") as temporary:
        for architecture in thread_profile.TARGETS:
            target = f"{architecture}-unknown-none"
            subprocess.run(
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--release",
                    "--manifest-path",
                    str(CONSUMER / "Cargo.toml"),
                    "--target",
                    target,
                ],
                cwd=ROOT,
                env=environment,
                check=True,
            )
            elf = (
                Path(environment["CARGO_TARGET_DIR"])
                / target
                / "release/troe-native-thread-probe"
            )
            converted = Path(temporary) / f"sdk-{architecture}.kex"
            subprocess.run(
                [
                    "cargo",
                    "kex",
                    "convert",
                    str(elf),
                    str(converted),
                    "--target",
                    architecture,
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
            destination = RETAINED / converted.name
            if args.check:
                if (
                    not destination.is_file()
                    or destination.read_bytes() != converted.read_bytes()
                ):
                    raise SystemExit(
                        f"embedded native SDK artifact differs: {destination}"
                    )
            else:
                destination.write_bytes(converted.read_bytes())
            print(f"{architecture}: {thread_profile.file_digest(converted)}")


if __name__ == "__main__":
    main()
