#!/usr/bin/env python3
"""Build, verify, and inspect repo-local TROE KEX applications."""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from tools import elf2kex
else:
    import elf2kex


REPO_ROOT = Path(__file__).resolve().parents[1]
LINKER_SCRIPT = REPO_ROOT / "sdk" / "kex.ld"
DEFAULT_OUTPUT = REPO_ROOT / "rootfs" / "bin"
TARGETS = {
    "x86_64": "x86_64-unknown-none",
    "aarch64": "aarch64-unknown-none",
}
COMMAND_NAME = re.compile(r"[a-z0-9][a-z0-9_-]*\Z")
RUST_FLAGS = (
    "-C",
    "relocation-model=static",
    "-C",
    "code-model=large",
    "-C",
    f"link-arg=-T{LINKER_SCRIPT}",
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
    "link-arg=max-page-size=4096",
)


@dataclass(frozen=True)
class AppManifest:
    """Validated build identity for one standalone application crate."""

    directory: Path
    package: str
    binary: str
    command: str


def read_manifest(app: Path, command: str | None = None) -> AppManifest:
    """Read the narrow standalone manifest subset used by the builder."""
    directory = app.resolve()
    directory.relative_to(REPO_ROOT)
    manifest_path = directory / "Cargo.toml"
    document = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    package = document["package"]["name"]
    bins = document.get("bin", [])
    if len(bins) > 1:
        raise ValueError("application manifests may define at most one binary")
    binary = bins[0]["name"] if bins else package
    resolved_command = command or directory.name
    if not COMMAND_NAME.fullmatch(resolved_command):
        raise ValueError("command name must contain only lowercase ASCII, digits, '_' or '-'")
    if "workspace" not in document:
        raise ValueError("application must be a standalone Cargo workspace")
    return AppManifest(directory, package, binary, resolved_command)


def cargo_command(manifest: AppManifest, target: str) -> tuple[str, ...]:
    """Return the deterministic Cargo command used for one target."""
    return (
        "cargo",
        "build",
        "--locked",
        "--manifest-path",
        str(manifest.directory / "Cargo.toml"),
        "--release",
        "--target",
        TARGETS[target],
    )


def build_one(
    manifest: AppManifest,
    target: str,
    output_root: Path,
    *,
    check: bool,
    stack_pages: int,
    heap_pages: int,
) -> Path:
    """Build and canonically convert one target, then write or compare it."""
    target_dir = REPO_ROOT / "target" / "kex" / manifest.command
    environment = os.environ.copy()
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_TARGET_DIR"] = str(target_dir)
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(RUST_FLAGS)
    subprocess.run(
        cargo_command(manifest, target),
        cwd=REPO_ROOT,
        env=environment,
        check=True,
    )
    executable = target_dir / TARGETS[target] / "release" / manifest.binary
    artifact = elf2kex.convert_elf(
        executable.read_bytes(),
        expected_target=target,
        stack_pages=stack_pages,
        heap_pages=heap_pages,
    )
    output = output_root.resolve() / target / f"{manifest.command}.kex"
    if check:
        if output.read_bytes() != artifact:
            raise ValueError(f"{output} differs from the canonical build")
        print(f"KEX app verified: {target} {len(artifact)} bytes -> {output}")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(".kex.tmp")
        temporary.write_bytes(artifact)
        temporary.replace(output)
        print(f"KEX app built: {target} {len(artifact)} bytes -> {output}")
    return output


def inspect(path: Path) -> dict[str, int | str]:
    """Validate a KEX artifact and return its bounded execution metadata."""
    artifact = path.read_bytes()
    if len(artifact) < elf2kex.KEX_HEADER_BYTES:
        raise ValueError("KEX header is truncated")
    target_id = struct.unpack_from("<H", artifact, 12)[0]
    reverse_targets = {value: name for name, value in elf2kex.KEX_TARGETS.items()}
    target = reverse_targets.get(target_id)
    if target is None:
        raise ValueError("KEX target is unknown")
    elf2kex.verify_kex(artifact, target)
    entry = struct.unpack_from("<Q", artifact, 24)[0]
    records = struct.unpack_from("<H", artifact, 32)[0]
    stack_pages, heap_pages = struct.unpack_from("<II", artifact, 36)
    return {
        "format": "KEX v1",
        "abi": "1.0",
        "target": target,
        "bytes": len(artifact),
        "records": records,
        "entry_offset": entry,
        "stack_pages": stack_pages,
        "heap_pages": heap_pages,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    build = commands.add_parser("build", help="build canonical KEX artifacts")
    build.add_argument("app", type=Path)
    build.add_argument("--name", help="installed command name; defaults to app directory")
    build.add_argument(
        "--target", choices=("all", *TARGETS), default="all"
    )
    build.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    build.add_argument("--stack-pages", type=int, default=4)
    build.add_argument("--heap-pages", type=int, default=0)
    build.add_argument("--check", action="store_true")
    show = commands.add_parser("inspect", help="validate and describe a KEX artifact")
    show.add_argument("artifact", type=Path)
    show.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.operation == "inspect":
            report = inspect(args.artifact)
            if args.json:
                print(json.dumps(report, sort_keys=True))
            else:
                print(
                    "{format}; target={target}; ABI={abi}; bytes={bytes}; "
                    "records={records}; entry={entry_offset:#x}; "
                    "stack={stack_pages} pages; heap={heap_pages} pages".format(
                        **report
                    )
                )
            return 0
        manifest = read_manifest(args.app, args.name)
        targets = tuple(TARGETS) if args.target == "all" else (args.target,)
        for target in targets:
            build_one(
                manifest,
                target,
                args.output,
                check=args.check,
                stack_pages=args.stack_pages,
                heap_pages=args.heap_pages,
            )
        return 0
    except (KeyError, FileNotFoundError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"kex: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
