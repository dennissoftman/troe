#!/usr/bin/env python3
"""Build the reproducible freestanding TROE C sysroot for KEX targets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = REPO_ROOT / "sdk" / "c"
INCLUDE_ROOT = SDK_ROOT / "troe-kex-sysroot" / "include"
RUNTIME_ROOT = SDK_ROOT / "troe-kex-runtime"
VENDOR_ROOT = RUNTIME_ROOT / "vendor" / "nanoprintf-0.6.1"
SOURCES = (
    "troe_libc_core.c",
    "troe_c_compat.c",
    "troe_posix.c",
    "troe_setjmp.c",
)
TARGETS = {
    "x86_64": "x86_64-unknown-none-elf",
    "aarch64": "aarch64-unknown-none-elf",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="empty output directory")
    parser.add_argument(
        "--architecture",
        choices=("all", *TARGETS),
        default="all",
        help="target architecture to build",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--ar", default=os.environ.get("AR"))
    parser.add_argument(
        "--check",
        action="store_true",
        help="build twice and reject nondeterministic output",
    )
    return parser.parse_args()


def run(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def find_archiver(explicit: str | None) -> str:
    if explicit:
        return explicit
    available = shutil.which("llvm-ar")
    if available:
        return available
    candidates = (
        Path("/opt/homebrew/opt/llvm/bin/llvm-ar"),
        Path("/usr/local/opt/llvm/bin/llvm-ar"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError(
        "llvm-ar is required to build the cross-target static C library"
    )


def build_one(output: Path, architecture: str, cc: str, archiver: str) -> None:
    target = TARGETS[architecture]
    destination = output / architecture
    include = destination / "include"
    objects = destination / "objects"
    library = destination / "lib"
    shutil.copytree(INCLUDE_ROOT, include)
    objects.mkdir(parents=True)
    library.mkdir()
    resource = Path(run([cc, "-print-resource-dir"])) / "include"
    common = [
        cc,
        f"--target={target}",
        "-std=c11",
        "-O2",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fPIC",
        "-ffunction-sections",
        "-fdata-sections",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-fvisibility=hidden",
        "-nostdlibinc",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-isystem",
        str(resource),
        "-I",
        str(INCLUDE_ROOT),
        "-I",
        str(VENDOR_ROOT),
    ]
    if architecture == "x86_64":
        common.extend(
            ("-mno-red-zone", "-msse2", "-mfpmath=sse", "-mno-avx", "-mno-avx2")
        )
    else:
        common.append("-march=armv8-a+simd")
    object_paths: list[Path] = []
    for source_name in SOURCES:
        object_path = objects / f"{Path(source_name).stem}.o"
        subprocess.run(
            [*common, "-c", str(RUNTIME_ROOT / source_name), "-o", str(object_path)],
            check=True,
        )
        object_paths.append(object_path)
    archive = library / "libtroe_c.a"
    subprocess.run(
        [archiver, "rcsD", str(archive), *(str(path) for path in object_paths)],
        check=True,
    )
    shutil.rmtree(objects)
    metadata = {
        "abi": 1,
        "architecture": architecture,
        "clang_target": target,
        "library": "lib/libtroe_c.a",
        "ownership": {
            "c": "libtroe_c.a",
            "ctype_decimal_math": "troe-kex-runtime Rust crate",
            "host_services": "troe_runtime_host supplied by the executable",
        },
    }
    (destination / "TARGET.json").write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def build(output: Path, architectures: tuple[str, ...], cc: str, archiver: str) -> None:
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    for architecture in architectures:
        build_one(output, architecture, cc, archiver)


def main() -> int:
    args = parse_args()
    architectures = tuple(TARGETS) if args.architecture == "all" else (args.architecture,)
    try:
        archiver = find_archiver(args.ar)
        build(args.output, architectures, args.cc, archiver)
        if args.check:
            with tempfile.TemporaryDirectory(prefix="troe-c-sysroot-") as temporary:
                second = Path(temporary) / "sysroot"
                build(second, architectures, args.cc, archiver)
                if tree_digest(args.output) != tree_digest(second):
                    raise RuntimeError("C sysroot output is not deterministic")
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"C sysroot build failed: {error}", file=os.sys.stderr)
        return 1
    print(f"TROE C sysroot ready: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
