#!/usr/bin/env python3
"""Qualify the pinned C11 local-exec compiler profile without native admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE_FILE = REPO_ROOT / "sdk/c/thread-profile-v1.json"
LINKER_SCRIPT = REPO_ROOT / "sdk/c/thread-profile-v1.ld"
INCLUDE_ROOT = REPO_ROOT / "sdk/c/troe-kex-sysroot/include"
TARGETS = {
    "x86_64": "x86_64-unknown-none-elf",
    "aarch64": "aarch64-unknown-none-elf",
}
REQUIRED_PROBES = frozenset(
    (
        "test_c_profile_uses_troe_headers_lp64_and_local_exec_storage",
        "test_compiled_local_exec_addresses_match_explicit_tls_conversion",
        "test_empty_template_and_pointer_initializer_policy",
        "test_empty_tls_still_charges_a_control_block",
        "test_layout_rejects_malformed_or_underfunded_requests",
        "test_threaded_conversion_rejects_malformed_elf_without_replacing_output",
    )
)
# These can add headers, configuration or driver options even when the
# command line excludes host standard includes. A caller cannot append flags.
DRIVER_ENVIRONMENT = (
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "COMPILER_PATH",
    "LIBRARY_PATH",
    "GCC_EXEC_PREFIX",
    "SDKROOT",
    "MACOSX_DEPLOYMENT_TARGET",
    "CCC_OVERRIDE_OPTIONS",
    "CLANG_CONFIG_FILE_USER_DIR",
    "CLANG_CONFIG_FILE_SYSTEM_DIR",
    "LDEMULATION",
    "LD_RUN_PATH",
)


def compiler_environment() -> dict[str, str]:
    """Remove ambient driver inputs and fix compiler timestamp expansion."""
    environment = os.environ.copy()
    for name in DRIVER_ENVIRONMENT:
        environment.pop(name, None)
    environment["SOURCE_DATE_EPOCH"] = "946684800"
    return environment


def executable(name: str) -> Path:
    """Resolve exactly the named executable; never download or fall back."""
    found = shutil.which(name)
    if found is None:
        raise RuntimeError(f"required profile tool is unavailable: {name}")
    # LLD selects its ELF driver from argv[0]. Resolving the ld.lld symlink to
    # the generic lld binary changes behavior; hashing still follows the link.
    return Path(found).absolute()


def resource_directory(cc: Path) -> Path:
    """Use only the selected compiler's builtin headers and the TROE sysroot."""
    result = subprocess.run(
        [cc, "--no-default-config", "-print-resource-dir"],
        check=True,
        capture_output=True,
        text=True,
        env=compiler_environment(),
    )
    include = Path(result.stdout.strip()) / "include"
    if not include.is_dir():
        raise RuntimeError("selected Clang has no builtin header directory")
    return include.resolve(strict=True)


def compile_probe(root: Path, target: str, source: str, cc: str, linker: str) -> Path:
    """Compile and link the exact qualification recipe, with no native launch."""
    compiler = executable(cc)
    ld = executable(linker)
    triple = TARGETS[target]
    environment = compiler_environment()
    (root / "probe.c").write_text(source)
    flags = [
        "--no-default-config",
        f"--target={triple}",
        "-std=c11",
        "-O2",
        "-ffreestanding",
        "-fno-builtin",
        "-fPIC",
        "-ftls-model=local-exec",
        "-fomit-frame-pointer",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        # Layout probes only; not production hardening approval.
        "-fno-stack-protector",
        "-fno-ident",
        "-Werror=date-time",
        "-nostdinc",
        "-isystem",
        str(resource_directory(compiler)),
        "-I",
        str(INCLUDE_ROOT),
        f"-ffile-prefix-map={root}=.",
        f"-fdebug-prefix-map={root}=.",
    ]
    if target == "x86_64":
        flags.extend(
            (
                "-mno-red-zone",
                "-march=x86-64",
                "-msse2",
                "-mfpmath=sse",
                "-mno-avx",
                "-mno-avx2",
            )
        )
    else:
        flags.extend(("-march=armv8-a+simd", "-mno-outline-atomics"))
    subprocess.run(
        [compiler, *flags, "-c", root / "probe.c", "-o", root / "probe.o"],
        check=True,
        capture_output=True,
        env=environment,
    )
    elf = root / "probe.elf"
    subprocess.run(
        [
            ld,
            "-pie",
            "-e",
            "_start",
            "--no-relax",
            "--no-dynamic-linker",
            "-z",
            "separate-loadable-segments",
            "-z",
            "norelro",
            "-z",
            "max-page-size=4096",
            "-T",
            LINKER_SCRIPT,
            root / "probe.o",
            "-o",
            elf,
        ],
        check=True,
        capture_output=True,
        env=environment,
    )
    return elf


def file_digest(path: Path) -> str:
    """Hash bytes with bounded scratch space."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def tree_digest(root: Path) -> str:
    """Bind relative names and contents without embedding host paths."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            name = path.relative_to(root).as_posix().encode()
            digest.update(len(name).to_bytes(8, "little"))
            digest.update(name)
            digest.update(bytes.fromhex(file_digest(path)))
    return digest.hexdigest()


def tool_identity(
    path: Path, kind: str, expected: str, compatible: bool
) -> dict[str, Any]:
    """Check the tool family and exact reviewed release before qualification."""
    result = subprocess.run(
        [path, "--version"],
        check=True,
        capture_output=True,
        text=True,
        env=compiler_environment(),
    )
    first = result.stdout.splitlines()[0] if result.stdout else ""
    pattern = (
        r"\bclang version (\d+\.\d+\.\d+)\b"
        if kind == "clang"
        else r"\bLLD (\d+\.\d+\.\d+)\b"
    )
    match = re.search(pattern, first)
    if match is None:
        raise RuntimeError(f"profile requires {kind}, received: {first}")
    version = match[1]
    pinned = version == expected and not first.startswith("Apple clang")
    if not compatible and not pinned:
        raise RuntimeError(f"profile requires {kind} {expected}; received {first}")
    return {
        "version": version,
        "description": first,
        "sha256": file_digest(path),
        "matches_pin": pinned,
    }


def run_probes() -> int:
    """Child-process runner: missing or skipped qualification is failure."""
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    suite = unittest.defaultTestLoader.loadTestsFromName("test_kex_tool.StaticTlsTests")
    names = {test.id().rsplit(".", 1)[-1] for test in suite}
    if not names >= REQUIRED_PROBES:
        print("required compiler qualification probes are missing", file=sys.stderr)
        return 1
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return int(
        not result.wasSuccessful()
        or bool(result.skipped)
        or bool(result.expectedFailures)
        or result.testsRun < len(REQUIRED_PROBES)
    )


def qualify(cc: str, linker: str, compatible: bool = False) -> dict[str, Any]:
    """Run cross-target instruction/conversion checks and bind their inputs."""
    profile = json.loads(PROFILE_FILE.read_text())
    if (
        profile.get("schema") != 1
        or profile.get("qualification_only") is not True
        or profile.get("native_admission") is not False
        or profile.get("container") != "1.3"
        or profile.get("application_abi") != "1.4"
    ):
        raise RuntimeError("unsupported compiler qualification profile")
    compiler, ld = executable(cc), executable(linker)

    def identities() -> dict[str, Any]:
        return {
            "clang": tool_identity(
                compiler, "clang", profile["clang_version"], compatible
            ),
            "lld": tool_identity(ld, "lld", profile["lld_version"], compatible),
            "builtin_headers_sha256": tree_digest(resource_directory(compiler)),
            "sysroot_headers_sha256": tree_digest(INCLUDE_ROOT),
            "profile_sha256": file_digest(PROFILE_FILE),
            "recipe_sha256": file_digest(Path(__file__).resolve()),
            "linker_script_sha256": file_digest(LINKER_SCRIPT),
            "probes_sha256": file_digest(REPO_ROOT / "tests/test_kex_tool.py"),
            "abi_source_sha256": tree_digest(REPO_ROOT / "crates/common/troe-abi/src"),
            "application_source_sha256": tree_digest(
                REPO_ROOT / "crates/runtime/troe-application/src"
            ),
            "converter_source_sha256": tree_digest(
                REPO_ROOT / "tools/troe-kex-tool/src"
            ),
            "cargo_lock_sha256": file_digest(REPO_ROOT / "Cargo.lock"),
            "rust_toolchain_sha256": file_digest(REPO_ROOT / "rust-toolchain.toml"),
        }

    before = identities()
    environment = compiler_environment()
    environment.update({"TROE_TLS_CC": str(compiler), "TROE_TLS_LD": str(ld)})
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from tools.thread_profile import run_probes; "
            "raise SystemExit(run_probes())",
        ],
        cwd=REPO_ROOT,
        check=True,
        env=environment,
        stdout=sys.stderr,
    )
    after = identities()
    if before != after:
        raise RuntimeError(
            "profile inputs changed during qualification; discard evidence"
        )
    return {
        "schema": 1,
        "profile": profile["profile"],
        "checks_passed": True,
        "pinned_tools": before["clang"]["matches_pin"] and before["lld"]["matches_pin"],
        "qualification_only": True,
        "native_admission": False,
        "inputs": before,
    }


def write_report(destination: Path, report: dict[str, Any]) -> None:
    """Publish complete evidence atomically only after qualification succeeds."""
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=destination.parent, prefix=".thread-profile-", delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("TROE_TLS_CC", "clang"))
    parser.add_argument("--ld", default=os.environ.get("TROE_TLS_LD", "ld.lld"))
    parser.add_argument(
        "--compatible-tools",
        action="store_true",
        help="qualify other Clang/LLD releases; report whether pins match",
    )
    parser.add_argument(
        "--output", type=Path, help="atomic JSON report; default stdout"
    )
    args = parser.parse_args()
    try:
        report = qualify(args.cc, args.ld, args.compatible_tools)
        if args.output:
            write_report(args.output, report)
        else:
            print(json.dumps(report, sort_keys=True, indent=2))
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"thread profile qualification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
