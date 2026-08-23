#!/usr/bin/env python3
"""Audit Cargo.lock with pinned cargo-audit and RustSec database revisions."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DATABASE_PATH = REPO_ROOT / "target" / "rustsec-advisory-db"
DATABASE_REVISION_FILE = REPO_ROOT / "tools" / "rustsec-advisory-db.rev"
DATABASE_URL = "https://github.com/RustSec/advisory-db.git"
EXPECTED_CARGO_AUDIT_VERSION = "0.22.1"


def run(*command: str | Path, capture: bool = False) -> str:
    """Run one checked command and optionally return stripped stdout."""
    result = subprocess.run(
        [str(argument) for argument in command],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def pinned_revision() -> str:
    """Read and validate the committed RustSec database revision."""
    revision = DATABASE_REVISION_FILE.read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RuntimeError("RustSec database revision must be a full lowercase Git hash")
    return revision


def verify_tool_version() -> None:
    """Reject an unreviewed cargo-audit executable version."""
    output = run("cargo", "audit", "--version", capture=True)
    match = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+)\b", output)
    if match is None or match.group(1) != EXPECTED_CARGO_AUDIT_VERSION:
        raise RuntimeError(
            f"expected cargo-audit {EXPECTED_CARGO_AUDIT_VERSION}, got {output!r}; "
            f"install with `cargo install cargo-audit --version "
            f"{EXPECTED_CARGO_AUDIT_VERSION} --locked`"
        )


def prepare_database(revision: str) -> None:
    """Check out the exact advisory database revision in the ignored target tree."""
    database_exists = (DATABASE_PATH / ".git").is_dir()
    if not database_exists:
        DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
        run("git", "clone", "--filter=blob:none", "--no-checkout", DATABASE_URL, DATABASE_PATH)
    elif run("git", "-C", DATABASE_PATH, "status", "--porcelain", capture=True):
        raise RuntimeError(f"RustSec database cache is modified: {DATABASE_PATH}")
    try:
        run("git", "-C", DATABASE_PATH, "cat-file", "-e", f"{revision}^{{commit}}")
    except subprocess.CalledProcessError:
        run("git", "-C", DATABASE_PATH, "fetch", "--depth", "1", "origin", revision)
    actual = run("git", "-C", DATABASE_PATH, "rev-parse", "HEAD", capture=True)
    if actual != revision:
        run("git", "-C", DATABASE_PATH, "checkout", "--detach", revision)
    if run("git", "-C", DATABASE_PATH, "status", "--porcelain", capture=True):
        raise RuntimeError(f"RustSec database checkout is modified: {DATABASE_PATH}")
    actual = run("git", "-C", DATABASE_PATH, "rev-parse", "HEAD", capture=True)
    if actual != revision:
        raise RuntimeError(f"expected RustSec database {revision}, got {actual}")


def main() -> int:
    """Prepare exact inputs and fail on every RustSec warning category."""
    try:
        revision = pinned_revision()
        verify_tool_version()
        prepare_database(revision)
        run(
            "cargo",
            "audit",
            "--no-fetch",
            "--db",
            DATABASE_PATH,
            "--file",
            REPO_ROOT / "Cargo.lock",
            "--deny",
            "warnings",
        )
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"dependency audit failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"dependency audit failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    print(f"dependency audit: passed at RustSec {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
