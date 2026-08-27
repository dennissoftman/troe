#!/usr/bin/env python3
"""Hosted TROE signing, verification, rotation, and registry publication CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from package_model import ModelError, canonical_json, decode_json, sha256
from package_trust import (
    MAX_ENVELOPE_BYTES,
    MAX_PACKAGE_BYTES,
    key_id,
    public_key_der,
    public_key_der_from_private,
    publish_release,
    sign_payload,
    verify_initial_root,
    verify_registry_generation,
    verify_release,
    verify_root_rotation,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the closed trust command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    identify = subparsers.add_parser("key-id", help="derive an Ed25519 key identity")
    key = identify.add_mutually_exclusive_group(required=True)
    key.add_argument("--public-key", type=Path)
    key.add_argument("--private-key", type=Path)

    sign = subparsers.add_parser("sign", help="sign one canonical metadata payload")
    sign.add_argument("--payload", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, action="append", required=True)
    sign.add_argument("--output", type=Path, required=True)

    root = subparsers.add_parser("verify-root", help="verify an anchored initial root")
    root.add_argument("--root", type=Path, required=True)
    root.add_argument("--trusted-payload-sha256", required=True)
    root.add_argument("--now", type=int, required=True)

    rotate = subparsers.add_parser("verify-rotation", help="verify one consecutive root")
    rotate.add_argument("--trusted-root", type=Path, required=True)
    rotate.add_argument("--trusted-payload-sha256", required=True)
    rotate.add_argument("--new-root", type=Path, required=True)
    rotate.add_argument("--now", type=int, required=True)

    release = subparsers.add_parser("verify-release", help="verify one signed package release")
    _root_arguments(release)
    release.add_argument("--release", type=Path, required=True)
    release.add_argument("--package", type=Path, required=True)
    release.add_argument("--now", type=int, required=True)
    release.add_argument("--minimum-sequence", type=int, default=0)
    release.add_argument("--offline", action="store_true")
    release.add_argument("--offline-grace", type=int, default=0)

    publish = subparsers.add_parser("publish", help="atomically publish one registry release")
    _root_arguments(publish)
    publish.add_argument("--release", type=Path, required=True)
    publish.add_argument("--package", type=Path, required=True)
    publish.add_argument("--snapshot-key", type=Path, action="append", required=True)
    publish.add_argument("--registry", type=Path, required=True)
    publish.add_argument("--now", type=int, required=True)
    publish.add_argument("--snapshot-expires", type=int, required=True)

    registry = subparsers.add_parser("verify-registry", help="verify the current generation")
    _root_arguments(registry)
    registry.add_argument("--registry", type=Path, required=True)
    registry.add_argument("--now", type=int, required=True)
    registry.add_argument("--minimum-generation", type=int, default=0)
    registry.add_argument("--offline", action="store_true")
    registry.add_argument("--offline-grace", type=int, default=0)
    return parser.parse_args(argv)


def _root_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--trusted-payload-sha256", required=True)


def read(path: Path, maximum: int) -> bytes:
    """Read one bounded non-symlink regular file."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise ModelError("invalid-input", str(path), "file type or size")
        return path.read_bytes()
    except OSError as error:
        raise ModelError("read-failed", str(path), str(error)) from error


def write_new(path: Path, payload: bytes) -> None:
    """Write one explicit absent output path."""
    if path.exists() or path.is_symlink():
        raise ModelError("output-exists", str(path), "refusing replacement")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as output:
            output.write(payload)
            output.flush()
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def trusted_root(path: Path, anchor: str, now: int) -> dict[str, object]:
    """Load one out-of-band anchored root."""
    return verify_initial_root(read(path, MAX_ENVELOPE_BYTES), anchor, now)[1]


def execute(args: argparse.Namespace) -> dict[str, object]:
    """Execute one explicit trust operation."""
    if args.command == "key-id":
        public = (
            public_key_der(args.public_key)
            if args.public_key is not None
            else public_key_der_from_private(args.private_key)
        )
        return {"key_id": key_id(public)}
    if args.command == "sign":
        payload = decode_json(read(args.payload, MAX_ENVELOPE_BYTES), str(args.payload))
        envelope = sign_payload(payload, args.private_key)
        write_new(args.output, envelope.bytes())
        return {
            "envelope_sha256": envelope.digest(),
            "payload_sha256": sha256(envelope.payload),
        }
    if args.command == "verify-root":
        envelope, root = verify_initial_root(
            read(args.root, MAX_ENVELOPE_BYTES), args.trusted_payload_sha256, args.now
        )
        return {"envelope_sha256": envelope.digest(), "generation": root["generation"]}
    if args.command == "verify-rotation":
        old = trusted_root(
            args.trusted_root, args.trusted_payload_sha256, args.now
        )
        envelope, root = verify_root_rotation(
            old, read(args.new_root, MAX_ENVELOPE_BYTES), args.now
        )
        return {"envelope_sha256": envelope.digest(), "generation": root["generation"]}
    root = trusted_root(args.root, args.trusted_payload_sha256, args.now)
    if args.command == "verify-release":
        verified = verify_release(
            root,
            read(args.release, MAX_ENVELOPE_BYTES),
            read(args.package, MAX_PACKAGE_BYTES),
            now=args.now,
            offline=args.offline,
            offline_grace=args.offline_grace,
            minimum_sequence=args.minimum_sequence,
        )
        return {
            "name": verified.payload["name"],
            "package_sha256": verified.payload["package_sha256"],
            "sequence": verified.payload["sequence"],
            "status": verified.status,
            "target": verified.payload["target"],
        }
    if args.command == "publish":
        generation = publish_release(
            args.registry,
            root,
            read(args.release, MAX_ENVELOPE_BYTES),
            read(args.package, MAX_PACKAGE_BYTES),
            args.snapshot_key,
            now=args.now,
            snapshot_expires=args.snapshot_expires,
        )
        return {"generation": generation}
    if args.command == "verify-registry":
        pointer = args.registry / "current"
        try:
            generation = int(read(pointer, 32).decode("ascii"))
        except (UnicodeError, ValueError) as error:
            raise ModelError("registry-corrupt", str(pointer), str(error)) from error
        snapshot = verify_registry_generation(
            root,
            args.registry / "generations" / f"{generation:020d}",
            now=args.now,
            minimum_generation=max(args.minimum_generation, generation),
            offline=args.offline,
            offline_grace=args.offline_grace,
        )
        return {"generation": snapshot["generation"], "releases": len(snapshot["releases"])}
    raise ModelError("unknown-command", "command", args.command)


def main(argv: list[str] | None = None) -> int:
    """Emit one stable machine result for every trust operation."""
    args = parse_args(argv)
    try:
        data = execute(args)
        result = {"command": args.command, "data": data, "diagnostics": [], "ok": True, "schema": 1}
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except ModelError as error:
        result = {
            "command": args.command,
            "data": None,
            "diagnostics": [error.json()],
            "ok": False,
            "schema": 1,
        }
        sys.stdout.buffer.write(canonical_json(result))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
