#!/usr/bin/env python3
"""Stable operator CLI for TROE system deployment lifecycle state."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__:
    from .package_model import (
        MAX_DOCUMENT_BYTES,
        ModelError,
        canonical_json,
        parse_package,
    )
    from .package_trust import (
        MAX_ENVELOPE_BYTES,
        MAX_PACKAGE_BYTES,
        parse_envelope,
        validate_release_payload,
    )
    from .system_lifecycle import (
        LifecycleStore,
        ReleaseInput,
        parse_migration,
    )
else:
    from package_model import (
        MAX_DOCUMENT_BYTES,
        ModelError,
        canonical_json,
        parse_package,
    )
    from package_trust import (
        MAX_ENVELOPE_BYTES,
        MAX_PACKAGE_BYTES,
        parse_envelope,
        validate_release_payload,
    )
    from system_lifecycle import LifecycleStore, ReleaseInput, parse_migration


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the closed lifecycle command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser("status", help="recover and inspect active state")
    _store_argument(status)

    recover = subparsers.add_parser("recover", help="recover an interrupted operation")
    _store_argument(recover)

    verify = subparsers.add_parser(
        "verify", help="verify retained generations and objects"
    )
    _store_argument(verify)
    verify.add_argument("--now", type=int)

    config = subparsers.add_parser("config-set", help="replace desired configuration")
    _store_argument(config)
    config.add_argument("--projection", type=Path, required=True)

    deploy = subparsers.add_parser(
        "deploy", help="stage a verified generation as pending"
    )
    _store_argument(deploy)
    deploy.add_argument("--lock", type=Path, required=True)
    deploy.add_argument("--root", type=Path, required=True)
    deploy.add_argument("--trusted-payload-sha256", required=True)
    deploy.add_argument("--release", type=Path, action="append", required=True)
    deploy.add_argument("--package", type=Path, action="append", required=True)
    deploy.add_argument("--migration", type=Path, action="append", default=[])
    deploy.add_argument("--allow-downgrade", action="append", default=[])
    deploy.add_argument("--now", type=int, required=True)
    deploy.add_argument("--offline", action="store_true")
    deploy.add_argument("--offline-grace", type=int, default=0)

    health = subparsers.add_parser(
        "health", help="commit or reject a pending generation"
    )
    _store_argument(health)
    health.add_argument("--generation", type=int, required=True)
    health.add_argument("--result", choices=("failed", "passed"), required=True)

    rollback = subparsers.add_parser("rollback", help="select the known predecessor")
    _store_argument(rollback)

    collect = subparsers.add_parser("gc", help="collect unreachable immutable state")
    _store_argument(collect)

    diagnostics = subparsers.add_parser(
        "diagnostics", help="read persistent diagnostics"
    )
    _store_argument(diagnostics)

    diagnose = subparsers.add_parser(
        "diagnose", help="append one persistent diagnostic"
    )
    _store_argument(diagnose)
    diagnose.add_argument("--code", required=True)
    diagnose.add_argument("--detail", required=True)
    diagnose.add_argument("--generation", type=int)
    return parser.parse_args(argv)


def _store_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--store", type=Path, required=True)


def read(path: Path, maximum: int) -> bytes:
    """Read one bounded non-symlink regular file."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise ModelError(
                "invalid-file", str(path), "regular non-symlink file required"
            )
        return path.read_bytes()
    except OSError as error:
        raise ModelError("read-failed", str(path), str(error)) from error


def release_inputs(
    release_paths: list[Path], package_paths: list[Path]
) -> list[ReleaseInput]:
    """Pair explicitly named release and package inputs independent of argv order."""
    releases: dict[str, bytes] = {}
    for path in release_paths:
        data = read(path, MAX_ENVELOPE_BYTES)
        envelope = parse_envelope(data, str(path))
        payload = validate_release_payload(envelope.payload, str(path))
        name = payload["name"]
        if name in releases:
            raise ModelError("duplicate-package", str(path), name)
        releases[name] = data
    packages: dict[str, bytes] = {}
    for path in package_paths:
        data = read(path, MAX_PACKAGE_BYTES)
        manifest, _lock, _artifact = parse_package(data, str(path))
        if manifest.name in packages:
            raise ModelError("duplicate-package", str(path), manifest.name)
        packages[manifest.name] = data
    if set(releases) != set(packages):
        raise ModelError(
            "incomplete-plan",
            "release-inputs",
            f"releases={sorted(releases)} packages={sorted(packages)}",
        )
    return [ReleaseInput(releases[name], packages[name]) for name in sorted(packages)]


def execute(args: argparse.Namespace) -> dict[str, object]:
    """Execute one lifecycle operation and return stable machine data."""
    store = LifecycleStore(args.store)
    if args.command == "status":
        return {"pointer": store.status()}
    if args.command == "recover":
        return {"pointer": store.recover()}
    if args.command == "verify":
        return store.verify(now=args.now)
    if args.command == "config-set":
        digest = store.set_desired_configuration(
            read(args.projection, MAX_DOCUMENT_BYTES)
        )
        return {"configuration_sha256": digest, "pointer": store.status()}
    if args.command == "deploy":
        migrations = [
            parse_migration(read(path, MAX_DOCUMENT_BYTES), str(path))
            for path in args.migration
        ]
        generation = store.deploy(
            read(args.lock, MAX_DOCUMENT_BYTES),
            read(args.root, MAX_ENVELOPE_BYTES),
            args.trusted_payload_sha256,
            release_inputs(args.release, args.package),
            now=args.now,
            migrations=migrations,
            allow_downgrade=args.allow_downgrade,
            offline=args.offline,
            offline_grace=args.offline_grace,
        )
        return {"generation": generation, "pointer": store.status()}
    if args.command == "health":
        return {"pointer": store.mark_health(args.generation, args.result == "passed")}
    if args.command == "rollback":
        return {"pointer": store.rollback()}
    if args.command == "gc":
        return {"removed": store.garbage_collect(), "pointer": store.status()}
    if args.command == "diagnostics":
        return {"events": store.diagnostics()}
    if args.command == "diagnose":
        sequence = store.record_diagnostic(args.code, args.detail, args.generation)
        return {"sequence": sequence}
    raise ModelError("unknown-command", "command", args.command)


def main(argv: list[str] | None = None) -> int:
    """Emit one canonical result and one stable diagnostic schema."""
    args = parse_args(argv)
    try:
        data = execute(args)
        result = {
            "command": args.command,
            "data": data,
            "diagnostics": [],
            "ok": True,
            "schema": 1,
        }
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
