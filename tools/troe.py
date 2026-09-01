#!/usr/bin/env python3
"""Hosted TROE package-model CLI; never mutates a running system."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path

from package_model import (
    Manifest,
    ModelError,
    build_package,
    canonical_json,
    parse_lock,
    parse_manifest_file,
    parse_package,
    plan,
    resolve,
    sha256,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the closed hosted-tool command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("human", "json"), default="human")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="validate package manifests")
    check.add_argument("manifest", type=Path, nargs="+")

    resolve_command = subparsers.add_parser("resolve", help="construct a target lock")
    resolve_command.add_argument("--root", required=True)
    resolve_command.add_argument("--target", required=True)
    resolve_command.add_argument(
        "--manifest", type=Path, action="append", required=True
    )
    resolve_command.add_argument("--output", type=Path)

    build = subparsers.add_parser(
        "build", help="construct a canonical package artifact"
    )
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument("--lock", type=Path, required=True)
    build.add_argument("--artifact", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)

    inspect = subparsers.add_parser("inspect", help="inspect a manifest or package")
    source = inspect.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest", type=Path)
    source.add_argument("--package", type=Path)

    explain = subparsers.add_parser(
        "explain", help="explain declared authority and cost"
    )
    explain.add_argument("--manifest", type=Path, required=True)

    plan_command = subparsers.add_parser(
        "plan", help="derive a non-mutating activation plan"
    )
    plan_command.add_argument("--lock", type=Path, required=True)
    plan_command.add_argument("--manifest", type=Path, action="append", required=True)

    diagnostics = subparsers.add_parser(
        "diagnostics", help="emit stable validation diagnostics"
    )
    diagnostics.add_argument("manifest", type=Path, nargs="+")
    return parser.parse_args(argv)


def read_bounded(path: Path, maximum: int = 8 * 1024 * 1024) -> bytes:
    """Read one regular, non-symlink input within its hard ceiling."""
    try:
        if path.is_symlink() or not path.is_file():
            raise ModelError(
                "invalid-input", str(path), "must be a regular non-symlink file"
            )
        if path.stat().st_size > maximum:
            raise ModelError("document-size", str(path), f"more than {maximum} bytes")
        return path.read_bytes()
    except OSError as error:
        raise ModelError("read-failed", str(path), str(error)) from error


def publish(path: Path, payload: bytes) -> None:
    """Publish one verified hosted artifact without replacing an existing path."""
    if path.exists() or path.is_symlink():
        raise ModelError("output-exists", str(path), "refusing to replace output")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except OSError as error:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise ModelError("write-failed", str(path), str(error)) from error


def load_manifests(paths: list[Path]) -> list[Manifest]:
    """Parse an explicit manifest catalog."""
    return [parse_manifest_file(path) for path in paths]


def manifest_summary(manifest: Manifest) -> dict[str, object]:
    """Return stable inspection data derived from the typed manifest."""
    return {
        "capabilities": list(manifest.capabilities),
        "dependencies": [dependency.json() for dependency in manifest.dependencies],
        "directories": [directory.json() for directory in manifest.directories],
        "manifest_sha256": manifest.digest(),
        "name": manifest.name,
        "resources": manifest.resources.json(),
        "services": [service.json() for service in manifest.services],
        "targets": [target.json() for target in manifest.targets],
        "version": manifest.version.json(),
    }


def execute(args: argparse.Namespace) -> dict[str, object]:
    """Execute one non-mutating model operation or explicit hosted file build."""
    if args.command in {"check", "diagnostics"}:
        manifests = load_manifests(args.manifest)
        return {
            "checked": [
                {
                    "manifest_sha256": manifest.digest(),
                    "name": manifest.name,
                    "version": manifest.version.json(),
                }
                for manifest in manifests
            ],
            "diagnostics": [],
        }
    if args.command == "resolve":
        lock = resolve(args.root, args.target, load_manifests(args.manifest))
        payload = canonical_json(lock.json())
        if args.output is not None:
            publish(args.output, payload)
        return {"lock": lock.json(), "lock_sha256": lock.digest()}
    if args.command == "build":
        manifest = parse_manifest_file(args.manifest)
        lock = parse_lock(read_bounded(args.lock), str(args.lock))
        payload = build_package(
            manifest, lock, read_bounded(args.artifact, 4 * 1024 * 1024)
        )
        parse_package(payload)
        publish(args.output, payload)
        return {
            "bytes": len(payload),
            "package_sha256": sha256(payload),
            "target": lock.target,
        }
    if args.command == "inspect":
        if args.manifest is not None:
            return manifest_summary(parse_manifest_file(args.manifest))
        manifest, lock, artifact = parse_package(
            read_bounded(args.package), str(args.package)
        )
        return {
            **manifest_summary(manifest),
            "artifact_sha256": sha256(artifact),
            "lock_sha256": lock.digest(),
            "target": lock.target,
        }
    if args.command == "explain":
        manifest = parse_manifest_file(args.manifest)
        return {
            "authority": {
                "capabilities": list(manifest.capabilities),
                "directories": [directory.json() for directory in manifest.directories],
            },
            "cost": manifest.resources.json(),
            "dependencies": [dependency.name for dependency in manifest.dependencies],
            "name": manifest.name,
            "services": [service.name for service in manifest.services],
            "version": manifest.version.json(),
        }
    if args.command == "plan":
        lock = parse_lock(read_bounded(args.lock), str(args.lock))
        manifests = load_manifests(args.manifest)
        catalog = {
            (manifest.name, manifest.version): manifest for manifest in manifests
        }
        if len(catalog) != len(manifests):
            raise ModelError(
                "duplicate-package", "catalog", "duplicate name and version"
            )
        return plan(lock, catalog)
    raise ModelError("unknown-command", "command", args.command)


def human(command: str, data: dict[str, object]) -> str:
    """Render human output from the exact machine-output data."""
    if command in {"check", "diagnostics"}:
        return "\n".join(
            f"ok {entry['name']} "
            f"{'.'.join(str(part) for part in entry['version'])} "
            f"{entry['manifest_sha256']}"
            for entry in data["checked"]
        )
    if command == "resolve":
        return (
            f"resolved {len(data['lock']['packages'])} packages; "
            f"lock {data['lock_sha256']}"
        )
    if command == "build":
        return (
            f"built {data['bytes']} bytes for {data['target']}; "
            f"package {data['package_sha256']}"
        )
    if command == "inspect":
        return (
            f"{data['name']} "
            f"{'.'.join(str(part) for part in data['version'])}; "
            f"manifest {data['manifest_sha256']}"
        )
    if command == "explain":
        capabilities = ", ".join(data["authority"]["capabilities"]) or "none"
        directories = (
            ", ".join(item["name"] for item in data["authority"]["directories"])
            or "none"
        )
        return (
            f"{data['name']}: capabilities={capabilities}; "
            f"directories={directories}; "
            f"cost={json.dumps(data['cost'], sort_keys=True)}"
        )
    if command == "plan":
        return (
            f"plan {data['lock_sha256']}: "
            f"{len(data['packages'])} packages for {data['target']}"
        )
    return json.dumps(data, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    """Run the stable CLI and reduce every failure to one diagnostic schema."""
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
        if args.format == "json":
            sys.stdout.buffer.write(canonical_json(result))
        else:
            print(human(args.command, data))
        return 0
    except ModelError as error:
        result = {
            "command": args.command,
            "data": None,
            "diagnostics": [error.json()],
            "ok": False,
            "schema": 1,
        }
        if args.format == "json":
            sys.stdout.buffer.write(canonical_json(result))
        else:
            print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
