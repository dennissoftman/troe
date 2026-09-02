#!/usr/bin/env python3
"""Provision one supported TROE machine from a verified production bundle.

This is the single hosted installation boundary. It consumes the exact
``troe-cloud-raw-bundle-v1`` three-image contract, verifies every byte before
touching a destination, writes with bounded buffers, flushes, reads the
installed bytes back, and publishes a canonical installation record. It is a
fixed-profile installer and claims no general GPT, filesystem, firmware,
physical-device, or cloud-provider support.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from . import mkcloud
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from tools import mkcloud


RECORD_FORMAT = "troe-installation-record-v1"
RECORD_FILENAME = "install.json"
RECORD_SCHEMA = 1
WRITE_CHUNK_BYTES = 1024 * 1024
MAX_SIGNATURE_SCAN_BYTES = 68 * 1024
CONFIRMATION_PHRASE = "destroy"

STATE_WRITING = "writing"
STATE_VERIFIED = "verified"
RECORD_STATES = (STATE_WRITING, STATE_VERIFIED)

ROLES = ("system", "activation", "state")

TARGET_FILE = "file"
TARGET_DEVICE = "device"


class SetupError(ValueError):
    """One stable machine-readable provisioning diagnostic."""

    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(f"{code} at {path}: {detail}")
        self.code = code
        self.path = path
        self.detail = detail

    def json(self) -> dict[str, str]:
        """Return the stable diagnostic schema."""
        return {"code": self.code, "detail": self.detail, "path": self.path}


def canonical_json(value: object) -> bytes:
    """Encode canonical UTF-8 JSON with a required trailing newline."""
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise SetupError("invalid-json", "$", str(error)) from error
    return encoded + b"\n"


@dataclass(frozen=True)
class Target:
    """One resolved destination with its stable identity and prior contents."""

    role: str
    requested: str
    resolved: Path
    kind: str
    identity: str
    capacity_bytes: int
    image_bytes: int
    signatures: tuple[str, ...]

    def json(self) -> dict[str, object]:
        """Return the record projection for this target."""
        return {
            "capacity_bytes": self.capacity_bytes,
            "identity": self.identity,
            "image_bytes": self.image_bytes,
            "kind": self.kind,
            "path": str(self.resolved),
            "requested": self.requested,
            "role": self.role,
            "signatures": list(self.signatures),
        }


def _sha256_file(path: Path, length: int) -> str:
    """Hash exactly ``length`` installed bytes with a bounded buffer."""
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as handle:
        while remaining > 0:
            chunk = handle.read(min(WRITE_CHUNK_BYTES, remaining))
            if not chunk:
                raise SetupError(
                    "short-read",
                    str(path),
                    f"expected {length} bytes; {remaining} missing",
                )
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _device_capacity(path: Path) -> int:
    """Return the exact byte length of a raw device without mutating it."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as error:
        raise SetupError("target-unreadable", str(path), str(error)) from error
    try:
        return os.lseek(descriptor, 0, os.SEEK_END)
    except OSError as error:
        raise SetupError("target-unsized", str(path), str(error)) from error
    finally:
        os.close(descriptor)


def _detect_signatures(path: Path, capacity: int) -> tuple[str, ...]:
    """Report recognizable existing on-media signatures before destroying them."""
    if capacity == 0:
        return ()
    span = min(capacity, MAX_SIGNATURE_SCAN_BYTES)
    try:
        with path.open("rb") as handle:
            head = handle.read(span)
    except OSError as error:
        raise SetupError("target-unreadable", str(path), str(error)) from error
    found: list[str] = []
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        found.append("mbr-boot-signature")
    if len(head) >= 1024 and head[512:520] == b"EFI PART":
        found.append("gpt-primary-header")
    if len(head) >= 1024 + 58 + 2 and head[1024 + 56 : 1024 + 58] == b"\x53\xef":
        found.append("ext2-ext3-ext4-superblock")
    if len(head) >= 90:
        if head[82:87] == b"FAT32":
            found.append("fat32-boot-sector")
        elif head[54:59] in (b"FAT12", b"FAT16"):
            found.append("fat-boot-sector")
    if any(byte != 0 for byte in head) and not found:
        found.append("unrecognized-nonzero-content")
    return tuple(found)


def _mount_table() -> tuple[str, ...]:
    """Return currently mounted source paths, best effort and bounded."""
    linux_table = Path("/proc/self/mounts")
    if linux_table.is_file():
        try:
            text = linux_table.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ()
        return tuple(
            line.split(" ")[0] for line in text.splitlines() if line and " " in line
        )
    try:
        completed = subprocess.run(
            ["/sbin/mount"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ()
    if completed.returncode != 0:
        return ()
    return tuple(
        line.split(" on ")[0]
        for line in completed.stdout.splitlines()
        if " on " in line
    )


def _refuse_mounted(path: Path) -> None:
    """Refuse a destination that is currently mounted or otherwise busy."""
    resolved = str(path)
    for source in _mount_table():
        if source == resolved or source.startswith(f"{resolved}s"):
            raise SetupError(
                "target-mounted",
                resolved,
                f"currently mounted as {source}; unmount before provisioning",
            )
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_EXCL)
    except OSError as error:
        if error.errno == errno.EBUSY:
            raise SetupError(
                "target-busy", resolved, "exclusive open refused; device is in use"
            ) from error
        return
    os.close(descriptor)


def _target_identity(info: os.stat_result) -> str:
    """Return a stable identity that never depends on enumeration order."""
    if stat.S_ISBLK(info.st_mode) or stat.S_ISCHR(info.st_mode):
        return f"device:{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    return f"file:{info.st_dev}:{info.st_ino}"


def _resolve_device_target(role: str, requested: str, image_bytes: int) -> Target:
    """Resolve one explicitly named raw-device destination."""
    path = Path(requested).expanduser()
    if path.is_symlink():
        raise SetupError(
            "target-symlink", requested, "refusing an ambiguous symbolic-link target"
        )
    resolved = path.resolve(strict=False)
    if not resolved.exists():
        raise SetupError("target-missing", requested, "destination does not exist")
    try:
        info = resolved.lstat()
    except OSError as error:
        raise SetupError("target-unreadable", requested, str(error)) from error
    if not (stat.S_ISBLK(info.st_mode) or stat.S_ISCHR(info.st_mode)):
        raise SetupError(
            "target-not-device",
            requested,
            "raw-device installation requires a block or character device",
        )
    _refuse_mounted(resolved)
    capacity = _device_capacity(resolved)
    if capacity < image_bytes:
        raise SetupError(
            "target-undersized",
            requested,
            f"{capacity} bytes cannot hold the {image_bytes}-byte {role} image",
        )
    return Target(
        role=role,
        requested=requested,
        resolved=resolved,
        kind=TARGET_DEVICE,
        identity=_target_identity(info),
        capacity_bytes=capacity,
        image_bytes=image_bytes,
        signatures=_detect_signatures(resolved, capacity),
    )


def _refuse_aliases(targets: list[Target]) -> None:
    """Refuse duplicate, aliased, or overlapping destinations."""
    by_path: dict[str, str] = {}
    by_identity: dict[str, str] = {}
    for target in targets:
        path_key = str(target.resolved)
        if path_key in by_path:
            raise SetupError(
                "target-duplicate",
                path_key,
                f"already selected for the {by_path[path_key]} role",
            )
        by_path[path_key] = target.role
        if target.identity in by_identity:
            raise SetupError(
                "target-alias",
                path_key,
                "resolves to the same media as the "
                f"{by_identity[target.identity]} role",
            )
        by_identity[target.identity] = target.role


def _prepare_runtime_directory(destination: Path) -> Path:
    """Create one private per-machine directory without reusing an existing one."""
    if destination.is_symlink():
        raise SetupError(
            "target-symlink",
            str(destination),
            "refusing an ambiguous symbolic-link destination",
        )
    if destination.exists():
        raise SetupError(
            "target-exists",
            str(destination),
            "runtime directory already exists; choose an unused destination",
        )
    try:
        destination.mkdir(parents=True, mode=0o700)
        destination.chmod(0o700)
    except OSError as error:
        raise SetupError("target-uncreatable", str(destination), str(error)) from error
    return destination


def _resolve_runtime_targets(destination: Path, images: dict[str, int]) -> list[Target]:
    """Resolve the three private runtime files inside one new directory."""
    resolved_directory = destination.resolve(strict=True)
    targets: list[Target] = []
    for role in ROLES:
        path = resolved_directory / mkcloud.BUNDLE_FILENAMES[role]
        targets.append(
            Target(
                role=role,
                requested=str(path),
                resolved=path,
                kind=TARGET_FILE,
                identity=f"path:{path}",
                capacity_bytes=images[role],
                image_bytes=images[role],
                signatures=(),
            )
        )
    return targets


def _write_target(source: Path, target: Target) -> None:
    """Stream one verified image to its destination, then flush it durably."""
    flags = os.O_WRONLY
    if target.kind == TARGET_FILE:
        flags |= os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(target.resolved, flags, 0o600)
    except OSError as error:
        raise SetupError(
            "target-unwritable", str(target.resolved), str(error)
        ) from error
    try:
        written = 0
        with source.open("rb") as handle:
            while written < target.image_bytes:
                chunk = handle.read(
                    min(WRITE_CHUNK_BYTES, target.image_bytes - written)
                )
                if not chunk:
                    raise SetupError(
                        "source-short",
                        str(source),
                        f"expected {target.image_bytes} bytes; got {written}",
                    )
                offset = 0
                while offset < len(chunk):
                    offset += os.write(descriptor, chunk[offset:])
                written += len(chunk)
        os.fsync(descriptor)
    except OSError as error:
        raise SetupError("write-failed", str(target.resolved), str(error)) from error
    finally:
        os.close(descriptor)


def _verify_target(target: Target, expected_sha256: str) -> str:
    """Read the complete installed bytes back and prove they match the bundle."""
    actual = _sha256_file(target.resolved, target.image_bytes)
    if actual != expected_sha256:
        raise SetupError(
            "readback-mismatch",
            str(target.resolved),
            f"installed bytes hash {actual}; bundle declares {expected_sha256}",
        )
    return actual


def stage_bundle_directory(bundle: Path, destination: Path) -> dict[str, Path]:
    """Copy one already-verified bundle into a new private per-machine directory.

    This is the shared durable-copy boundary: bounded buffers, one flush per
    file, and a complete read-back before the copy is reported as staged. It
    does not verify the bundle. A caller that has not already verified the
    bundle independently must use :func:`install` instead.
    """
    created = _prepare_runtime_directory(destination)
    try:
        staged: dict[str, Path] = {}
        for role in ROLES:
            source = bundle / mkcloud.BUNDLE_FILENAMES[role]
            try:
                length = source.stat().st_size
            except OSError as error:
                raise SetupError("source-missing", str(source), str(error)) from error
            target = Target(
                role=role,
                requested=str(created / mkcloud.BUNDLE_FILENAMES[role]),
                resolved=created / mkcloud.BUNDLE_FILENAMES[role],
                kind=TARGET_FILE,
                identity=f"path:{created / mkcloud.BUNDLE_FILENAMES[role]}",
                capacity_bytes=length,
                image_bytes=length,
                signatures=(),
            )
            _write_target(source, target)
            _verify_target(target, _sha256_file(source, length))
            staged[role] = target.resolved
        manifest_source = bundle / mkcloud.BUNDLE_MANIFEST
        try:
            manifest_length = manifest_source.stat().st_size
        except OSError as error:
            raise SetupError(
                "source-missing", str(manifest_source), str(error)
            ) from error
        manifest_target = Target(
            role="manifest",
            requested=str(created / mkcloud.BUNDLE_MANIFEST),
            resolved=created / mkcloud.BUNDLE_MANIFEST,
            kind=TARGET_FILE,
            identity=f"path:{created / mkcloud.BUNDLE_MANIFEST}",
            capacity_bytes=manifest_length,
            image_bytes=manifest_length,
            signatures=(),
        )
        _write_target(manifest_source, manifest_target)
        _verify_target(manifest_target, _sha256_file(manifest_source, manifest_length))
    except Exception:
        for path in sorted(created.iterdir()):
            with contextlib.suppress(OSError):
                path.unlink()
        with contextlib.suppress(OSError):
            created.rmdir()
        raise
    return staged


def _record(
    *,
    manifest: dict[str, object],
    bundle: Path,
    targets: list[Target],
    state: str,
    installed: dict[str, str],
) -> dict[str, object]:
    """Build the canonical installation record; never include keys or secrets."""
    if state not in RECORD_STATES:
        raise SetupError("invalid-state", "state", state)
    disks = {str(disk["role"]): disk for disk in manifest["disks"]}  # type: ignore[index]
    return {
        "bundle": {
            "environment": manifest["environment"],
            "format": manifest["format"],
            "kind": manifest["kind"],
            "matrix_entry": manifest["matrix_entry"],
            "path": str(bundle),
            "platform": manifest["platform"],
            "platform_id": manifest["platform_id"],
        },
        "format": RECORD_FORMAT,
        "schema": RECORD_SCHEMA,
        "state": state,
        "targets": [
            {
                **target.json(),
                "expected_sha256": str(disks[target.role]["sha256"]),
                "installed_sha256": installed.get(target.role),
            }
            for target in targets
        ],
    }


def _publish_record(path: Path | None, record: dict[str, object]) -> None:
    """Write the installation record durably so an interruption stays visible."""
    if path is None:
        return
    payload = canonical_json(record)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SetupError("record-unwritable", str(path), str(error)) from error


def _confirm(targets: list[Target], *, confirm_destroy: bool, assume_tty: bool) -> None:
    """Require one explicit destructive confirmation before mutating devices."""
    destructive = [target for target in targets if target.kind == TARGET_DEVICE]
    if not destructive:
        return
    if confirm_destroy:
        return
    if not assume_tty:
        raise SetupError(
            "confirmation-required",
            "targets",
            "raw-device installation requires --confirm-destroy in non-interactive use",
        )
    for target in destructive:
        signatures = ", ".join(target.signatures) or "none detected"
        print(
            f"  {target.role}: {target.resolved} ({target.identity}) "
            f"{target.capacity_bytes} bytes; existing signatures: {signatures}",
            file=sys.stderr,
        )
    print(
        "This irreversibly overwrites every target listed above.",
        file=sys.stderr,
    )
    answer = input(f"Type {CONFIRMATION_PHRASE!r} to proceed: ")
    if answer.strip() != CONFIRMATION_PHRASE:
        raise SetupError(
            "confirmation-declined", "targets", "destructive install refused"
        )


def install(
    *,
    bundle: Path,
    runtime_dir: Path | None = None,
    device_targets: dict[str, str] | None = None,
    record_path: Path | None = None,
    allow_test_artifacts: bool = False,
    confirm_destroy: bool = False,
    assume_tty: bool = False,
    platform_manifest_path: Path = mkcloud.PLATFORM_MANIFEST_PATH,
    environment_matrix_path: Path = mkcloud.ENVIRONMENT_MATRIX_PATH,
) -> dict[str, object]:
    """Verify one bundle completely, then provision the exact three targets."""
    if (runtime_dir is None) == (device_targets is None):
        raise SetupError(
            "target-selection",
            "targets",
            "choose exactly one of a runtime directory or explicit device targets",
        )
    bundle_directory = bundle.expanduser().resolve(strict=False)
    if not bundle_directory.is_dir():
        raise SetupError("bundle-missing", str(bundle), "bundle directory not found")

    try:
        manifest = mkcloud.verify_bundle(
            bundle_directory,
            platform_manifest_path=platform_manifest_path,
            environment_matrix_path=environment_matrix_path,
            allow_test_artifacts=allow_test_artifacts,
        )
    except ValueError as error:
        raise SetupError(
            "bundle-rejected", str(bundle_directory), str(error)
        ) from error

    disks = {str(disk["role"]): disk for disk in manifest["disks"]}  # type: ignore[index]
    if set(disks) != set(ROLES):
        raise SetupError(
            "bundle-rejected",
            str(bundle_directory),
            "bundle does not declare the exact system, activation, and state roles",
        )
    image_bytes = {role: int(disks[role]["bytes"]) for role in ROLES}  # type: ignore[index]

    if device_targets is not None:
        if set(device_targets) != set(ROLES):
            raise SetupError(
                "target-selection",
                "targets",
                "raw-device installation requires exactly one system, "
                "activation, and state target",
            )
        if record_path is None:
            raise SetupError(
                "record-required",
                "targets",
                "raw-device installation requires --record so an "
                "interruption stays identifiable",
            )
        targets = [
            _resolve_device_target(role, device_targets[role], image_bytes[role])
            for role in ROLES
        ]
        _refuse_aliases(targets)
        _confirm(targets, confirm_destroy=confirm_destroy, assume_tty=assume_tty)
        created_directory = None
    else:
        assert runtime_dir is not None
        created_directory = _prepare_runtime_directory(runtime_dir.expanduser())
        targets = _resolve_runtime_targets(created_directory, image_bytes)
        _refuse_aliases(targets)
        if record_path is None:
            record_path = created_directory / RECORD_FILENAME

    installed: dict[str, str] = {}
    _publish_record(
        record_path,
        _record(
            manifest=manifest,
            bundle=bundle_directory,
            targets=targets,
            state=STATE_WRITING,
            installed=installed,
        ),
    )

    for target in targets:
        source = bundle_directory / mkcloud.BUNDLE_FILENAMES[target.role]
        _write_target(source, target)
        installed[target.role] = _verify_target(
            target,
            str(disks[target.role]["sha256"]),  # type: ignore[index]
        )

    if created_directory is not None:
        manifest_copy = created_directory / mkcloud.BUNDLE_MANIFEST
        _publish_record(manifest_copy, manifest)

    record = _record(
        manifest=manifest,
        bundle=bundle_directory,
        targets=targets,
        state=STATE_VERIFIED,
        installed=installed,
    )
    _publish_record(record_path, record)
    return record


def read_record(path: Path) -> dict[str, object]:
    """Read one installation record and classify a possibly interrupted install."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SetupError("record-unreadable", str(path), str(error)) from error
    if len(raw) > mkcloud.MAX_MANIFEST_BYTES:
        raise SetupError("record-oversized", str(path), "record exceeds its ceiling")
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SetupError("record-invalid", str(path), str(error)) from error
    if not isinstance(decoded, dict) or decoded.get("format") != RECORD_FORMAT:
        raise SetupError("record-invalid", str(path), "not a TROE installation record")
    if decoded.get("state") not in RECORD_STATES:
        raise SetupError("record-invalid", str(path), "unknown installation state")
    return decoded


def verify_installation(record_path: Path) -> dict[str, object]:
    """Re-verify an installation and refuse to call an interrupted one complete."""
    record = read_record(record_path)
    if record["state"] != STATE_VERIFIED:
        raise SetupError(
            "installation-incomplete",
            str(record_path),
            f"installation is {record['state']}; restart it before use",
        )
    checked: list[dict[str, object]] = []
    for entry in record["targets"]:  # type: ignore[union-attr]
        path = Path(str(entry["path"]))
        actual = _sha256_file(path, int(entry["image_bytes"]))
        if actual != entry["expected_sha256"]:
            raise SetupError(
                "installation-drift",
                str(path),
                f"installed bytes hash {actual}; "
                f"record declares {entry['expected_sha256']}",
            )
        checked.append({"path": str(path), "role": entry["role"], "sha256": actual})
    return {"state": STATE_VERIFIED, "targets": checked}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the closed provisioning command surface."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("human", "json"), default="human")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_command = subparsers.add_parser(
        "install", help="provision one machine from a verified bundle"
    )
    install_command.add_argument("--bundle", type=Path, required=True)
    destination = install_command.add_mutually_exclusive_group(required=True)
    destination.add_argument(
        "--runtime-dir",
        type=Path,
        help="create one new private per-machine directory of raw images",
    )
    destination.add_argument(
        "--device",
        action="append",
        default=[],
        metavar="ROLE=PATH",
        help="explicitly name one raw device per role; repeat for all three roles",
    )
    install_command.add_argument("--record", type=Path)
    install_command.add_argument("--allow-test-artifacts", action="store_true")
    install_command.add_argument(
        "--confirm-destroy",
        action="store_true",
        help="confirm irreversible destruction of every named raw device",
    )

    verify = subparsers.add_parser(
        "verify", help="re-verify one installation record and its installed bytes"
    )
    verify.add_argument("--record", type=Path, required=True)
    return parser.parse_args(argv)


def _parse_devices(entries: list[str]) -> dict[str, str]:
    """Map explicit role assignments; enumeration order never assigns a role."""
    devices: dict[str, str] = {}
    for entry in entries:
        role, separator, path = entry.partition("=")
        if not separator or role not in ROLES or not path:
            raise SetupError(
                "target-selection",
                entry,
                "expected system=PATH, activation=PATH, or state=PATH",
            )
        if role in devices:
            raise SetupError("target-duplicate", entry, f"role {role} named twice")
        devices[role] = path
    return devices


def execute(args: argparse.Namespace) -> dict[str, object]:
    """Execute one provisioning operation."""
    if args.command == "install":
        devices = _parse_devices(args.device) if args.device else None
        return install(
            bundle=args.bundle,
            runtime_dir=args.runtime_dir,
            device_targets=devices,
            record_path=args.record,
            allow_test_artifacts=args.allow_test_artifacts,
            confirm_destroy=args.confirm_destroy,
            assume_tty=sys.stdin.isatty() and sys.stderr.isatty(),
        )
    if args.command == "verify":
        return verify_installation(args.record)
    raise SetupError("unknown-command", "command", args.command)


def human(command: str, data: dict[str, object]) -> str:
    """Render human output from the exact machine-output data."""
    if command == "install":
        bundle = data["bundle"]
        lines = [
            f"installed {bundle['kind']} bundle {bundle['matrix_entry']} "  # type: ignore[index]
            f"({bundle['platform']}/{bundle['environment']}); state {data['state']}"  # type: ignore[index]
        ]
        lines.extend(
            f"  {entry['role']}: {entry['path']} {entry['image_bytes']} bytes "
            f"{entry['installed_sha256']}"
            for entry in data["targets"]  # type: ignore[union-attr]
        )
        return "\n".join(lines)
    if command == "verify":
        lines = [f"installation {data['state']}"]
        lines.extend(
            f"  {entry['role']}: {entry['path']} {entry['sha256']}"
            for entry in data["targets"]  # type: ignore[union-attr]
        )
        return "\n".join(lines)
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
            "schema": RECORD_SCHEMA,
        }
        if args.format == "json":
            sys.stdout.buffer.write(canonical_json(result))
        else:
            print(human(args.command, data))
        return 0
    except SetupError as error:
        result = {
            "command": args.command,
            "data": None,
            "diagnostics": [error.json()],
            "ok": False,
            "schema": RECORD_SCHEMA,
        }
        if args.format == "json":
            sys.stdout.buffer.write(canonical_json(result))
        else:
            print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
