#!/usr/bin/env python3
"""Transactional hosted system generations, migration, rollback, and garbage
collection."""

from __future__ import annotations

import base64
import fcntl
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .package_model import (
        MAX_DOCUMENT_BYTES,
        ModelError,
        TargetLock,
        Version,
        canonical_json,
        decode_json,
        parse_lock,
        parse_package,
        plan,
        sha256,
    )
    from .package_trust import (
        MAX_ENVELOPE_BYTES,
        MAX_PACKAGE_BYTES,
        parse_envelope,
        validate_release_payload,
        verify_initial_root,
        verify_release,
    )
else:
    from package_model import (
        MAX_DOCUMENT_BYTES,
        ModelError,
        TargetLock,
        Version,
        canonical_json,
        decode_json,
        parse_lock,
        parse_package,
        plan,
        sha256,
    )
    from package_trust import (
        MAX_ENVELOPE_BYTES,
        MAX_PACKAGE_BYTES,
        parse_envelope,
        validate_release_payload,
        verify_initial_root,
        verify_release,
    )


MAX_CONFIG_FILES = 128
MAX_CONFIG_BYTES = 64 * 1024
MAX_CONFIG_FILE_BYTES = 8 * 1024
MAX_MIGRATIONS = 32
MAX_MIGRATION_OPERATIONS = 64
MAX_DATA_BYTES = 64 * 1024
MAX_DIAGNOSTICS = 64
MAX_DIAGNOSTIC_DETAIL_BYTES = 1024
MAX_GENERATIONS = 4096
MAX_TRUST_GENERATION = 2**63 - 1
_PACKAGE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_CONFIG_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")
_DATA_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class SimulatedPowerLoss(BaseException):
    """Test-only abrupt stop raised immediately after one durable boundary."""


@dataclass(frozen=True)
class FailAfter:
    """Inject exactly one abrupt stop after a named durable boundary."""

    boundary: str

    def __call__(self, boundary: str) -> None:
        if boundary == self.boundary:
            raise SimulatedPowerLoss(boundary)


@dataclass(frozen=True)
class ReleaseInput:
    """One signed release envelope paired with its exact TPKG bytes."""

    release: bytes
    package: bytes


@dataclass(frozen=True)
class Migration:
    """One bounded, idempotent package data migration."""

    package: str
    from_version: Version | None
    to_version: Version
    mode: str
    operations: tuple[dict[str, object], ...]

    def json(self) -> dict[str, object]:
        """Return the canonical migration descriptor."""
        return {
            "from_version": None
            if self.from_version is None
            else self.from_version.json(),
            "mode": self.mode,
            "operations": list(self.operations),
            "package": self.package,
            "schema": 1,
            "to_version": self.to_version.json(),
        }


def _object(value: object, fields: set[str], path: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ModelError("invalid-fields", path, f"expected exactly {sorted(fields)}")
    return value


def _integer(value: object, minimum: int, maximum: int, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ModelError("invalid-integer", path, f"expected {minimum}..{maximum}")
    return value


def _optional_generation(value: object, path: str) -> int | None:
    if value is None:
        return None
    return _integer(value, 1, MAX_GENERATIONS, path)


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ModelError("invalid-digest", path, "expected lowercase SHA-256")
    return value


def _package_name(value: object, path: str) -> str:
    if not isinstance(value, str) or _PACKAGE.fullmatch(value) is None:
        raise ModelError("invalid-name", path, "package name is not canonical")
    return value


def _read_bounded(path: Path, maximum: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
            raise ModelError(
                "invalid-file", str(path), "regular non-symlink file required"
            )
        return path.read_bytes()
    except OSError as error:
        raise ModelError("read-failed", str(path), str(error)) from error


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def _ensure_directory(path: Path) -> None:
    try:
        if path.is_symlink():
            raise ModelError("invalid-directory", str(path), "symbolic link forbidden")
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir() or path.is_symlink():
            raise ModelError("invalid-directory", str(path), "directory required")
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def _write_new(path: Path, payload: bytes) -> None:
    _ensure_directory(path.parent)
    try:
        with path.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        _fsync_directory(path.parent)
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def _atomic_replace(path: Path, payload: bytes) -> None:
    _ensure_directory(path.parent)
    if path.is_symlink():
        raise ModelError("invalid-file", str(path), "symbolic link forbidden")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        _fsync_directory(path.parent)
    except OSError as error:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
        raise ModelError("write-failed", str(path), str(error)) from error


def _unlink_durable(path: Path) -> None:
    try:
        if path.is_symlink():
            raise ModelError("invalid-file", str(path), "symbolic link forbidden")
        path.unlink(missing_ok=True)
        _fsync_directory(path.parent)
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def parse_projection(
    data: bytes, label: str = "projection"
) -> tuple[tuple[str, bytes], ...]:
    """Parse one canonical bounded configuration projection document."""
    document = _object(decode_json(data, label), {"files", "schema"}, label)
    if document["schema"] != 1 or not isinstance(document["files"], list):
        raise ModelError("unsupported-schema", label, "expected projection schema 1")
    if len(document["files"]) > MAX_CONFIG_FILES:
        raise ModelError(
            "config-capacity", f"{label}.files", str(len(document["files"]))
        )
    result: list[tuple[str, bytes]] = []
    total = 0
    for index, raw in enumerate(document["files"]):
        path = f"{label}.files[{index}]"
        entry = _object(raw, {"data", "path"}, path)
        relative = entry["path"]
        if not isinstance(relative, str):
            raise ModelError("invalid-config-path", f"{path}.path", "string required")
        components = relative.split("/")
        if (
            not relative
            or relative.startswith("/")
            or len(components) > 14
            or any(
                _CONFIG_COMPONENT.fullmatch(component) is None
                for component in components
            )
            or len(f"/sys/config/{relative}".encode()) > 256
        ):
            raise ModelError("invalid-config-path", f"{path}.path", relative)
        encoded = entry["data"]
        if not isinstance(encoded, str):
            raise ModelError(
                "invalid-config-data", f"{path}.data", "base64 string required"
            )
        try:
            payload = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise ModelError(
                "invalid-config-data", f"{path}.data", "invalid base64"
            ) from error
        if base64.b64encode(payload).decode("ascii") != encoded:
            raise ModelError(
                "invalid-config-data", f"{path}.data", "noncanonical base64"
            )
        if len(payload) > MAX_CONFIG_FILE_BYTES:
            raise ModelError("config-capacity", f"{path}.data", str(len(payload)))
        total += len(payload)
        if total > MAX_CONFIG_BYTES:
            raise ModelError("config-capacity", f"{label}.files", str(total))
        result.append((relative, payload))
    names = [name for name, _payload in result]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ModelError(
            "noncanonical-order", f"{label}.files", "unique sorted paths required"
        )
    for name in names:
        if any(other.startswith(f"{name}/") for other in names):
            raise ModelError("config-collision", f"{label}.files", name)
    if canonical_json(document) != data:
        raise ModelError("noncanonical-json", label, "projection bytes differ")
    return tuple(result)


def projection_bytes(files: Iterable[tuple[str, bytes]]) -> bytes:
    """Encode and independently validate one canonical projection."""
    document = {
        "files": [
            {"data": base64.b64encode(payload).decode("ascii"), "path": path}
            for path, payload in sorted(files)
        ],
        "schema": 1,
    }
    encoded = canonical_json(document)
    parse_projection(encoded)
    return encoded


def parse_migration(data: bytes, label: str = "migration") -> Migration:
    """Parse one canonical bounded declarative migration."""
    document = _object(
        decode_json(data, label),
        {"from_version", "mode", "operations", "package", "schema", "to_version"},
        label,
    )
    if document["schema"] != 1:
        raise ModelError("unsupported-schema", f"{label}.schema", "expected 1")
    package = _package_name(document["package"], f"{label}.package")
    from_version = (
        None
        if document["from_version"] is None
        else Version.parse(document["from_version"], f"{label}.from_version")
    )
    to_version = Version.parse(document["to_version"], f"{label}.to_version")
    mode = document["mode"]
    if mode not in {"forward-only", "reversible"}:
        raise ModelError("invalid-migration-mode", f"{label}.mode", str(mode))
    raw_operations = document["operations"]
    if (
        not isinstance(raw_operations, list)
        or not raw_operations
        or len(raw_operations) > MAX_MIGRATION_OPERATIONS
    ):
        raise ModelError("migration-capacity", f"{label}.operations", "expected 1..64")
    operations: list[dict[str, object]] = []
    for index, raw in enumerate(raw_operations):
        path = f"{label}.operations[{index}]"
        if not isinstance(raw, dict) or raw.get("op") not in {"delete", "set"}:
            raise ModelError(
                "invalid-migration-operation", path, "set or delete required"
            )
        expected = {"op", "path", "value"} if raw["op"] == "set" else {"op", "path"}
        operation = _object(raw, expected, path)
        keys = operation["path"]
        if (
            not isinstance(keys, list)
            or not keys
            or len(keys) > 8
            or any(
                not isinstance(key, str) or _DATA_KEY.fullmatch(key) is None
                for key in keys
            )
        ):
            raise ModelError("invalid-migration-path", f"{path}.path", str(keys))
        operations.append(operation)
    migration = Migration(package, from_version, to_version, mode, tuple(operations))
    if canonical_json(migration.json()) != data:
        raise ModelError("noncanonical-json", label, "migration bytes differ")
    return migration


def _pointer_document(
    active: int | None,
    previous: int | None,
    recovery: int | None,
    status: str,
    transaction: int | None,
) -> dict[str, object]:
    return {
        "active": active,
        "previous": previous,
        "recovery": recovery,
        "schema": 1,
        "status": status,
        "transaction": transaction,
    }


class LifecycleStore:
    """One process-serialized durable system deployment store."""

    def __init__(
        self,
        root: Path,
        injector: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root
        self.injector = injector
        self._initialize()

    def _initialize(self) -> None:
        if self.root.is_symlink():
            raise ModelError("invalid-store", str(self.root), "symbolic link forbidden")
        for relative in (
            "data",
            "desired",
            "diagnostics",
            "generations",
            "health",
            "objects/packages",
            "objects/releases",
            "objects/roots",
            "snapshots",
            "state",
        ):
            _ensure_directory(self.root / relative)
        pointer = self.root / "state/pointer.json"
        if not pointer.exists():
            _write_new(
                pointer,
                canonical_json(_pointer_document(None, None, None, "recovery", None)),
            )
        desired = self.root / "desired/config.json"
        if not desired.exists():
            _write_new(desired, projection_bytes(()))

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock_path = self.root / "state/operator.lock"
        try:
            descriptor = os.open(
                lock_path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        except OSError as error:
            raise ModelError("lock-failed", str(lock_path), str(error)) from error
        finally:
            if "descriptor" in locals():
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    def _boundary(self, name: str) -> None:
        if self.injector is not None:
            self.injector(name)

    def _read_pointer(self) -> dict[str, object]:
        path = self.root / "state/pointer.json"
        data = _read_bounded(path, 4096)
        document = _object(
            decode_json(data, str(path)),
            {"active", "previous", "recovery", "schema", "status", "transaction"},
            str(path),
        )
        if document["schema"] != 1 or document["status"] not in {
            "healthy",
            "migrating",
            "pending",
            "recovery",
            "recovery-required",
        }:
            raise ModelError("invalid-pointer", str(path), "schema or status")
        active = _optional_generation(document["active"], "pointer.active")
        previous = _optional_generation(document["previous"], "pointer.previous")
        recovery = _optional_generation(document["recovery"], "pointer.recovery")
        transaction = _optional_generation(
            document["transaction"], "pointer.transaction"
        )
        if document["status"] == "recovery" and active is not None:
            raise ModelError(
                "invalid-pointer", str(path), "recovery must not name active"
            )
        if document["status"] != "recovery" and active is None:
            raise ModelError("invalid-pointer", str(path), "active generation required")
        if active is not None and previous == active:
            raise ModelError("invalid-pointer", str(path), "active equals previous")
        if (
            document["status"] in {"migrating", "recovery-required"}
            and transaction != active
        ):
            raise ModelError(
                "invalid-pointer", str(path), "transaction must name active"
            )
        if document["status"] == "pending" and transaction not in {None, active}:
            raise ModelError(
                "invalid-pointer", str(path), "pending transaction differs"
            )
        if document["status"] in {"healthy", "recovery"} and transaction is not None:
            raise ModelError(
                "invalid-pointer", str(path), "settled state has transaction"
            )
        if canonical_json(document) != data:
            raise ModelError("noncanonical-json", str(path), "pointer bytes differ")
        return {
            **document,
            "active": active,
            "previous": previous,
            "recovery": recovery,
            "transaction": transaction,
        }

    def _write_pointer(self, document: Mapping[str, object]) -> None:
        _atomic_replace(
            self.root / "state/pointer.json", canonical_json(dict(document))
        )

    def status(self) -> dict[str, object]:
        """Return the verified pointer without resolving intentional pending work."""
        with self._locked():
            pointer = self._read_pointer()
            self._verify_pointer_generations(pointer)
            return pointer

    def set_desired_configuration(self, projection: bytes) -> str:
        """Replace desired configuration without changing the active generation."""
        parse_projection(projection, "desired-configuration")
        with self._locked():
            before = self._read_pointer()
            _atomic_replace(self.root / "desired/config.json", projection)
            after = self._read_pointer()
            if before != after:
                raise ModelError(
                    "pointer-changed", "desired-configuration", "unexpected"
                )
            self._boundary("config.desired")
        return sha256(projection)

    def desired_configuration(self) -> bytes:
        """Return the independently validated desired configuration bytes."""
        with self._locked():
            data = _read_bounded(self.root / "desired/config.json", MAX_DOCUMENT_BYTES)
            parse_projection(data, "desired-configuration")
            return data

    def deploy(
        self,
        lock_bytes: bytes,
        root_envelope_bytes: bytes,
        root_payload_sha256: str,
        releases: Sequence[ReleaseInput],
        *,
        now: int,
        migrations: Sequence[Migration] = (),
        allow_downgrade: Iterable[str] = (),
        offline: bool = False,
        offline_grace: int = 0,
    ) -> int:
        """Verify and stage one complete generation, migrate, and make it pending."""
        with self._locked():
            pointer = self._read_pointer()
            if pointer["status"] not in {"healthy", "recovery"}:
                raise ModelError(
                    "operation-in-progress", "pointer.status", str(pointer["status"])
                )
            if self._read_transaction() is not None:
                raise ModelError(
                    "operation-in-progress", "transaction", "explicit recovery required"
                )
            if any((self.root / "generations").glob(".stage-*")):
                raise ModelError(
                    "operation-in-progress", "generations", "explicit recovery required"
                )
            lock = parse_lock(lock_bytes, "deployment-lock")
            root_envelope, root = verify_initial_root(
                root_envelope_bytes, root_payload_sha256, now
            )
            retained_root_generation, _retained_sequences = self._read_trust_state()
            if root["generation"] < retained_root_generation:
                raise ModelError(
                    "root-replay", "root.generation", str(root["generation"])
                )
            records, manifests = self._verify_release_set(
                lock,
                root,
                releases,
                now=now,
                offline=offline,
                offline_grace=offline_grace,
            )
            projection = _read_bounded(
                self.root / "desired/config.json", MAX_DOCUMENT_BYTES
            )
            config_files = parse_projection(projection, "desired-configuration")
            candidate_migrations = tuple(
                parse_migration(
                    canonical_json(migration.json()), f"migrations[{index}]"
                )
                for index, migration in enumerate(migrations)
            )
            if len(candidate_migrations) > MAX_MIGRATIONS:
                raise ModelError(
                    "migration-capacity", "migrations", str(len(migrations))
                )
            self._validate_migrations(pointer["active"], lock, candidate_migrations)
            downgrade_names = self._validate_downgrade(
                pointer["active"], lock, set(allow_downgrade)
            )
            generation = self._next_generation()
            self._store_object("roots", root_envelope.digest(), root_envelope_bytes)
            for record, release_input in zip(
                records, sorted(releases, key=self._release_name), strict=True
            ):
                self._store_object(
                    "packages", record["package_sha256"], release_input.package
                )
                self._store_object(
                    "releases", record["release_sha256"], release_input.release
                )
            generation_document = {
                "config_sha256": sha256(projection),
                "downgrade_authorized": downgrade_names,
                "generation": generation,
                "lock": lock.json(),
                "lock_sha256": lock.digest(),
                "migrations": [migration.json() for migration in candidate_migrations],
                "packages": records,
                "plan": plan(lock, manifests),
                "predecessor": pointer["active"],
                "root_envelope_sha256": root_envelope.digest(),
                "root_generation": root["generation"],
                "root_payload_sha256": root_payload_sha256,
                "schema": 1,
            }
            self._publish_generation(generation_document, config_files)
            if candidate_migrations:
                self._prepare_migrations(
                    generation, pointer["active"], candidate_migrations
                )
                migrating = _pointer_document(
                    generation,
                    pointer["active"],
                    pointer["recovery"],
                    "migrating",
                    generation,
                )
                self._write_pointer(migrating)
                self._boundary("activation.migrating")
                self._apply_migrations_locked(generation)
            pending = _pointer_document(
                generation,
                pointer["active"],
                pointer["recovery"],
                "pending",
                generation if candidate_migrations else None,
            )
            self._write_pointer(pending)
            self._boundary("activation.pending")
            return generation

    @staticmethod
    def _release_name(value: ReleaseInput) -> str:
        manifest, _lock, _artifact = parse_package(
            value.package, "release-input.package"
        )
        return manifest.name

    def _verify_release_set(
        self,
        lock: TargetLock,
        root: Mapping[str, object],
        releases: Sequence[ReleaseInput],
        *,
        now: int,
        offline: bool,
        offline_grace: int,
    ) -> tuple[list[dict[str, object]], dict[tuple[str, Version], object]]:
        if len(releases) != len(lock.packages):
            raise ModelError(
                "incomplete-plan", "releases", "one release per locked package"
            )
        minimums = self._trust_sequences()
        records: list[dict[str, object]] = []
        manifests: dict[tuple[str, Version], object] = {}
        ordered = sorted(releases, key=self._release_name)
        for release_input in ordered:
            manifest, embedded_lock, artifact = parse_package(
                release_input.package, "deployment.package"
            )
            verified = verify_release(
                root,
                release_input.release,
                release_input.package,
                now=now,
                offline=offline,
                offline_grace=offline_grace,
                minimum_sequence=minimums.get(manifest.name, 0),
            )
            if verified.status != "active":
                raise ModelError(
                    "recovery-only", f"package:{manifest.name}", "not activatable"
                )
            if embedded_lock != lock:
                raise ModelError(
                    "lock-mismatch", f"package:{manifest.name}", "embedded lock"
                )
            locked = next(
                (package for package in lock.packages if package.name == manifest.name),
                None,
            )
            if (
                locked is None
                or locked.version != manifest.version
                or locked.manifest_sha256 != manifest.digest()
                or locked.artifact_sha256 != sha256(artifact)
            ):
                raise ModelError(
                    "plan-mismatch", f"package:{manifest.name}", "identity differs"
                )
            identity = (manifest.name, manifest.version)
            if identity in manifests:
                raise ModelError(
                    "duplicate-package", f"package:{manifest.name}", "duplicate"
                )
            manifests[identity] = manifest
            records.append(
                {
                    "artifact_sha256": locked.artifact_sha256,
                    "manifest_sha256": locked.manifest_sha256,
                    "name": manifest.name,
                    "package_sha256": sha256(release_input.package),
                    "release_sequence": verified.payload["sequence"],
                    "release_sha256": sha256(release_input.release),
                    "version": manifest.version.json(),
                }
            )
        expected = [(package.name, package.version) for package in lock.packages]
        actual = [
            (record["name"], Version.parse(record["version"], "record.version"))
            for record in records
        ]
        if actual != expected:
            raise ModelError(
                "incomplete-plan", "releases", "package set differs from lock"
            )
        return records, manifests

    def _store_object(self, kind: str, identity: str, payload: bytes) -> None:
        path = (
            self.root
            / "objects"
            / kind
            / (f"{identity}.tpkg" if kind == "packages" else f"{identity}.json")
        )
        if path.exists():
            if (
                _read_bounded(path, max(MAX_PACKAGE_BYTES, MAX_ENVELOPE_BYTES))
                != payload
            ):
                raise ModelError("object-collision", str(path), identity)
            return
        _write_new(path, payload)
        self._boundary(f"object.{kind}.{identity}")

    def _next_generation(self) -> int:
        generations: list[int] = [
            int(path.name)
            for path in (self.root / "generations").iterdir()
            if path.name.isdigit() and len(path.name) == 20
        ]
        generation = max(generations, default=0) + 1
        if generation > MAX_GENERATIONS:
            raise ModelError("generation-capacity", "generations", str(generation))
        return generation

    def _publish_generation(
        self,
        document: Mapping[str, object],
        config_files: Sequence[tuple[str, bytes]],
    ) -> None:
        generation = document["generation"]
        staging = self.root / "generations" / f".stage-{generation:020d}"
        destination = self._generation_path(generation)
        if staging.exists() or staging.is_symlink() or destination.exists():
            raise ModelError("generation-exists", str(destination), str(generation))
        _ensure_directory(staging / "sys-config")
        _write_new(staging / "generation.json", canonical_json(dict(document)))
        for relative, payload in config_files:
            _write_new(staging / "sys-config" / relative, payload)
        self._sync_tree(staging)
        self._verify_generation_directory(staging, expected=generation)
        self._boundary("generation.staged")
        try:
            staging.rename(destination)
        except OSError as error:
            raise ModelError("write-failed", str(destination), str(error)) from error
        _fsync_directory(destination.parent)
        self._boundary("generation.published")

    @staticmethod
    def _sync_tree(root: Path) -> None:
        directories = [path for path in root.rglob("*") if path.is_dir()]
        for directory in sorted(
            directories, key=lambda path: len(path.parts), reverse=True
        ):
            _fsync_directory(directory)
        _fsync_directory(root)

    def _generation_path(self, generation: int) -> Path:
        return self.root / "generations" / f"{generation:020d}"

    def _read_generation(self, generation: int) -> dict[str, object]:
        return self._verify_generation_directory(
            self._generation_path(generation), generation
        )

    def _verify_generation_directory(
        self, directory: Path, expected: int
    ) -> dict[str, object]:
        if directory.is_symlink() or not directory.is_dir():
            raise ModelError("invalid-generation", str(directory), "directory required")
        data = _read_bounded(directory / "generation.json", MAX_DOCUMENT_BYTES)
        document = _object(
            decode_json(data, str(directory / "generation.json")),
            {
                "config_sha256",
                "downgrade_authorized",
                "generation",
                "lock",
                "lock_sha256",
                "migrations",
                "packages",
                "plan",
                "predecessor",
                "root_envelope_sha256",
                "root_generation",
                "root_payload_sha256",
                "schema",
            },
            str(directory / "generation.json"),
        )
        if document["schema"] != 1 or document["generation"] != expected:
            raise ModelError("invalid-generation", str(directory), "schema or identity")
        lock = parse_lock(canonical_json(document["lock"]), "generation.lock")
        if lock.digest() != _digest(document["lock_sha256"], "generation.lock_sha256"):
            raise ModelError("invalid-generation", str(directory), "lock digest")
        _digest(document["root_envelope_sha256"], "generation.root_envelope_sha256")
        _digest(document["root_payload_sha256"], "generation.root_payload_sha256")
        _integer(
            document["root_generation"],
            1,
            MAX_TRUST_GENERATION,
            "generation.root_generation",
        )
        predecessor = _optional_generation(
            document["predecessor"], "generation.predecessor"
        )
        if predecessor is not None and predecessor >= expected:
            raise ModelError("invalid-generation", str(directory), "predecessor order")
        authorized = document["downgrade_authorized"]
        if (
            not isinstance(authorized, list)
            or authorized != sorted(authorized)
            or len(authorized) != len(set(authorized))
            or any(
                not isinstance(name, str) or _PACKAGE.fullmatch(name) is None
                for name in authorized
            )
        ):
            raise ModelError("invalid-generation", str(directory), "downgrade policy")
        if not isinstance(document["packages"], list) or len(
            document["packages"]
        ) != len(lock.packages):
            raise ModelError("invalid-generation", str(directory), "package count")
        package_names: list[str] = []
        manifests: dict[tuple[str, Version], object] = {}
        for index, raw in enumerate(document["packages"]):
            path = f"generation.packages[{index}]"
            record = _object(
                raw,
                {
                    "artifact_sha256",
                    "manifest_sha256",
                    "name",
                    "package_sha256",
                    "release_sequence",
                    "release_sha256",
                    "version",
                },
                path,
            )
            name = _package_name(record["name"], f"{path}.name")
            package_names.append(name)
            Version.parse(record["version"], f"{path}.version")
            for field in (
                "artifact_sha256",
                "manifest_sha256",
                "package_sha256",
                "release_sha256",
            ):
                _digest(record[field], f"{path}.{field}")
            _integer(
                record["release_sequence"], 1, 2**63 - 1, f"{path}.release_sequence"
            )
            package_path = (
                self.root / "objects/packages" / f"{record['package_sha256']}.tpkg"
            )
            release_path = (
                self.root / "objects/releases" / f"{record['release_sha256']}.json"
            )
            package_bytes = _read_bounded(package_path, MAX_PACKAGE_BYTES)
            release_bytes = _read_bounded(release_path, MAX_ENVELOPE_BYTES)
            if (
                sha256(package_bytes) != record["package_sha256"]
                or sha256(release_bytes) != record["release_sha256"]
            ):
                raise ModelError("invalid-generation", path, "object digest")
            manifest, embedded_lock, artifact = parse_package(
                package_bytes, str(package_path)
            )
            version = Version.parse(record["version"], f"{path}.version")
            if (
                embedded_lock != lock
                or manifest.name != name
                or manifest.version != version
                or manifest.digest() != record["manifest_sha256"]
                or sha256(artifact) != record["artifact_sha256"]
            ):
                raise ModelError("invalid-generation", path, "package identity")
            manifests[(name, version)] = manifest
            envelope = parse_envelope(release_bytes, str(release_path))
            release = validate_release_payload(envelope.payload, str(release_path))
            if (
                envelope.digest() != record["release_sha256"]
                or release["name"] != name
                or release["version"] != version
                or release["package_sha256"] != record["package_sha256"]
                or release["manifest_sha256"] != record["manifest_sha256"]
                or release["lock_sha256"] != document["lock_sha256"]
                or release["sequence"] != record["release_sequence"]
            ):
                raise ModelError("invalid-generation", path, "release identity")
        if package_names != sorted(package_names) or package_names != [
            package.name for package in lock.packages
        ]:
            raise ModelError("invalid-generation", str(directory), "package ordering")
        if document["plan"] != plan(lock, manifests):
            raise ModelError("invalid-generation", str(directory), "activation plan")
        root_object = (
            self.root / "objects/roots" / f"{document['root_envelope_sha256']}.json"
        )
        root_bytes = _read_bounded(root_object, MAX_ENVELOPE_BYTES)
        root_envelope = parse_envelope(root_bytes, str(root_object))
        if (
            root_envelope.digest() != document["root_envelope_sha256"]
            or sha256(root_envelope.payload) != document["root_payload_sha256"]
        ):
            raise ModelError("invalid-generation", str(directory), "root identity")
        if (
            not isinstance(document["migrations"], list)
            or len(document["migrations"]) > MAX_MIGRATIONS
        ):
            raise ModelError("invalid-generation", str(directory), "migrations")
        for index, migration in enumerate(document["migrations"]):
            parse_migration(
                canonical_json(migration), f"generation.migrations[{index}]"
            )
        projection = self._projection_from_tree(directory / "sys-config")
        if sha256(projection) != _digest(
            document["config_sha256"], "generation.config_sha256"
        ):
            raise ModelError(
                "invalid-generation", str(directory), "configuration digest"
            )
        expected_entries = {"generation.json", "sys-config"}
        if {path.name for path in directory.iterdir()} != expected_entries:
            raise ModelError("invalid-generation", str(directory), "unexpected files")
        if canonical_json(document) != data:
            raise ModelError(
                "noncanonical-json", str(directory), "generation bytes differ"
            )
        return document

    @staticmethod
    def _projection_from_tree(root: Path) -> bytes:
        if root.is_symlink() or not root.is_dir():
            raise ModelError("invalid-config-tree", str(root), "directory required")
        files: list[tuple[str, bytes]] = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ModelError(
                    "invalid-config-tree", str(path), "symbolic link forbidden"
                )
            if path.is_file():
                files.append(
                    (
                        path.relative_to(root).as_posix(),
                        _read_bounded(path, MAX_CONFIG_FILE_BYTES),
                    )
                )
            elif not path.is_dir():
                raise ModelError("invalid-config-tree", str(path), "unexpected type")
        return projection_bytes(files)

    def _validate_downgrade(
        self, active: int | None, lock: TargetLock, authorized: set[str]
    ) -> list[str]:
        if any(_PACKAGE.fullmatch(name) is None for name in authorized):
            raise ModelError("downgrade-policy", "allow_downgrade", "invalid package")
        actual: set[str] = set()
        if active is not None:
            previous = self._read_generation(active)
            versions = {
                record["name"]: Version.parse(record["version"], "active.version")
                for record in previous["packages"]
            }
            for package in lock.packages:
                if (
                    package.name in versions
                    and package.version < versions[package.name]
                ):
                    actual.add(package.name)
        if actual != authorized:
            raise ModelError(
                "downgrade-policy",
                "allow_downgrade",
                f"required={sorted(actual)} supplied={sorted(authorized)}",
            )
        return sorted(actual)

    def _validate_migrations(
        self,
        active: int | None,
        lock: TargetLock,
        migrations: Sequence[Migration],
    ) -> None:
        if [migration.package for migration in migrations] != sorted(
            migration.package for migration in migrations
        ) or len({migration.package for migration in migrations}) != len(migrations):
            raise ModelError(
                "noncanonical-order", "migrations", "unique sorted packages"
            )
        old_versions: dict[str, Version] = {}
        if active is not None:
            generation = self._read_generation(active)
            old_versions = {
                record["name"]: Version.parse(record["version"], "active.version")
                for record in generation["packages"]
            }
        new_versions = {package.name: package.version for package in lock.packages}
        for migration in migrations:
            if (
                old_versions.get(migration.package) != migration.from_version
                or new_versions.get(migration.package) != migration.to_version
                or migration.from_version == migration.to_version
            ):
                raise ModelError(
                    "migration-version",
                    f"migration:{migration.package}",
                    "plan differs",
                )

    def _prepare_migrations(
        self,
        generation: int,
        previous: int | None,
        migrations: Sequence[Migration],
    ) -> None:
        snapshot_root = self.root / "snapshots" / f"{generation:020d}"
        _ensure_directory(snapshot_root)
        for migration in migrations:
            if migration.mode == "reversible":
                _write_new(
                    snapshot_root / f"{migration.package}.json",
                    self._read_data(migration.package),
                )
        transaction = {
            "applied": [],
            "generation": generation,
            "migrations": [migration.json() for migration in migrations],
            "operation": "deploy",
            "previous": previous,
            "schema": 1,
        }
        _atomic_replace(
            self.root / "state/transaction.json", canonical_json(transaction)
        )
        self._boundary("migration.intent")

    def _read_transaction(self) -> dict[str, object] | None:
        path = self.root / "state/transaction.json"
        if not path.exists():
            return None
        data = _read_bounded(path, MAX_DOCUMENT_BYTES)
        document = _object(
            decode_json(data, str(path)),
            {
                "applied",
                "generation",
                "migrations",
                "operation",
                "previous",
                "schema",
            },
            str(path),
        )
        if (
            document["schema"] != 1
            or document["operation"] not in {"deploy", "rollback"}
            or not isinstance(document["applied"], list)
            or not isinstance(document["migrations"], list)
        ):
            raise ModelError("invalid-transaction", str(path), "schema or arrays")
        generation = _integer(
            document["generation"], 1, MAX_GENERATIONS, "transaction.generation"
        )
        _optional_generation(document["previous"], "transaction.previous")
        migrations = [
            parse_migration(canonical_json(raw), f"transaction.migrations[{index}]")
            for index, raw in enumerate(document["migrations"])
        ]
        applied = [
            _package_name(name, "transaction.applied") for name in document["applied"]
        ]
        migration_names = [migration.package for migration in migrations]
        if (
            migration_names != sorted(migration_names)
            or len(migration_names) != len(set(migration_names))
            or applied != sorted(applied)
            or len(applied) != len(set(applied))
            or not set(applied).issubset(set(migration_names))
        ):
            raise ModelError("invalid-transaction", str(path), "applied set")
        if canonical_json(document) != data:
            raise ModelError("noncanonical-json", str(path), "transaction bytes differ")
        return {**document, "generation": generation, "migrations_typed": migrations}

    def _read_data(self, package: str) -> bytes:
        path = self.root / "data" / f"{package}.json"
        if not path.exists():
            return canonical_json({})
        data = _read_bounded(path, MAX_DATA_BYTES)
        document = decode_json(data, str(path), MAX_DATA_BYTES)
        if not isinstance(document, dict) or canonical_json(document) != data:
            raise ModelError("invalid-data", str(path), "canonical object required")
        return data

    def _write_data(self, package: str, data: bytes) -> None:
        document = decode_json(data, f"data:{package}", MAX_DATA_BYTES)
        if not isinstance(document, dict) or canonical_json(document) != data:
            raise ModelError(
                "invalid-data", f"data:{package}", "canonical object required"
            )
        _atomic_replace(self.root / "data" / f"{package}.json", data)

    @staticmethod
    def _migrate_data(data: bytes, migration: Migration) -> bytes:
        document = decode_json(data, f"data:{migration.package}", MAX_DATA_BYTES)
        if not isinstance(document, dict):
            raise ModelError(
                "invalid-data", f"data:{migration.package}", "object required"
            )
        for operation in migration.operations:
            current = document
            keys = operation["path"]
            for key in keys[:-1]:
                child = current.get(key)
                if child is None and operation["op"] == "set":
                    child = {}
                    current[key] = child
                if not isinstance(child, dict):
                    raise ModelError(
                        "migration-conflict", f"data:{migration.package}", str(keys)
                    )
                current = child
            final = keys[-1]
            if operation["op"] == "set":
                current[final] = operation["value"]
            else:
                current.pop(final, None)
        encoded = canonical_json(document)
        if len(encoded) > MAX_DATA_BYTES:
            raise ModelError(
                "data-capacity", f"data:{migration.package}", str(len(encoded))
            )
        return encoded

    def _apply_migrations_locked(self, generation: int) -> None:
        transaction = self._read_transaction()
        if (
            transaction is None
            or transaction["generation"] != generation
            or transaction["operation"] != "deploy"
        ):
            raise ModelError("invalid-transaction", "migration", str(generation))
        generation_document = self._read_generation(generation)
        if (
            transaction["migrations"] != generation_document["migrations"]
            or transaction["previous"] != generation_document["predecessor"]
        ):
            raise ModelError("invalid-transaction", "migration", "generation differs")
        applied = set(transaction["applied"])
        for migration in transaction["migrations_typed"]:
            migrated = self._migrate_data(self._read_data(migration.package), migration)
            self._write_data(migration.package, migrated)
            applied.add(migration.package)
            transaction_document = {
                "applied": sorted(applied),
                "generation": generation,
                "migrations": transaction["migrations"],
                "operation": "deploy",
                "previous": transaction["previous"],
                "schema": 1,
            }
            _atomic_replace(
                self.root / "state/transaction.json",
                canonical_json(transaction_document),
            )
            self._boundary(f"migration.package.{migration.package}")

    def mark_health(self, generation: int, healthy: bool) -> dict[str, object]:
        """Persist one health result and commit or automatically recover."""
        with self._locked():
            pointer = self._read_pointer()
            recovery_retry = (
                pointer["active"] == generation
                and pointer["status"] == "recovery-required"
                and healthy
            )
            if pointer["active"] != generation or (
                pointer["status"] != "pending" and not recovery_retry
            ):
                raise ModelError("health-state", "pointer", str(generation))
            self._read_generation(generation)
            if pointer["transaction"] is not None:
                transaction = self._read_transaction()
                if (
                    transaction is None
                    or transaction["operation"] != "deploy"
                    or transaction["generation"] != generation
                    or set(transaction["applied"])
                    != {
                        migration.package
                        for migration in transaction["migrations_typed"]
                    }
                ):
                    raise ModelError(
                        "health-state", "transaction", "migration incomplete"
                    )
            receipt = {"generation": generation, "healthy": healthy, "schema": 1}
            receipt_path = self.root / "health" / f"{generation:020d}.json"
            if recovery_retry:
                if receipt_path.exists():
                    prior_data = _read_bounded(receipt_path, 1024)
                    prior = _object(
                        decode_json(prior_data, str(receipt_path)),
                        {"generation", "healthy", "schema"},
                        str(receipt_path),
                    )
                    if (
                        prior["schema"] != 1
                        or prior["generation"] != generation
                        or prior["healthy"] is not False
                        or canonical_json(prior) != prior_data
                    ):
                        raise ModelError(
                            "health-state", str(receipt_path), "prior failure"
                        )
                    _atomic_replace(receipt_path, canonical_json(receipt))
                else:
                    _write_new(receipt_path, canonical_json(receipt))
            else:
                _write_new(receipt_path, canonical_json(receipt))
            self._boundary("health.checked")
            self._apply_health_locked(pointer, healthy)
            return self._read_pointer()

    def _apply_health_locked(
        self, pointer: Mapping[str, object], healthy: bool
    ) -> None:
        generation = pointer["active"]
        if healthy:
            recovery = (
                pointer["recovery"] if pointer["recovery"] is not None else generation
            )
            committed = _pointer_document(
                generation,
                pointer["previous"],
                recovery,
                "healthy",
                None,
            )
            self._write_pointer(committed)
            self._boundary("activation.committed")
            self._reconcile_trust_locked()
            self._cleanup_transaction_locked()
            return
        generation_document = self._read_generation(generation)
        migrations = [
            parse_migration(canonical_json(raw), "generation.migration")
            for raw in generation_document["migrations"]
        ]
        if any(migration.mode == "forward-only" for migration in migrations):
            required = _pointer_document(
                generation,
                pointer["previous"],
                pointer["recovery"],
                "recovery-required",
                generation,
            )
            self._write_pointer(required)
            self._boundary("activation.recovery-required")
            self._record_diagnostic_locked(
                "forward-only-health-failure",
                "candidate data cannot safely run predecessor code",
                generation,
            )
            return
        self._restore_snapshots_locked(generation)
        self._restore_previous_pointer(pointer["previous"], pointer["recovery"])
        self._boundary("rollback.restored")
        self._record_diagnostic_locked(
            "health-rollback",
            "candidate failed health and predecessor was restored",
            generation,
        )
        self._cleanup_transaction_locked()

    def _restore_previous_pointer(
        self, previous: int | None, recovery: int | None
    ) -> None:
        if previous is None:
            self._write_pointer(
                _pointer_document(None, None, recovery, "recovery", None)
            )
            return
        previous_document = self._read_generation(previous)
        self._write_pointer(
            _pointer_document(
                previous,
                previous_document["predecessor"],
                recovery,
                "healthy",
                None,
            )
        )

    def _restore_snapshots_locked(self, generation: int) -> None:
        generation_document = self._read_generation(generation)
        for raw in generation_document["migrations"]:
            migration = parse_migration(canonical_json(raw), "generation.migration")
            if migration.mode == "reversible":
                snapshot = (
                    self.root
                    / "snapshots"
                    / f"{generation:020d}"
                    / f"{migration.package}.json"
                )
                self._write_data(
                    migration.package, _read_bounded(snapshot, MAX_DATA_BYTES)
                )
                self._boundary(f"rollback.package.{migration.package}")

    def rollback(self) -> dict[str, object]:
        """Select the known predecessor and restore reversible data snapshots."""
        with self._locked():
            pointer = self._read_pointer()
            if pointer["status"] != "healthy" or pointer["previous"] is None:
                raise ModelError(
                    "rollback-unavailable", "pointer", "healthy predecessor required"
                )
            active = pointer["active"]
            active_document = self._read_generation(active)
            migrations = [
                parse_migration(canonical_json(raw), "generation.migration")
                for raw in active_document["migrations"]
            ]
            if any(migration.mode == "forward-only" for migration in migrations):
                self._record_diagnostic_locked(
                    "rollback-forward-only",
                    "healthy generation remains active because predecessor "
                    "data is incompatible",
                    active,
                )
                raise ModelError("rollback-forward-only", "migration", str(active))
            transaction = {
                "applied": sorted(migration.package for migration in migrations),
                "generation": active,
                "migrations": [migration.json() for migration in migrations],
                "operation": "rollback",
                "previous": pointer["previous"],
                "schema": 1,
            }
            _atomic_replace(
                self.root / "state/transaction.json", canonical_json(transaction)
            )
            self._boundary("rollback.intent")
            self._write_pointer(
                _pointer_document(
                    active,
                    pointer["previous"],
                    pointer["recovery"],
                    "migrating",
                    active,
                )
            )
            self._boundary("rollback.migrating")
            self._restore_snapshots_locked(active)
            self._restore_previous_pointer(pointer["previous"], pointer["recovery"])
            self._boundary("rollback.restored")
            self._cleanup_transaction_locked()
            return self._read_pointer()

    def recover(self) -> dict[str, object]:
        """Recover one interrupted lifecycle operation and verify its result."""
        with self._locked():
            self._recover_locked()
            pointer = self._read_pointer()
            self._verify_pointer_generations(pointer)
            return pointer

    def _recover_locked(self) -> None:
        self._remove_staging_locked()
        pointer = self._read_pointer()
        transaction = self._read_transaction()
        if transaction is not None and transaction["operation"] == "rollback":
            if pointer["status"] == "migrating":
                if (
                    pointer["active"] != transaction["generation"]
                    or pointer["previous"] != transaction["previous"]
                ):
                    raise ModelError(
                        "invalid-transaction", "rollback", "pointer differs"
                    )
                self._restore_snapshots_locked(transaction["generation"])
                self._restore_previous_pointer(
                    transaction["previous"], pointer["recovery"]
                )
                self._boundary("rollback.restored")
            self._cleanup_transaction_locked()
            return
        if pointer["status"] == "recovery-required":
            receipt_path = self.root / "health" / f"{pointer['active']:020d}.json"
            if not receipt_path.exists():
                return
            receipt_data = _read_bounded(receipt_path, 1024)
            receipt = _object(
                decode_json(receipt_data, str(receipt_path)),
                {"generation", "healthy", "schema"},
                str(receipt_path),
            )
            if (
                receipt["schema"] != 1
                or receipt["generation"] != pointer["active"]
                or not isinstance(receipt["healthy"], bool)
                or canonical_json(receipt) != receipt_data
            ):
                raise ModelError("invalid-health", str(receipt_path), "receipt")
            if receipt["healthy"]:
                self._apply_health_locked(pointer, True)
            return
        if pointer["status"] in {"healthy", "recovery"}:
            if transaction is not None:
                self._cleanup_transaction_locked()
            if pointer["status"] == "healthy":
                self._reconcile_trust_locked()
            self._prune_diagnostics_locked()
            return
        generation = pointer["active"]
        receipt_path = self.root / "health" / f"{generation:020d}.json"
        if receipt_path.exists():
            receipt_data = _read_bounded(receipt_path, 1024)
            receipt = _object(
                decode_json(receipt_data, str(receipt_path)),
                {"generation", "healthy", "schema"},
                str(receipt_path),
            )
            if (
                receipt["schema"] != 1
                or receipt["generation"] != generation
                or not isinstance(receipt["healthy"], bool)
                or canonical_json(receipt) != receipt_data
            ):
                raise ModelError("invalid-health", str(receipt_path), "receipt")
            if pointer["status"] == "migrating":
                self._apply_migrations_locked(generation)
                pointer = _pointer_document(
                    generation,
                    pointer["previous"],
                    pointer["recovery"],
                    "pending",
                    generation,
                )
                self._write_pointer(pointer)
            self._apply_health_locked(pointer, receipt["healthy"])
            return
        if transaction is not None:
            forward = any(
                migration.mode == "forward-only"
                for migration in transaction["migrations_typed"]
            )
            if pointer["status"] in {"migrating", "pending"} and forward:
                if pointer["status"] == "migrating":
                    self._apply_migrations_locked(generation)
                required = _pointer_document(
                    generation,
                    pointer["previous"],
                    pointer["recovery"],
                    "recovery-required",
                    generation,
                )
                self._write_pointer(required)
                self._boundary("activation.recovery-required")
                return
            self._restore_snapshots_locked(generation)
        self._restore_previous_pointer(pointer["previous"], pointer["recovery"])
        self._boundary("rollback.restored")
        self._cleanup_transaction_locked()

    def _remove_staging_locked(self) -> None:
        for path in sorted((self.root / "generations").glob(".stage-*")):
            if path.is_symlink() or not path.is_dir():
                raise ModelError("invalid-generation", str(path), "staging type")
            shutil.rmtree(path)
            _fsync_directory(path.parent)
            self._boundary("cleanup.staging")

    def _cleanup_transaction_locked(self) -> None:
        path = self.root / "state/transaction.json"
        if path.exists():
            _unlink_durable(path)
            self._boundary("cleanup.transaction")

    def _read_trust_state(self) -> tuple[int, dict[str, int]]:
        path = self.root / "state/trust.json"
        if not path.exists():
            return 0, {}
        data = _read_bounded(path, MAX_DOCUMENT_BYTES)
        document = _object(
            decode_json(data, str(path)),
            {"releases", "root_generation", "schema"},
            str(path),
        )
        if document["schema"] != 1 or not isinstance(document["releases"], list):
            raise ModelError("invalid-trust-state", str(path), "schema")
        root_generation = _integer(
            document["root_generation"],
            1,
            MAX_TRUST_GENERATION,
            "trust.root_generation",
        )
        releases: dict[str, int] = {}
        for raw in document["releases"]:
            entry = _object(raw, {"name", "sequence"}, "trust.releases")
            name = _package_name(entry["name"], "trust.name")
            if name in releases:
                raise ModelError("invalid-trust-state", str(path), "duplicate package")
            releases[name] = _integer(entry["sequence"], 1, 2**63 - 1, "trust.sequence")
        if list(releases) != sorted(releases) or canonical_json(document) != data:
            raise ModelError("invalid-trust-state", str(path), "ordering or bytes")
        return root_generation, releases

    def _trust_sequences(self) -> dict[str, int]:
        return self._read_trust_state()[1]

    def _reconcile_trust_locked(self) -> None:
        pointer = self._read_pointer()
        if pointer["status"] != "healthy":
            return
        generation = self._read_generation(pointer["active"])
        retained_root_generation, existing = self._read_trust_state()
        sequences = dict(existing)
        for record in generation["packages"]:
            sequences[record["name"]] = max(
                sequences.get(record["name"], 0), record["release_sequence"]
            )
        document = {
            "releases": [
                {"name": name, "sequence": sequence}
                for name, sequence in sorted(sequences.items())
            ],
            "root_generation": max(
                retained_root_generation, generation["root_generation"]
            ),
            "schema": 1,
        }
        path = self.root / "state/trust.json"
        encoded = canonical_json(document)
        if not path.exists() or _read_bounded(path, MAX_DOCUMENT_BYTES) != encoded:
            _atomic_replace(path, encoded)

    def verify(self, *, now: int | None = None) -> dict[str, object]:
        """Verify retained generations; optionally repeat signature/freshness checks."""
        with self._locked():
            pointer = self._read_pointer()
            roots = self._verify_pointer_generations(pointer)
            verified_releases = 0
            if now is not None:
                for generation_number in roots:
                    generation = self._read_generation(generation_number)
                    root_path = (
                        self.root
                        / "objects/roots"
                        / f"{generation['root_envelope_sha256']}.json"
                    )
                    root_bytes = _read_bounded(root_path, MAX_ENVELOPE_BYTES)
                    _envelope, root = verify_initial_root(
                        root_bytes, generation["root_payload_sha256"], now
                    )
                    for record in generation["packages"]:
                        package = _read_bounded(
                            self.root
                            / "objects/packages"
                            / f"{record['package_sha256']}.tpkg",
                            MAX_PACKAGE_BYTES,
                        )
                        release = _read_bounded(
                            self.root
                            / "objects/releases"
                            / f"{record['release_sha256']}.json",
                            MAX_ENVELOPE_BYTES,
                        )
                        verified = verify_release(
                            root,
                            release,
                            package,
                            now=now,
                            minimum_sequence=record["release_sequence"],
                        )
                        if verified.status != "active":
                            raise ModelError("recovery-only", "verify", record["name"])
                        verified_releases += 1
            return {
                "generations": sorted(roots),
                "pointer": pointer,
                "verified_releases": verified_releases,
            }

    def _verify_pointer_generations(self, pointer: Mapping[str, object]) -> set[int]:
        roots = {
            generation
            for generation in (
                pointer["active"],
                pointer["previous"],
                pointer["recovery"],
                pointer["transaction"],
            )
            if generation is not None
        }
        for generation in roots:
            self._read_generation(generation)
        if pointer["transaction"] is not None:
            transaction = self._read_transaction()
            if (
                transaction is None
                or transaction["generation"] != pointer["transaction"]
            ):
                raise ModelError(
                    "invalid-transaction", "pointer.transaction", "state differs"
                )
        return roots

    def record_diagnostic(
        self, code: str, detail: str, generation: int | None = None
    ) -> int:
        """Append one bounded persistent diagnostic and prune the oldest entry."""
        with self._locked():
            return self._record_diagnostic_locked(code, detail, generation)

    def _record_diagnostic_locked(
        self, code: str, detail: str, generation: int | None
    ) -> int:
        if _DATA_KEY.fullmatch(code) is None:
            raise ModelError("invalid-diagnostic", "code", code)
        if len(detail.encode("utf-8")) > MAX_DIAGNOSTIC_DETAIL_BYTES:
            raise ModelError("invalid-diagnostic", "detail", "too long")
        _optional_generation(generation, "diagnostic.generation")
        existing = [
            int(path.stem)
            for path in (self.root / "diagnostics").glob("*.json")
            if path.stem.isdigit()
        ]
        sequence = max(existing, default=0) + 1
        document = {
            "code": code,
            "detail": detail,
            "generation": generation,
            "schema": 1,
            "sequence": sequence,
        }
        _write_new(
            self.root / "diagnostics" / f"{sequence:020d}.json",
            canonical_json(document),
        )
        self._boundary("diagnostic.appended")
        self._prune_diagnostics_locked()
        return sequence

    def _prune_diagnostics_locked(self) -> None:
        paths = sorted((self.root / "diagnostics").glob("*.json"))
        for path in paths[:-MAX_DIAGNOSTICS]:
            _unlink_durable(path)
            self._boundary("cleanup.diagnostic")

    def diagnostics(self) -> list[dict[str, object]]:
        """Read and validate the bounded persistent diagnostic log."""
        with self._locked():
            self._prune_diagnostics_locked()
            result: list[dict[str, object]] = []
            for path in sorted((self.root / "diagnostics").glob("*.json")):
                data = _read_bounded(path, 4096)
                document = _object(
                    decode_json(data, str(path)),
                    {"code", "detail", "generation", "schema", "sequence"},
                    str(path),
                )
                if document["schema"] != 1 or canonical_json(document) != data:
                    raise ModelError("invalid-diagnostic", str(path), "schema or bytes")
                result.append(document)
            return result

    def garbage_collect(self) -> dict[str, list[str]]:
        """Delete only objects unreachable from active lifecycle roots."""
        with self._locked():
            pointer = self._read_pointer()
            roots = self._verify_pointer_generations(pointer)
            transaction = self._read_transaction()
            if transaction is not None:
                roots.add(transaction["generation"])
                self._read_generation(transaction["generation"])
            reachable: dict[str, set[str]] = {
                "packages": set(),
                "releases": set(),
                "roots": set(),
            }
            for generation in roots:
                document = self._read_generation(generation)
                reachable["roots"].add(document["root_envelope_sha256"])
                for record in document["packages"]:
                    reachable["packages"].add(record["package_sha256"])
                    reachable["releases"].add(record["release_sha256"])
            removed: dict[str, list[str]] = {
                "generations": [],
                "health": [],
                "packages": [],
                "releases": [],
                "roots": [],
                "snapshots": [],
            }
            for path in sorted((self.root / "generations").iterdir()):
                if (
                    path.name.isdigit()
                    and len(path.name) == 20
                    and int(path.name) not in roots
                ):
                    if path.is_symlink() or not path.is_dir():
                        raise ModelError(
                            "invalid-generation", str(path), "directory required"
                        )
                    shutil.rmtree(path)
                    _fsync_directory(path.parent)
                    removed["generations"].append(path.name)
                    self._boundary(f"gc.generation.{path.name}")
            for kind in ("packages", "releases", "roots"):
                suffix = ".tpkg" if kind == "packages" else ".json"
                for path in sorted((self.root / "objects" / kind).glob(f"*{suffix}")):
                    identity = path.name.removesuffix(suffix)
                    if identity not in reachable[kind]:
                        _unlink_durable(path)
                        removed[kind].append(identity)
                        self._boundary(f"gc.{kind}.{identity}")
            for kind in ("snapshots", "health"):
                base = self.root / kind
                for path in sorted(base.iterdir()):
                    stem = path.stem if kind == "health" else path.name
                    if stem.isdigit() and int(stem) not in roots:
                        if path.is_dir() and not path.is_symlink():
                            shutil.rmtree(path)
                            _fsync_directory(path.parent)
                        else:
                            _unlink_durable(path)
                        removed[kind].append(path.name)
                        self._boundary(f"gc.{kind}.{path.name}")
            return removed
