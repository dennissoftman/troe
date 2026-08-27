#!/usr/bin/env python3
"""Bounded package manifests, target locks, resolution, and package artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence


MAX_DOCUMENT_BYTES = 256 * 1024
MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 128
MAX_DEPENDENCIES = 32
MAX_TARGETS = 2
MAX_CAPABILITIES = 32
MAX_DIRECTORIES = 8
MAX_SERVICES = 16
SUPPORTED_TARGETS = {
    "aarch64-unknown-uefi": "aarch64",
    "x86_64-unknown-uefi": "x86_64",
}
KNOWN_CAPABILITIES = {
    "clock.observe",
    "clock.control",
    "fs.directory.read",
    "fs.directory.mutate",
    "network.datagram",
    "network.tcp-connect",
    "timer.wait",
}
DIRECTORY_ROLES = {"assets", "config", "data"}
DIRECTORY_RIGHTS = {"read", "read-mutate"}
_NAME = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_SERVICE = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, order=True)
class Version:
    """One canonical three-component package version."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: object, path: str) -> Version:
        """Parse a bounded version array."""
        if (
            not isinstance(value, list)
            or len(value) != 3
            or any(not isinstance(part, int) or isinstance(part, bool) for part in value)
            or any(part < 0 or part > 65_535 for part in value)
        ):
            raise ModelError("invalid-version", path, "expected [major, minor, patch]")
        return cls(*value)

    def json(self) -> list[int]:
        """Return the canonical JSON representation."""
        return [self.major, self.minor, self.patch]

    def text(self) -> str:
        """Return the stable human representation."""
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class VersionRange:
    """Inclusive minimum and exclusive maximum dependency constraint."""

    minimum: Version
    maximum_exclusive: Version

    def contains(self, version: Version) -> bool:
        """Whether one exact version is within this range."""
        return self.minimum <= version < self.maximum_exclusive

    def json(self) -> dict[str, object]:
        """Return the canonical JSON representation."""
        return {
            "maximum_exclusive": self.maximum_exclusive.json(),
            "minimum": self.minimum.json(),
        }


@dataclass(frozen=True)
class Dependency:
    """One named dependency and its closed version interval."""

    name: str
    requirement: VersionRange

    def json(self) -> dict[str, object]:
        """Return the canonical JSON representation."""
        return {"name": self.name, "requirement": self.requirement.json()}


@dataclass(frozen=True)
class TargetArtifact:
    """One architecture-native artifact and every build input identity."""

    target: str
    architecture: str
    abi: tuple[int, int]
    artifact_sha256: str
    artifact_bytes: int
    sdk_sha256: str
    toolchain_sha256: str

    def json(self) -> dict[str, object]:
        """Return the canonical JSON representation."""
        return {
            "abi": list(self.abi),
            "architecture": self.architecture,
            "artifact_bytes": self.artifact_bytes,
            "artifact_sha256": self.artifact_sha256,
            "sdk_sha256": self.sdk_sha256,
            "target": self.target,
            "toolchain_sha256": self.toolchain_sha256,
        }


@dataclass(frozen=True)
class ResourceLimits:
    """Hard application resource declarations."""

    execution_ms: int
    handles: int
    heap_bytes: int
    stack_bytes: int

    def json(self) -> dict[str, int]:
        """Return the canonical JSON representation."""
        return {
            "execution_ms": self.execution_ms,
            "handles": self.handles,
            "heap_bytes": self.heap_bytes,
            "stack_bytes": self.stack_bytes,
        }


@dataclass(frozen=True)
class DirectoryGrant:
    """One package root declaration resolved only during activation."""

    name: str
    role: str
    rights: str

    def json(self) -> dict[str, str]:
        """Return the canonical JSON representation."""
        return {"name": self.name, "rights": self.rights, "role": self.role}


@dataclass(frozen=True)
class Service:
    """One package-provided service identity."""

    name: str
    command: str

    def json(self) -> dict[str, str]:
        """Return the canonical JSON representation."""
        return {"command": self.command, "name": self.name}


@dataclass(frozen=True)
class Manifest:
    """Fully validated PMAN v1 package manifest."""

    name: str
    version: Version
    dependencies: tuple[Dependency, ...]
    targets: tuple[TargetArtifact, ...]
    capabilities: tuple[str, ...]
    directories: tuple[DirectoryGrant, ...]
    resources: ResourceLimits
    services: tuple[Service, ...]

    def json(self) -> dict[str, object]:
        """Return canonical PMAN v1 data."""
        return {
            "capabilities": list(self.capabilities),
            "dependencies": [dependency.json() for dependency in self.dependencies],
            "directories": [directory.json() for directory in self.directories],
            "name": self.name,
            "resources": self.resources.json(),
            "schema": 1,
            "services": [service.json() for service in self.services],
            "targets": [target.json() for target in self.targets],
            "version": self.version.json(),
        }

    def target(self, target: str) -> TargetArtifact:
        """Select one exact target or fail closed."""
        selected = [artifact for artifact in self.targets if artifact.target == target]
        if len(selected) != 1:
            raise ModelError(
                "unsupported-target",
                f"manifest:{self.name}.targets",
                f"no unique artifact for {target}",
            )
        return selected[0]

    def digest(self) -> str:
        """Return the canonical manifest identity."""
        return sha256(canonical_json(self.json()))


@dataclass(frozen=True)
class LockedPackage:
    """One exact resolver choice in a target lock."""

    name: str
    version: Version
    manifest_sha256: str
    artifact_sha256: str
    artifact_bytes: int
    sdk_sha256: str
    toolchain_sha256: str
    dependencies: tuple[tuple[str, Version], ...]

    def json(self) -> dict[str, object]:
        """Return canonical lock data."""
        return {
            "artifact_bytes": self.artifact_bytes,
            "artifact_sha256": self.artifact_sha256,
            "dependencies": [
                {"name": name, "version": version.json()}
                for name, version in self.dependencies
            ],
            "manifest_sha256": self.manifest_sha256,
            "name": self.name,
            "sdk_sha256": self.sdk_sha256,
            "toolchain_sha256": self.toolchain_sha256,
            "version": self.version.json(),
        }


@dataclass(frozen=True)
class TargetLock:
    """Deterministic, complete PLOCK v1 resolution result."""

    root: str
    target: str
    packages: tuple[LockedPackage, ...]

    def json(self) -> dict[str, object]:
        """Return canonical PLOCK v1 data."""
        return {
            "packages": [package.json() for package in self.packages],
            "root": self.root,
            "schema": 1,
            "target": self.target,
        }

    def digest(self) -> str:
        """Return the complete target-lock identity."""
        return sha256(canonical_json(self.json()))


@dataclass
class ModelError(ValueError):
    """One stable machine-readable package-model diagnostic."""

    code: str
    path: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code} at {self.path}: {self.detail}"

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
        raise ModelError("invalid-json", "$", str(error)) from error
    return encoded + b"\n"


def sha256(data: bytes) -> str:
    """Return a lowercase SHA-256 identity."""
    return hashlib.sha256(data).hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ModelError("duplicate-field", "$", f"duplicate field {key!r}")
        result[key] = value
    return result


def decode_json(data: bytes, label: str, maximum: int = MAX_DOCUMENT_BYTES) -> object:
    """Decode bounded JSON while rejecting duplicate keys and non-integer numbers."""
    if not data or len(data) > maximum:
        raise ModelError("document-size", label, f"must be 1..{maximum} bytes")
    try:
        return json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ModelError("invalid-number", label, "floating-point values are forbidden")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ModelError("invalid-number", label, "non-finite values are forbidden")
            ),
        )
    except UnicodeDecodeError as error:
        raise ModelError("invalid-utf8", label, str(error)) from error
    except json.JSONDecodeError as error:
        raise ModelError("invalid-json", label, str(error)) from error


def _object(value: object, fields: set[str], path: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ModelError("invalid-fields", path, f"expected exactly {sorted(fields)}")
    return value


def _array(value: object, path: str, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ModelError("invalid-array", path, f"expected at most {maximum} entries")
    return value


def _name(value: object, path: str, matcher: re.Pattern[str] = _NAME) -> str:
    if not isinstance(value, str) or matcher.fullmatch(value) is None:
        raise ModelError("invalid-name", path, "name is not canonical")
    return value


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ModelError("invalid-digest", path, "expected lowercase SHA-256")
    return value


def _bounded_int(value: object, path: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise ModelError("invalid-limit", path, f"expected {minimum}..{maximum}")
    return value


def _strictly_sorted(values: Sequence[object], key: Callable[[object], object], path: str) -> None:
    keys = [key(value) for value in values]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ModelError("noncanonical-order", path, "entries must be unique and sorted")


def parse_manifest(data: bytes, label: str = "manifest") -> Manifest:
    """Parse one strict, bounded PMAN v1 document."""
    document = _object(
        decode_json(data, label),
        {
            "capabilities",
            "dependencies",
            "directories",
            "name",
            "resources",
            "schema",
            "services",
            "targets",
            "version",
        },
        label,
    )
    if document["schema"] != 1:
        raise ModelError("unsupported-schema", f"{label}.schema", "expected 1")
    name = _name(document["name"], f"{label}.name")
    version = Version.parse(document["version"], f"{label}.version")

    raw_dependencies = _array(
        document["dependencies"], f"{label}.dependencies", MAX_DEPENDENCIES
    )
    dependencies: list[Dependency] = []
    for index, raw in enumerate(raw_dependencies):
        path = f"{label}.dependencies[{index}]"
        entry = _object(raw, {"name", "requirement"}, path)
        requirement = _object(
            entry["requirement"], {"maximum_exclusive", "minimum"}, f"{path}.requirement"
        )
        minimum = Version.parse(requirement["minimum"], f"{path}.requirement.minimum")
        maximum = Version.parse(
            requirement["maximum_exclusive"],
            f"{path}.requirement.maximum_exclusive",
        )
        if minimum >= maximum:
            raise ModelError("invalid-range", f"{path}.requirement", "range is empty")
        dependencies.append(
            Dependency(_name(entry["name"], f"{path}.name"), VersionRange(minimum, maximum))
        )
    _strictly_sorted(dependencies, lambda dependency: dependency.name, f"{label}.dependencies")
    if any(dependency.name == name for dependency in dependencies):
        raise ModelError("self-dependency", f"{label}.dependencies", name)

    raw_targets = _array(document["targets"], f"{label}.targets", MAX_TARGETS)
    if not raw_targets:
        raise ModelError("invalid-array", f"{label}.targets", "at least one target is required")
    targets: list[TargetArtifact] = []
    target_fields = {
        "abi",
        "architecture",
        "artifact_bytes",
        "artifact_sha256",
        "sdk_sha256",
        "target",
        "toolchain_sha256",
    }
    for index, raw in enumerate(raw_targets):
        path = f"{label}.targets[{index}]"
        entry = _object(raw, target_fields, path)
        target = entry["target"]
        if not isinstance(target, str) or target not in SUPPORTED_TARGETS:
            raise ModelError("unsupported-target", f"{path}.target", str(target))
        architecture = entry["architecture"]
        if architecture != SUPPORTED_TARGETS[target]:
            raise ModelError("target-mismatch", f"{path}.architecture", str(architecture))
        abi = entry["abi"]
        if (
            not isinstance(abi, list)
            or len(abi) != 2
            or abi[0] != 1
            or abi[1] not in {0, 1}
        ):
            raise ModelError("unsupported-abi", f"{path}.abi", "expected [1,0] or [1,1]")
        targets.append(
            TargetArtifact(
                target,
                architecture,
                (abi[0], abi[1]),
                _digest(entry["artifact_sha256"], f"{path}.artifact_sha256"),
                _bounded_int(entry["artifact_bytes"], f"{path}.artifact_bytes", 1, 4 * 1024 * 1024),
                _digest(entry["sdk_sha256"], f"{path}.sdk_sha256"),
                _digest(entry["toolchain_sha256"], f"{path}.toolchain_sha256"),
            )
        )
    _strictly_sorted(targets, lambda target: target.target, f"{label}.targets")

    capabilities = tuple(
        _name(value, f"{label}.capabilities[{index}]", _SERVICE)
        for index, value in enumerate(
            _array(document["capabilities"], f"{label}.capabilities", MAX_CAPABILITIES)
        )
    )
    _strictly_sorted(capabilities, lambda value: value, f"{label}.capabilities")
    unknown = set(capabilities) - KNOWN_CAPABILITIES
    if unknown:
        raise ModelError(
            "unknown-capability", f"{label}.capabilities", ",".join(sorted(unknown))
        )

    raw_directories = _array(document["directories"], f"{label}.directories", MAX_DIRECTORIES)
    directories: list[DirectoryGrant] = []
    for index, raw in enumerate(raw_directories):
        path = f"{label}.directories[{index}]"
        entry = _object(raw, {"name", "rights", "role"}, path)
        role = entry["role"]
        rights = entry["rights"]
        if role not in DIRECTORY_ROLES:
            raise ModelError("unknown-directory-role", f"{path}.role", str(role))
        if rights not in DIRECTORY_RIGHTS or (role in {"assets", "config"} and rights != "read"):
            raise ModelError("invalid-directory-rights", f"{path}.rights", str(rights))
        directories.append(
            DirectoryGrant(_name(entry["name"], f"{path}.name"), role, rights)
        )
    _strictly_sorted(directories, lambda directory: directory.name, f"{label}.directories")

    resource = _object(
        document["resources"],
        {"execution_ms", "handles", "heap_bytes", "stack_bytes"},
        f"{label}.resources",
    )
    resources = ResourceLimits(
        _bounded_int(resource["execution_ms"], f"{label}.resources.execution_ms", 1, 50),
        _bounded_int(resource["handles"], f"{label}.resources.handles", 1, 8),
        _bounded_int(resource["heap_bytes"], f"{label}.resources.heap_bytes", 4096, 64 * 1024 * 1024),
        _bounded_int(resource["stack_bytes"], f"{label}.resources.stack_bytes", 4096, 1024 * 1024),
    )

    raw_services = _array(document["services"], f"{label}.services", MAX_SERVICES)
    services: list[Service] = []
    for index, raw in enumerate(raw_services):
        path = f"{label}.services[{index}]"
        entry = _object(raw, {"command", "name"}, path)
        command = _name(entry["command"], f"{path}.command")
        services.append(Service(_name(entry["name"], f"{path}.name", _SERVICE), command))
    _strictly_sorted(services, lambda service: service.name, f"{label}.services")
    return Manifest(
        name,
        version,
        tuple(dependencies),
        tuple(targets),
        capabilities,
        tuple(directories),
        resources,
        tuple(services),
    )


def parse_manifest_file(path: Path) -> Manifest:
    """Read and parse a manifest without following unbounded input."""
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ModelError("read-failed", str(path), str(error)) from error
    return parse_manifest(data, str(path))


def resolve(root: str, target: str, manifests: Iterable[Manifest]) -> TargetLock:
    """Resolve the highest compatible versions deterministically and reject conflicts."""
    if target not in SUPPORTED_TARGETS:
        raise ModelError("unsupported-target", "target", target)
    catalog: dict[str, list[Manifest]] = {}
    identities: set[tuple[str, Version]] = set()
    for manifest in manifests:
        identity = (manifest.name, manifest.version)
        if identity in identities:
            raise ModelError("duplicate-package", "catalog", f"{manifest.name}@{manifest.version.text()}")
        identities.add(identity)
        manifest.target(target)
        catalog.setdefault(manifest.name, []).append(manifest)
    if len(identities) > MAX_PACKAGES:
        raise ModelError("package-capacity", "catalog", f"more than {MAX_PACKAGES} versions")
    for versions in catalog.values():
        versions.sort(key=lambda manifest: manifest.version, reverse=True)
    if root not in catalog:
        raise ModelError("missing-root", "root", root)

    visited_states: set[tuple[tuple[str, Version], ...]] = set()
    state_count = 0

    def search(
        supplied: dict[str, Manifest],
    ) -> tuple[dict[str, Manifest] | None, ModelError | None]:
        nonlocal state_count
        state_count += 1
        if state_count > 16_384:
            return None, ModelError(
                "resolution-capacity", "catalog", "more than 16384 resolver states"
            )

        reachable = {root}
        pending = [root]
        while pending:
            owner = pending.pop()
            manifest = supplied.get(owner)
            if manifest is None:
                continue
            for dependency in manifest.dependencies:
                if dependency.name not in reachable:
                    reachable.add(dependency.name)
                    pending.append(dependency.name)
        selected = {name: manifest for name, manifest in supplied.items() if name in reachable}
        state = tuple(sorted((name, manifest.version) for name, manifest in selected.items()))
        if state in visited_states:
            return None, ModelError("version-conflict", "catalog", "repeated resolver state")
        visited_states.add(state)

        requirements: dict[str, list[tuple[str, VersionRange]]] = {}
        for owner, manifest in selected.items():
            for dependency in manifest.dependencies:
                requirements.setdefault(dependency.name, []).append(
                    (owner, dependency.requirement)
                )

        unresolved: list[str] = []
        for name in sorted(reachable):
            if name not in catalog:
                owners = sorted(owner for owner, _range in requirements.get(name, []))
                return None, ModelError(
                    "missing-dependency", f"package:{owners[0] if owners else root}", name
                )
            selected_manifest = selected.get(name)
            if selected_manifest is None or any(
                not requirement.contains(selected_manifest.version)
                for _owner, requirement in requirements.get(name, [])
            ):
                unresolved.append(name)
        if not unresolved:
            try:
                _validate_acyclic(root, selected)
            except ModelError as error:
                return None, error
            return selected, None

        name = unresolved[0]
        constraints = requirements.get(name, [])
        candidates = [
            manifest
            for manifest in catalog[name]
            if all(requirement.contains(manifest.version) for _owner, requirement in constraints)
        ]
        if not candidates:
            owners = ",".join(sorted(owner for owner, _requirement in constraints))
            return None, ModelError(
                "version-conflict", f"package:{name}", owners or "no candidate"
            )
        last_error: ModelError | None = None
        for candidate in candidates:
            choice = dict(selected)
            choice[name] = candidate
            solved, error = search(choice)
            if solved is not None:
                return solved, None
            last_error = error
        return None, last_error

    selected, resolution_error = search({})
    if selected is None:
        raise resolution_error or ModelError(
            "version-conflict", "catalog", "no complete resolution"
        )

    locked: list[LockedPackage] = []
    for name in sorted(selected):
        manifest = selected[name]
        artifact = manifest.target(target)
        locked.append(
            LockedPackage(
                manifest.name,
                manifest.version,
                manifest.digest(),
                artifact.artifact_sha256,
                artifact.artifact_bytes,
                artifact.sdk_sha256,
                artifact.toolchain_sha256,
                tuple(
                    (dependency.name, selected[dependency.name].version)
                    for dependency in manifest.dependencies
                ),
            )
        )
    return TargetLock(root, target, tuple(locked))


def _validate_acyclic(root: str, selected: Mapping[str, Manifest]) -> None:
    """Reject a complete dependency assignment containing any reachable cycle."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise ModelError("dependency-cycle", f"package:{name}", "cycle detected")
        if name in visited:
            return
        visiting.add(name)
        for dependency in selected[name].dependencies:
            visit(dependency.name)
        visiting.remove(name)
        visited.add(name)

    visit(root)


def parse_lock(data: bytes, label: str = "lock") -> TargetLock:
    """Parse one canonical PLOCK v1 document and revalidate its graph."""
    document = _object(
        decode_json(data, label), {"packages", "root", "schema", "target"}, label
    )
    if document["schema"] != 1:
        raise ModelError("unsupported-schema", f"{label}.schema", "expected 1")
    root = _name(document["root"], f"{label}.root")
    target = document["target"]
    if not isinstance(target, str) or target not in SUPPORTED_TARGETS:
        raise ModelError("unsupported-target", f"{label}.target", str(target))
    raw_packages = _array(document["packages"], f"{label}.packages", MAX_PACKAGES)
    if not raw_packages:
        raise ModelError("invalid-array", f"{label}.packages", "lock is empty")
    packages: list[LockedPackage] = []
    fields = {
        "artifact_bytes",
        "artifact_sha256",
        "dependencies",
        "manifest_sha256",
        "name",
        "sdk_sha256",
        "toolchain_sha256",
        "version",
    }
    for index, raw in enumerate(raw_packages):
        path = f"{label}.packages[{index}]"
        entry = _object(raw, fields, path)
        dependencies: list[tuple[str, Version]] = []
        for dependency_index, raw_dependency in enumerate(
            _array(entry["dependencies"], f"{path}.dependencies", MAX_DEPENDENCIES)
        ):
            dependency_path = f"{path}.dependencies[{dependency_index}]"
            dependency = _object(raw_dependency, {"name", "version"}, dependency_path)
            dependencies.append(
                (
                    _name(dependency["name"], f"{dependency_path}.name"),
                    Version.parse(dependency["version"], f"{dependency_path}.version"),
                )
            )
        _strictly_sorted(dependencies, lambda dependency: dependency[0], f"{path}.dependencies")
        packages.append(
            LockedPackage(
                _name(entry["name"], f"{path}.name"),
                Version.parse(entry["version"], f"{path}.version"),
                _digest(entry["manifest_sha256"], f"{path}.manifest_sha256"),
                _digest(entry["artifact_sha256"], f"{path}.artifact_sha256"),
                _bounded_int(entry["artifact_bytes"], f"{path}.artifact_bytes", 1, 4 * 1024 * 1024),
                _digest(entry["sdk_sha256"], f"{path}.sdk_sha256"),
                _digest(entry["toolchain_sha256"], f"{path}.toolchain_sha256"),
                tuple(dependencies),
            )
        )
    _strictly_sorted(packages, lambda package: package.name, f"{label}.packages")
    by_name = {package.name: package for package in packages}
    if root not in by_name:
        raise ModelError("missing-root", f"{label}.root", root)
    for package in packages:
        for dependency, version in package.dependencies:
            if dependency not in by_name or by_name[dependency].version != version:
                raise ModelError("lock-mismatch", f"package:{package.name}", dependency)
    reachable: set[str] = set()
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise ModelError("dependency-cycle", f"package:{name}", "cycle detected")
        if name in reachable:
            return
        visiting.add(name)
        for dependency, _version in by_name[name].dependencies:
            visit(dependency)
        visiting.remove(name)
        reachable.add(name)

    visit(root)
    if reachable != set(by_name):
        raise ModelError(
            "unreachable-package", f"{label}.packages", ",".join(sorted(set(by_name) - reachable))
        )
    lock = TargetLock(root, target, tuple(packages))
    if canonical_json(document) != data:
        raise ModelError("noncanonical-json", label, "lock bytes are not canonical")
    return lock


def build_package(manifest: Manifest, lock: TargetLock, artifact: bytes) -> bytes:
    """Construct one canonical TPKG v1 artifact for the locked root and target."""
    if manifest.name != lock.root:
        raise ModelError("root-mismatch", "package", f"{manifest.name} != {lock.root}")
    locked = next((package for package in lock.packages if package.name == manifest.name), None)
    if locked is None or locked.manifest_sha256 != manifest.digest():
        raise ModelError("manifest-mismatch", "package", manifest.name)
    _validate_locked_manifest(lock, manifest, locked)
    target = manifest.target(lock.target)
    if len(artifact) != target.artifact_bytes or sha256(artifact) != target.artifact_sha256:
        raise ModelError("artifact-mismatch", "package.artifact", manifest.name)
    document = {
        "artifact": base64.b64encode(artifact).decode("ascii"),
        "lock": lock.json(),
        "manifest": manifest.json(),
        "schema": 1,
        "target": lock.target,
    }
    encoded = canonical_json(document)
    if len(encoded) > MAX_PACKAGE_BYTES:
        raise ModelError("package-size", "package", f"more than {MAX_PACKAGE_BYTES} bytes")
    return encoded


def parse_package(data: bytes, label: str = "package") -> tuple[Manifest, TargetLock, bytes]:
    """Independently parse and cross-check one canonical TPKG v1 artifact."""
    document = _object(
        decode_json(data, label, MAX_PACKAGE_BYTES),
        {"artifact", "lock", "manifest", "schema", "target"},
        label,
    )
    if document["schema"] != 1:
        raise ModelError("unsupported-schema", f"{label}.schema", "expected 1")
    if canonical_json(document) != data:
        raise ModelError("noncanonical-json", label, "package bytes are not canonical")
    manifest = parse_manifest(canonical_json(document["manifest"]), f"{label}.manifest")
    lock = parse_lock(canonical_json(document["lock"]), f"{label}.lock")
    if document["target"] != lock.target:
        raise ModelError("target-mismatch", f"{label}.target", str(document["target"]))
    artifact_value = document["artifact"]
    if not isinstance(artifact_value, str):
        raise ModelError("invalid-artifact", f"{label}.artifact", "expected base64 string")
    try:
        artifact = base64.b64decode(artifact_value, validate=True)
    except ValueError as error:
        raise ModelError("invalid-artifact", f"{label}.artifact", "invalid base64") from error
    if base64.b64encode(artifact).decode("ascii") != artifact_value:
        raise ModelError("noncanonical-artifact", f"{label}.artifact", "base64 is not canonical")
    if build_package(manifest, lock, artifact) != data:
        raise ModelError("package-mismatch", label, "cross-check failed")
    return manifest, lock, artifact


def plan(lock: TargetLock, manifests: Mapping[tuple[str, Version], Manifest]) -> dict[str, object]:
    """Derive a stable, non-mutating activation plan from one complete lock."""
    packages: list[dict[str, object]] = []
    totals = {"artifact_bytes": 0, "handles": 0, "heap_bytes": 0, "stack_bytes": 0}
    for locked in lock.packages:
        manifest = manifests.get((locked.name, locked.version))
        if manifest is None or manifest.digest() != locked.manifest_sha256:
            raise ModelError("manifest-mismatch", f"plan:{locked.name}", locked.version.text())
        _validate_locked_manifest(lock, manifest, locked)
        artifact = manifest.target(lock.target)
        if artifact.artifact_sha256 != locked.artifact_sha256:
            raise ModelError("artifact-mismatch", f"plan:{locked.name}", lock.target)
        totals["artifact_bytes"] += locked.artifact_bytes
        totals["handles"] += manifest.resources.handles
        totals["heap_bytes"] += manifest.resources.heap_bytes
        totals["stack_bytes"] += manifest.resources.stack_bytes
        packages.append(
            {
                "capabilities": list(manifest.capabilities),
                "directories": [directory.json() for directory in manifest.directories],
                "name": locked.name,
                "services": [service.json() for service in manifest.services],
                "version": locked.version.json(),
            }
        )
    if totals["artifact_bytes"] > 64 * 1024 * 1024:
        raise ModelError("plan-capacity", "plan.artifact_bytes", str(totals["artifact_bytes"]))
    if totals["handles"] > 256:
        raise ModelError("plan-capacity", "plan.handles", str(totals["handles"]))
    if totals["heap_bytes"] > 512 * 1024 * 1024:
        raise ModelError("plan-capacity", "plan.heap_bytes", str(totals["heap_bytes"]))
    if totals["stack_bytes"] > 16 * 1024 * 1024:
        raise ModelError("plan-capacity", "plan.stack_bytes", str(totals["stack_bytes"]))
    return {
        "lock_sha256": lock.digest(),
        "packages": packages,
        "root": lock.root,
        "schema": 1,
        "target": lock.target,
        "totals": totals,
    }


def _validate_locked_manifest(
    lock: TargetLock, manifest: Manifest, locked: LockedPackage
) -> None:
    """Require one lock record to reproduce its manifest's dependency contract."""
    locked_dependencies = {name: version for name, version in locked.dependencies}
    if tuple(locked_dependencies) != tuple(dependency.name for dependency in manifest.dependencies):
        raise ModelError("lock-mismatch", f"package:{manifest.name}", "dependency names differ")
    for dependency in manifest.dependencies:
        version = locked_dependencies[dependency.name]
        selected = next(
            (package for package in lock.packages if package.name == dependency.name), None
        )
        if (
            selected is None
            or selected.version != version
            or not dependency.requirement.contains(version)
        ):
            raise ModelError("lock-mismatch", f"package:{manifest.name}", dependency.name)
