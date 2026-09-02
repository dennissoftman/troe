#!/usr/bin/env python3
"""Ed25519 trust roots, release metadata, freshness, and atomic publication."""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .package_model import (
        MAX_PACKAGE_BYTES,
        ModelError,
        Version,
        canonical_json,
        decode_json,
        parse_package,
        sha256,
    )
else:
    from package_model import (
        MAX_PACKAGE_BYTES,
        ModelError,
        Version,
        canonical_json,
        decode_json,
        parse_package,
        sha256,
    )


MAX_ENVELOPE_BYTES = 512 * 1024
MAX_KEYS = 32
MAX_SIGNATURES = 16
MAX_PUBLISHERS = 64
MAX_REVOCATIONS = 32
MAX_RECOVERY_PACKAGES = 4
MAX_RELEASES = 256
MAX_OFFLINE_STALENESS_SECONDS = 7 * 24 * 60 * 60
SIGNATURE_DOMAIN = b"TROE-SIGNED-METADATA-V1\0"
_IDENTIFIER = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
_PACKAGE_NAME = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Envelope:
    """Canonical signed payload and its ordered detached signatures."""

    payload: bytes
    signatures: tuple[tuple[str, bytes], ...]

    def json(self) -> dict[str, object]:
        """Return canonical envelope data."""
        return {
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "schema": 1,
            "signatures": [
                {
                    "key_id": key_id,
                    "signature": base64.b64encode(signature).decode("ascii"),
                }
                for key_id, signature in self.signatures
            ],
        }

    def bytes(self) -> bytes:
        """Return exact canonical envelope bytes."""
        return canonical_json(self.json())

    def digest(self) -> str:
        """Return the independently verifiable envelope identity."""
        return sha256(self.bytes())


@dataclass(frozen=True)
class VerifiedRelease:
    """Successful release authorization and its activation eligibility."""

    payload: Mapping[str, object]
    status: str


def _object(value: object, fields: set[str], path: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ModelError("invalid-fields", path, f"expected exactly {sorted(fields)}")
    return value


def _array(value: object, maximum: int, path: str) -> list[object]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ModelError("invalid-array", path, f"expected at most {maximum} entries")
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


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ModelError("invalid-digest", path, "expected lowercase SHA-256")
    return value


def _identifier(
    value: object, path: str, pattern: re.Pattern[str] = _IDENTIFIER
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ModelError("invalid-name", path, "identifier is not canonical")
    return value


def _sorted_unique(values: Sequence[object], key: object, path: str) -> None:
    extractor = key
    keys = [extractor(value) for value in values]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ModelError(
            "noncanonical-order", path, "entries must be unique and sorted"
        )


def require_openssl() -> str:
    """Require the reviewed OpenSSL 3 Ed25519 command boundary."""
    executable = shutil.which("openssl")
    if executable is None:
        raise ModelError("openssl-unavailable", "openssl", "executable is not on PATH")
    try:
        output = subprocess.run(
            (executable, "version"),
            check=True,
            text=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ModelError("openssl-unavailable", "openssl", str(error)) from error
    if re.match(r"OpenSSL ([3-9]|[1-9][0-9]+)\.", output) is None:
        raise ModelError("openssl-version", "openssl", output.strip())
    return executable


def _run_openssl(arguments: Sequence[str], *, data: bytes | None = None) -> bytes:
    executable = require_openssl()
    try:
        return subprocess.run(
            (executable, *arguments),
            input=data,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        detail = (
            error.stderr.decode("utf-8", errors="replace").strip()
            if isinstance(error, subprocess.CalledProcessError)
            else str(error)
        )
        raise ModelError("openssl-failed", "openssl", detail) from error


def public_key_der_from_private(path: Path) -> bytes:
    """Derive canonical SPKI DER from one Ed25519 private PEM key."""
    if path.is_symlink() or not path.is_file():
        raise ModelError("invalid-key", str(path), "private key must be a regular file")
    return _run_openssl(("pkey", "-in", str(path), "-pubout", "-outform", "DER"))


def public_key_der(path: Path) -> bytes:
    """Normalize one Ed25519 public PEM key to SPKI DER."""
    if path.is_symlink() or not path.is_file():
        raise ModelError("invalid-key", str(path), "public key must be a regular file")
    return _run_openssl(
        ("pkey", "-pubin", "-in", str(path), "-pubout", "-outform", "DER")
    )


def key_id(public_der: bytes) -> str:
    """Return the public-key identity used by every signed role."""
    if not public_der or len(public_der) > 1024:
        raise ModelError("invalid-key", "public-key", "SPKI DER length is invalid")
    return sha256(public_der)


def key_record(public_der: bytes) -> dict[str, str]:
    """Construct one canonical root key record."""
    return {
        "key_id": key_id(public_der),
        "public_key": base64.b64encode(public_der).decode("ascii"),
    }


def sign(private_key: Path, payload: bytes) -> tuple[str, bytes]:
    """Sign one exact canonical payload with Ed25519."""
    public_der = public_key_der_from_private(private_key)
    with tempfile.TemporaryDirectory(prefix="troe-sign-") as directory:
        source = Path(directory) / "payload"
        signature = Path(directory) / "signature"
        source.write_bytes(SIGNATURE_DOMAIN + payload)
        _run_openssl(
            (
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(source),
                "-out",
                str(signature),
            )
        )
        value = signature.read_bytes()
    if len(value) != 64:
        raise ModelError(
            "invalid-signature", str(private_key), "Ed25519 signature is not 64 bytes"
        )
    return key_id(public_der), value


def sign_payload(payload: object, private_keys: Iterable[Path]) -> Envelope:
    """Canonicalize and sign metadata, sorting signatures by key identity."""
    encoded = canonical_json(payload)
    signatures = sorted(sign(path, encoded) for path in private_keys)
    if not signatures or len(signatures) > MAX_SIGNATURES:
        raise ModelError("signature-count", "signatures", "expected 1..16 signatures")
    if len({identity for identity, _signature in signatures}) != len(signatures):
        raise ModelError("duplicate-signature", "signatures", "same key signed twice")
    return Envelope(encoded, tuple(signatures))


def parse_envelope(data: bytes, label: str = "envelope") -> Envelope:
    """Parse one canonical envelope without interpreting its signed payload."""
    document = _object(
        decode_json(data, label, MAX_ENVELOPE_BYTES),
        {"payload", "schema", "signatures"},
        label,
    )
    if document["schema"] != 1:
        raise ModelError("unsupported-schema", f"{label}.schema", "expected 1")
    payload_value = document["payload"]
    if not isinstance(payload_value, str):
        raise ModelError(
            "invalid-payload", f"{label}.payload", "expected base64 string"
        )
    try:
        payload = base64.b64decode(payload_value, validate=True)
    except ValueError as error:
        raise ModelError(
            "invalid-payload", f"{label}.payload", "invalid base64"
        ) from error
    if base64.b64encode(payload).decode("ascii") != payload_value:
        raise ModelError("noncanonical-payload", f"{label}.payload", "base64 differs")
    raw_signatures = _array(
        document["signatures"], MAX_SIGNATURES, f"{label}.signatures"
    )
    if not raw_signatures:
        raise ModelError("signature-count", f"{label}.signatures", "no signatures")
    signatures: list[tuple[str, bytes]] = []
    for index, raw in enumerate(raw_signatures):
        path = f"{label}.signatures[{index}]"
        entry = _object(raw, {"key_id", "signature"}, path)
        identity = _digest(entry["key_id"], f"{path}.key_id")
        value = entry["signature"]
        if not isinstance(value, str):
            raise ModelError(
                "invalid-signature", f"{path}.signature", "expected base64"
            )
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as error:
            raise ModelError(
                "invalid-signature", f"{path}.signature", "invalid base64"
            ) from error
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
            raise ModelError(
                "invalid-signature", f"{path}.signature", "not canonical Ed25519"
            )
        signatures.append((identity, decoded))
    _sorted_unique(signatures, lambda signature: signature[0], f"{label}.signatures")
    envelope = Envelope(payload, tuple(signatures))
    if envelope.bytes() != data:
        raise ModelError("noncanonical-json", label, "envelope bytes differ")
    return envelope


def _verify_signature(public_der: bytes, payload: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory(prefix="troe-verify-") as directory:
        root = Path(directory)
        key = root / "key.der"
        source = root / "payload"
        signature_path = root / "signature"
        key.write_bytes(public_der)
        source.write_bytes(SIGNATURE_DOMAIN + payload)
        signature_path.write_bytes(signature)
        executable = require_openssl()
        result = subprocess.run(
            (
                executable,
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                str(source),
                "-sigfile",
                str(signature_path),
            ),
            check=False,
            capture_output=True,
        )
    return result.returncode == 0


def _decode_public_key(value: object, path: str) -> bytes:
    if not isinstance(value, str):
        raise ModelError("invalid-key", path, "expected base64 SPKI DER")
    try:
        public_der = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ModelError("invalid-key", path, "invalid base64") from error
    if base64.b64encode(public_der).decode("ascii") != value or not public_der:
        raise ModelError("invalid-key", path, "noncanonical SPKI DER")
    return public_der


def _role(value: object, keys: Mapping[str, bytes], path: str) -> dict[str, object]:
    role = _object(value, {"key_ids", "threshold"}, path)
    key_ids = _array(role["key_ids"], MAX_KEYS, f"{path}.key_ids")
    if not key_ids:
        raise ModelError("invalid-role", path, "role has no keys")
    identities = tuple(_digest(value, f"{path}.key_ids") for value in key_ids)
    _sorted_unique(identities, lambda identity: identity, f"{path}.key_ids")
    if any(identity not in keys for identity in identities):
        raise ModelError("unknown-key", path, "role references an absent key")
    threshold = _integer(role["threshold"], 1, len(identities), f"{path}.threshold")
    return {"key_ids": list(identities), "threshold": threshold}


def validate_root_payload(payload: bytes, label: str = "root") -> dict[str, object]:
    """Validate canonical TROOT v1 metadata and its complete role graph."""
    document = _object(
        decode_json(payload, label, MAX_ENVELOPE_BYTES),
        {
            "expires",
            "generation",
            "issued_at",
            "keys",
            "previous_root_sha256",
            "publishers",
            "recovery_packages",
            "revocations",
            "roles",
            "schema",
            "type",
        },
        label,
    )
    if document["schema"] != 1 or document["type"] != "root":
        raise ModelError("unsupported-schema", label, "expected TROOT v1")
    generation = _integer(document["generation"], 1, 2**63 - 1, f"{label}.generation")
    issued_at = _integer(document["issued_at"], 0, 2**63 - 1, f"{label}.issued_at")
    expires = _integer(document["expires"], 1, 2**63 - 1, f"{label}.expires")
    if issued_at >= expires:
        raise ModelError("invalid-freshness", label, "root expires before issuance")
    previous = document["previous_root_sha256"]
    if generation == 1:
        if previous is not None:
            raise ModelError(
                "invalid-rotation", f"{label}.previous_root_sha256", "initial root"
            )
    elif _digest(previous, f"{label}.previous_root_sha256") == "":
        raise AssertionError("unreachable")

    raw_keys = _array(document["keys"], MAX_KEYS, f"{label}.keys")
    if not raw_keys:
        raise ModelError("invalid-key", f"{label}.keys", "root has no keys")
    keys: dict[str, bytes] = {}
    for index, raw in enumerate(raw_keys):
        path = f"{label}.keys[{index}]"
        entry = _object(raw, {"key_id", "public_key"}, path)
        public_der = _decode_public_key(entry["public_key"], f"{path}.public_key")
        identity = _digest(entry["key_id"], f"{path}.key_id")
        if identity != key_id(public_der):
            raise ModelError("key-id-mismatch", path, identity)
        keys[identity] = public_der
    if len(keys) != len(raw_keys) or list(keys) != sorted(keys):
        raise ModelError(
            "noncanonical-order", f"{label}.keys", "keys must be unique and sorted"
        )

    roles = _object(
        document["roles"], {"provenance", "root", "snapshot"}, f"{label}.roles"
    )
    validated_roles = {
        "provenance": _role(roles["provenance"], keys, f"{label}.roles.provenance"),
        "root": _role(roles["root"], keys, f"{label}.roles.root"),
        "snapshot": _role(roles["snapshot"], keys, f"{label}.roles.snapshot"),
    }
    raw_publishers = _array(
        document["publishers"], MAX_PUBLISHERS, f"{label}.publishers"
    )
    publishers: list[dict[str, object]] = []
    for index, raw in enumerate(raw_publishers):
        path = f"{label}.publishers[{index}]"
        entry = _object(raw, {"key_ids", "package", "threshold"}, path)
        package = _identifier(entry["package"], f"{path}.package", _PACKAGE_NAME)
        validated = _role(
            {"key_ids": entry["key_ids"], "threshold": entry["threshold"]}, keys, path
        )
        publishers.append({"package": package, **validated})
    _sorted_unique(
        publishers, lambda publisher: publisher["package"], f"{label}.publishers"
    )

    raw_revocations = _array(
        document["revocations"], MAX_REVOCATIONS, f"{label}.revocations"
    )
    revocations: list[dict[str, object]] = []
    for index, raw in enumerate(raw_revocations):
        path = f"{label}.revocations[{index}]"
        entry = _object(raw, {"key_id", "reason", "revoked_at"}, path)
        identity = _digest(entry["key_id"], f"{path}.key_id")
        if identity not in keys:
            raise ModelError("unknown-key", path, identity)
        reason = entry["reason"]
        if not isinstance(reason, str) or not 1 <= len(reason.encode("utf-8")) <= 256:
            raise ModelError("invalid-revocation", f"{path}.reason", "invalid reason")
        revocations.append(
            {
                "key_id": identity,
                "reason": reason,
                "revoked_at": _integer(
                    entry["revoked_at"], 0, 2**63 - 1, f"{path}.revoked_at"
                ),
            }
        )
    _sorted_unique(
        revocations, lambda revocation: revocation["key_id"], f"{label}.revocations"
    )
    recovery = tuple(
        _digest(value, f"{label}.recovery_packages")
        for value in _array(
            document["recovery_packages"],
            MAX_RECOVERY_PACKAGES,
            f"{label}.recovery_packages",
        )
    )
    _sorted_unique(recovery, lambda digest: digest, f"{label}.recovery_packages")
    if canonical_json(document) != payload:
        raise ModelError("noncanonical-json", label, "root payload bytes differ")
    return {
        **document,
        "keys": keys,
        "publishers": publishers,
        "recovery_packages": recovery,
        "revocations": revocations,
        "roles": validated_roles,
    }


def _valid_signature_keys(
    envelope: Envelope, root: Mapping[str, object], role: Mapping[str, object], at: int
) -> set[str]:
    allowed = set(role["key_ids"])
    revoked = {
        revocation["key_id"]
        for revocation in root["revocations"]
        if revocation["revoked_at"] <= at
    }
    keys = root["keys"]
    return {
        identity
        for identity, signature in envelope.signatures
        if identity in allowed
        and identity not in revoked
        and _verify_signature(keys[identity], envelope.payload, signature)
    }


def _valid_signature_keys_without_revocation(
    envelope: Envelope, root: Mapping[str, object], role: Mapping[str, object]
) -> set[str]:
    """Verify historical recovery signatures without granting active authority."""
    allowed = set(role["key_ids"])
    keys = root["keys"]
    return {
        identity
        for identity, signature in envelope.signatures
        if identity in allowed
        and _verify_signature(keys[identity], envelope.payload, signature)
    }


def _require_role(
    envelope: Envelope,
    root: Mapping[str, object],
    role: Mapping[str, object],
    at: int,
    label: str,
) -> None:
    valid = _valid_signature_keys(envelope, root, role, at)
    if len(valid) < role["threshold"]:
        raise ModelError("signature-threshold", label, f"{len(valid)} valid signatures")


def verify_initial_root(
    envelope_bytes: bytes, trusted_payload_sha256: str, now: int
) -> tuple[Envelope, dict[str, object]]:
    """Bootstrap one self-signed root through an out-of-band payload digest."""
    envelope = parse_envelope(envelope_bytes, "root-envelope")
    if sha256(envelope.payload) != _digest(trusted_payload_sha256, "trusted-root"):
        raise ModelError(
            "root-anchor-mismatch", "trusted-root", sha256(envelope.payload)
        )
    root = validate_root_payload(envelope.payload)
    if now < root["issued_at"] or now > root["expires"]:
        raise ModelError("root-expired", "root", str(now))
    _require_role(envelope, root, root["roles"]["root"], root["issued_at"], "root")
    return envelope, root


def verify_root_rotation(
    trusted_root: Mapping[str, object], new_envelope_bytes: bytes, now: int
) -> tuple[Envelope, dict[str, object]]:
    """Require consecutive old-root authorization and new-root self-authorization."""
    envelope = parse_envelope(new_envelope_bytes, "root-envelope")
    new_root = validate_root_payload(envelope.payload)
    if (
        new_root["generation"] != trusted_root["generation"] + 1
        or new_root["previous_root_sha256"]
        != sha256(canonical_json(_root_json(trusted_root)))
        or new_root["issued_at"] < trusted_root["issued_at"]
        or now < new_root["issued_at"]
        or now > new_root["expires"]
    ):
        raise ModelError("invalid-rotation", "root", "generation, predecessor, or time")
    _require_role(
        envelope,
        trusted_root,
        trusted_root["roles"]["root"],
        new_root["issued_at"],
        "old-root",
    )
    _require_role(
        envelope, new_root, new_root["roles"]["root"], new_root["issued_at"], "new-root"
    )
    return envelope, new_root


def _root_json(root: Mapping[str, object]) -> dict[str, object]:
    """Remove parsed helper fields and reproduce the signed root document."""
    return {
        key: value
        for key, value in root.items()
        if key
        in {
            "expires",
            "generation",
            "issued_at",
            "previous_root_sha256",
            "recovery_packages",
            "schema",
            "type",
        }
    } | {
        "keys": [
            key_record(public_der)
            for _identity, public_der in sorted(root["keys"].items())
        ],
        "publishers": [dict(publisher) for publisher in root["publishers"]],
        "revocations": [dict(revocation) for revocation in root["revocations"]],
        "roles": {name: dict(role) for name, role in root["roles"].items()},
    }


def validate_release_payload(
    payload: bytes, label: str = "release"
) -> dict[str, object]:
    """Validate canonical TREL v1 metadata and provenance."""
    document = _object(
        decode_json(payload, label, MAX_ENVELOPE_BYTES),
        {
            "expires",
            "lock_sha256",
            "manifest_sha256",
            "name",
            "package_bytes",
            "package_sha256",
            "provenance",
            "published_at",
            "schema",
            "sequence",
            "target",
            "type",
            "version",
        },
        label,
    )
    if document["schema"] != 1 or document["type"] != "release":
        raise ModelError("unsupported-schema", label, "expected TREL v1")
    name = _identifier(document["name"], f"{label}.name", _PACKAGE_NAME)
    version = Version.parse(document["version"], f"{label}.version")
    target = document["target"]
    if target not in {"aarch64-unknown-uefi", "x86_64-unknown-uefi"}:
        raise ModelError("unsupported-target", f"{label}.target", str(target))
    package_digest = _digest(document["package_sha256"], f"{label}.package_sha256")
    _integer(document["package_bytes"], 1, MAX_PACKAGE_BYTES, f"{label}.package_bytes")
    _digest(document["manifest_sha256"], f"{label}.manifest_sha256")
    _digest(document["lock_sha256"], f"{label}.lock_sha256")
    published = _integer(
        document["published_at"], 0, 2**63 - 1, f"{label}.published_at"
    )
    expires = _integer(document["expires"], 1, 2**63 - 1, f"{label}.expires")
    if published >= expires:
        raise ModelError(
            "invalid-freshness", label, "release expires before publication"
        )
    _integer(document["sequence"], 1, 2**63 - 1, f"{label}.sequence")
    provenance = _object(
        document["provenance"],
        {
            "build_recipe_sha256",
            "builder",
            "reproducible_sha256",
            "source_sha256",
        },
        f"{label}.provenance",
    )
    builder = _identifier(provenance["builder"], f"{label}.provenance.builder")
    source = _digest(provenance["source_sha256"], f"{label}.provenance.source_sha256")
    recipe = _digest(
        provenance["build_recipe_sha256"], f"{label}.provenance.build_recipe_sha256"
    )
    reproducible = _digest(
        provenance["reproducible_sha256"], f"{label}.provenance.reproducible_sha256"
    )
    if reproducible != package_digest:
        raise ModelError("provenance-mismatch", f"{label}.provenance", reproducible)
    if canonical_json(document) != payload:
        raise ModelError("noncanonical-json", label, "release payload bytes differ")
    return {
        **document,
        "name": name,
        "provenance": {
            "build_recipe_sha256": recipe,
            "builder": builder,
            "reproducible_sha256": reproducible,
            "source_sha256": source,
        },
        "version": version,
    }


def publisher_role(root: Mapping[str, object], package: str) -> Mapping[str, object]:
    """Resolve exactly one package publication role."""
    matches = [
        publisher for publisher in root["publishers"] if publisher["package"] == package
    ]
    if len(matches) != 1:
        raise ModelError(
            "publisher-unauthorized", f"package:{package}", "no unique role"
        )
    return matches[0]


def verify_release(
    root: Mapping[str, object],
    envelope_bytes: bytes,
    package_bytes: bytes,
    *,
    now: int,
    offline: bool = False,
    offline_grace: int = 0,
    minimum_sequence: int = 0,
) -> VerifiedRelease:
    """Verify bytes, target, publisher, provenance, replay, revocation, and
    freshness."""
    if offline_grace < 0 or offline_grace > MAX_OFFLINE_STALENESS_SECONDS:
        raise ModelError("offline-policy", "offline_grace", str(offline_grace))
    envelope = parse_envelope(envelope_bytes, "release-envelope")
    release = validate_release_payload(envelope.payload)
    if release["sequence"] < minimum_sequence:
        raise ModelError("release-replay", "release.sequence", str(release["sequence"]))
    manifest, lock, _artifact = parse_package(package_bytes, "release.package")
    if (
        len(package_bytes) != release["package_bytes"]
        or sha256(package_bytes) != release["package_sha256"]
        or manifest.name != release["name"]
        or manifest.version != release["version"]
        or manifest.digest() != release["manifest_sha256"]
        or lock.digest() != release["lock_sha256"]
        or lock.target != release["target"]
    ):
        raise ModelError(
            "release-mismatch", "release", "package identity or target differs"
        )
    role = publisher_role(root, release["name"])

    def recovery_signatures_are_valid() -> bool:
        publisher_signatures = _valid_signature_keys_without_revocation(
            envelope, root, role
        )
        provenance_role = root["roles"]["provenance"]
        provenance_signatures = _valid_signature_keys_without_revocation(
            envelope, root, provenance_role
        )
        return (
            len(publisher_signatures) >= role["threshold"]
            and len(provenance_signatures) >= provenance_role["threshold"]
        )

    try:
        _require_role(envelope, root, role, now, f"publisher:{release['name']}")
        _require_role(
            envelope,
            root,
            root["roles"]["provenance"],
            now,
            f"provenance:{release['name']}",
        )
    except ModelError:
        if (
            release["package_sha256"] in root["recovery_packages"]
            and recovery_signatures_are_valid()
        ):
            return VerifiedRelease(release, "recovery-only")
        raise
    freshness_limit = release["expires"] + (offline_grace if offline else 0)
    if now < release["published_at"] or now > freshness_limit:
        if release["package_sha256"] in root["recovery_packages"]:
            return VerifiedRelease(release, "recovery-only")
        raise ModelError("release-expired", "release", str(now))
    return VerifiedRelease(release, "active")


def snapshot_payload(
    generation: int,
    published_at: int,
    expires: int,
    releases: Iterable[tuple[Mapping[str, object], str]],
) -> dict[str, object]:
    """Construct canonical TSNP v1 data from verified release payloads."""
    entries = sorted(
        (
            {
                "name": release["name"],
                "package_sha256": release["package_sha256"],
                "release_sha256": release_digest,
                "target": release["target"],
                "version": release["version"].json()
                if isinstance(release["version"], Version)
                else release["version"],
            }
            for release, release_digest in releases
        ),
        key=lambda entry: (entry["name"], entry["version"], entry["target"]),
    )
    if len(entries) > MAX_RELEASES:
        raise ModelError("snapshot-capacity", "snapshot.releases", str(len(entries)))
    return {
        "expires": expires,
        "generation": generation,
        "published_at": published_at,
        "releases": entries,
        "schema": 1,
        "type": "snapshot",
    }


def validate_snapshot_payload(
    payload: bytes, label: str = "snapshot"
) -> dict[str, object]:
    """Validate canonical TSNP v1 metadata."""
    document = _object(
        decode_json(payload, label, MAX_ENVELOPE_BYTES),
        {"expires", "generation", "published_at", "releases", "schema", "type"},
        label,
    )
    if document["schema"] != 1 or document["type"] != "snapshot":
        raise ModelError("unsupported-schema", label, "expected TSNP v1")
    _integer(document["generation"], 1, 2**63 - 1, f"{label}.generation")
    published = _integer(
        document["published_at"], 0, 2**63 - 1, f"{label}.published_at"
    )
    expires = _integer(document["expires"], 1, 2**63 - 1, f"{label}.expires")
    if published >= expires:
        raise ModelError(
            "invalid-freshness", label, "snapshot expires before publication"
        )
    raw_releases = _array(document["releases"], MAX_RELEASES, f"{label}.releases")
    releases: list[dict[str, object]] = []
    for index, raw in enumerate(raw_releases):
        path = f"{label}.releases[{index}]"
        entry = _object(
            raw,
            {"name", "package_sha256", "release_sha256", "target", "version"},
            path,
        )
        target = entry["target"]
        if target not in {"aarch64-unknown-uefi", "x86_64-unknown-uefi"}:
            raise ModelError("unsupported-target", f"{path}.target", str(target))
        releases.append(
            {
                "name": _identifier(entry["name"], f"{path}.name", _PACKAGE_NAME),
                "package_sha256": _digest(
                    entry["package_sha256"], f"{path}.package_sha256"
                ),
                "release_sha256": _digest(
                    entry["release_sha256"], f"{path}.release_sha256"
                ),
                "target": target,
                "version": Version.parse(entry["version"], f"{path}.version"),
            }
        )
    keys = [(entry["name"], entry["version"], entry["target"]) for entry in releases]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ModelError(
            "noncanonical-order", f"{label}.releases", "duplicate or unsorted"
        )
    if canonical_json(document) != payload:
        raise ModelError("noncanonical-json", label, "snapshot payload bytes differ")
    return {**document, "releases": releases}


def verify_snapshot(
    root: Mapping[str, object],
    envelope_bytes: bytes,
    *,
    now: int,
    minimum_generation: int = 0,
    offline: bool = False,
    offline_grace: int = 0,
) -> tuple[Envelope, dict[str, object]]:
    """Verify snapshot authorization, monotonicity, and bounded offline freshness."""
    if offline_grace < 0 or offline_grace > MAX_OFFLINE_STALENESS_SECONDS:
        raise ModelError("offline-policy", "offline_grace", str(offline_grace))
    envelope = parse_envelope(envelope_bytes, "snapshot-envelope")
    snapshot = validate_snapshot_payload(envelope.payload)
    if snapshot["generation"] < minimum_generation:
        raise ModelError(
            "snapshot-replay", "snapshot.generation", str(snapshot["generation"])
        )
    if now < snapshot["published_at"] or now > snapshot["expires"] + (
        offline_grace if offline else 0
    ):
        raise ModelError("snapshot-expired", "snapshot", str(now))
    _require_role(envelope, root, root["roles"]["snapshot"], now, "snapshot")
    return envelope, snapshot


def _durable_write(path: Path, payload: bytes) -> None:
    """Create and flush one publication file without replacement."""
    try:
        with path.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def _fsync_directory(path: Path) -> None:
    """Durably order directory entries on hosts that implement directory fsync."""
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ModelError("write-failed", str(path), str(error)) from error


def publish_release(
    registry: Path,
    root: Mapping[str, object],
    release_envelope_bytes: bytes,
    package_bytes: bytes,
    snapshot_private_keys: Iterable[Path],
    *,
    now: int,
    snapshot_expires: int,
) -> int:
    """Stage a complete immutable registry generation, then atomically publish
    its pointer."""
    verified = verify_release(root, release_envelope_bytes, package_bytes, now=now)
    if verified.status != "active":
        raise ModelError("recovery-only", "release", "cannot publish as active")
    release_envelope = parse_envelope(release_envelope_bytes)
    current_path = registry / "current"
    previous_entries: list[tuple[dict[str, object], str, bytes, bytes]] = []
    generation = 1
    if current_path.exists():
        if current_path.is_symlink() or not current_path.is_file():
            raise ModelError("registry-corrupt", str(current_path), "invalid pointer")
        try:
            current = int(current_path.read_text(encoding="ascii"))
        except (OSError, UnicodeError, ValueError) as error:
            raise ModelError(
                "registry-corrupt", str(current_path), str(error)
            ) from error
        generation = current + 1
        previous_dir = registry / "generations" / f"{current:020d}"
        snapshot_bytes = (previous_dir / "snapshot.json").read_bytes()
        _snapshot_envelope, snapshot = verify_snapshot(
            root, snapshot_bytes, now=now, minimum_generation=current
        )
        for entry in snapshot["releases"]:
            release_bytes = (
                previous_dir / "releases" / f"{entry['release_sha256']}.json"
            ).read_bytes()
            package = (
                previous_dir / "packages" / f"{entry['package_sha256']}.tpkg"
            ).read_bytes()
            previous_release = parse_envelope(release_bytes)
            previous_payload = validate_release_payload(previous_release.payload)
            previous_entries.append(
                (previous_payload, entry["release_sha256"], release_bytes, package)
            )

    release_identity = release_envelope.digest()
    replacement_key = (
        verified.payload["name"],
        verified.payload["version"],
        verified.payload["target"],
    )
    retained = [
        entry
        for entry in previous_entries
        if (entry[0]["name"], entry[0]["version"], entry[0]["target"])
        != replacement_key
    ]
    retained.append(
        (
            dict(verified.payload),
            release_identity,
            release_envelope_bytes,
            package_bytes,
        )
    )
    snapshot = snapshot_payload(
        generation,
        now,
        snapshot_expires,
        ((payload, digest) for payload, digest, _envelope, _package in retained),
    )
    snapshot_envelope = sign_payload(snapshot, snapshot_private_keys)
    _require_role(
        snapshot_envelope, root, root["roles"]["snapshot"], now, "snapshot-publication"
    )

    generations = registry / "generations"
    generations.mkdir(parents=True, exist_ok=True)
    destination = generations / f"{generation:020d}"
    while destination.exists() or destination.is_symlink():
        generation += 1
        snapshot["generation"] = generation
        snapshot_envelope = sign_payload(snapshot, snapshot_private_keys)
        destination = generations / f"{generation:020d}"
    staging = Path(tempfile.mkdtemp(prefix=f".{generation:020d}-", dir=generations))
    try:
        (staging / "releases").mkdir()
        (staging / "packages").mkdir()
        for payload, digest, envelope_bytes, package in retained:
            _durable_write(staging / "releases" / f"{digest}.json", envelope_bytes)
            _durable_write(
                staging / "packages" / f"{payload['package_sha256']}.tpkg", package
            )
        _durable_write(staging / "snapshot.json", snapshot_envelope.bytes())
        _fsync_directory(staging / "releases")
        _fsync_directory(staging / "packages")
        _fsync_directory(staging)
        verify_registry_generation(
            root, staging, now=now, minimum_generation=generation
        )
        staging.rename(destination)
        _fsync_directory(generations)
        pointer = registry / f".current.{os.getpid()}.tmp"
        _durable_write(pointer, str(generation).encode("ascii"))
        pointer.replace(current_path)
        _fsync_directory(registry)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return generation


def verify_registry_generation(
    root: Mapping[str, object],
    directory: Path,
    *,
    now: int,
    minimum_generation: int = 0,
    offline: bool = False,
    offline_grace: int = 0,
) -> dict[str, object]:
    """Independently verify the exact files and every release in one generation."""
    if directory.is_symlink() or not directory.is_dir():
        raise ModelError(
            "registry-corrupt", str(directory), "generation is not a directory"
        )
    snapshot_path = directory / "snapshot.json"
    _envelope, snapshot = verify_snapshot(
        root,
        snapshot_path.read_bytes(),
        now=now,
        minimum_generation=minimum_generation,
        offline=offline,
        offline_grace=offline_grace,
    )
    expected_files = {"snapshot.json", "releases", "packages"}
    if {path.name for path in directory.iterdir()} != expected_files:
        raise ModelError(
            "registry-corrupt", str(directory), "unexpected top-level files"
        )
    expected_releases = {
        f"{entry['release_sha256']}.json" for entry in snapshot["releases"]
    }
    expected_packages = {
        f"{entry['package_sha256']}.tpkg" for entry in snapshot["releases"]
    }
    release_dir = directory / "releases"
    package_dir = directory / "packages"
    if {path.name for path in release_dir.iterdir()} != expected_releases or {
        path.name for path in package_dir.iterdir()
    } != expected_packages:
        raise ModelError(
            "registry-corrupt", str(directory), "generation file set differs"
        )
    for entry in snapshot["releases"]:
        release_bytes = (release_dir / f"{entry['release_sha256']}.json").read_bytes()
        package_bytes = (package_dir / f"{entry['package_sha256']}.tpkg").read_bytes()
        if sha256(release_bytes) != entry["release_sha256"]:
            raise ModelError("registry-corrupt", "release", entry["release_sha256"])
        verified = verify_release(
            root,
            release_bytes,
            package_bytes,
            now=now,
            offline=offline,
            offline_grace=offline_grace,
        )
        if verified.payload["package_sha256"] != entry["package_sha256"]:
            raise ModelError("registry-corrupt", "package", entry["package_sha256"])
    return snapshot
