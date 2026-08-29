#!/usr/bin/env python3
"""Build, verify, or install a deterministic TROE shared runtime tree."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

try:
    from tools import mkshared
except ImportError:
    import mkshared  # type: ignore[no-redef]


RUNTIME_SCHEMA = 1
RUNTIME_DIRECTORY = Path("runtime") / f"v{RUNTIME_SCHEMA}"
MANIFEST_NAME = "MANIFEST.sha256"
ARCHITECTURES = ("aarch64", "x86_64")
KEX_PACKAGE_HEADER_BYTES = 48
KCAP_MAX_BYTES = 16 + 128 * 8
KEX_EXECUTABLE_MAX_BYTES = 32 * 1024 * 1024
CMPL_MAX_BYTES = 16 * 1024
MAX_ARTIFACT_BYTES = (
    KEX_PACKAGE_HEADER_BYTES
    + KCAP_MAX_BYTES
    + KEX_EXECUTABLE_MAX_BYTES
    + CMPL_MAX_BYTES
)
MAX_ARTIFACTS = 128


@dataclass(frozen=True, order=True)
class Artifact:
    """One architecture-owned runtime artifact."""

    architecture: str
    name: str
    source: Path

    @property
    def relative_path(self) -> PurePosixPath:
        return PurePosixPath(self.architecture, "bin", f"{self.name}.kex")


def _valid_name(name: str) -> bool:
    return bool(name) and len(name.encode("utf-8")) <= 64 and all(
        character.isascii()
        and (character.isalnum() or character in ("-", "_", "."))
        for character in name
    )


def parse_artifact(specification: str) -> Artifact:
    """Parse ``ARCH:NAME=PATH`` without accepting ambiguous path syntax."""
    identity, separator, raw_path = specification.partition("=")
    architecture, colon, name = identity.partition(":")
    if (
        not separator
        or not colon
        or architecture not in ARCHITECTURES
        or not _valid_name(name)
        or not raw_path
    ):
        raise ValueError(
            "runtime artifact must use ARCH:NAME=PATH with a supported "
            "architecture and a portable name"
        )
    source = Path(raw_path)
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"runtime artifact is not a regular file: {source}")
    byte_count = source.stat().st_size
    if byte_count == 0 or byte_count > MAX_ARTIFACT_BYTES:
        raise ValueError(f"runtime artifact has an invalid size: {source}")
    return Artifact(architecture, name, source.resolve())


def collect_artifacts(specifications: list[str]) -> list[Artifact]:
    """Parse, sort, and reject duplicate runtime paths."""
    if not specifications or len(specifications) > MAX_ARTIFACTS:
        raise ValueError("runtime tree requires 1 through 128 artifacts")
    artifacts = sorted(parse_artifact(value) for value in specifications)
    for previous, current in zip(artifacts, artifacts[1:], strict=False):
        if previous.relative_path == current.relative_path:
            raise ValueError(f"duplicate runtime artifact: {current.relative_path}")
    return artifacts


def _digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
    return byte_count, digest.hexdigest()


def manifest_bytes(entries: list[tuple[PurePosixPath, int, str]]) -> bytes:
    """Encode the canonical line-oriented runtime manifest."""
    lines = [f"TROE-RUNTIME-TREE {RUNTIME_SCHEMA}\n"]
    for path, byte_count, digest in entries:
        lines.append(f"{digest} {byte_count} {path.as_posix()}\n")
    return "".join(lines).encode("ascii")


def build_tree(output: Path, artifacts: list[Artifact]) -> None:
    """Atomically build one version directory from exact artifact inputs."""
    output = output.resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=output.parent, prefix=f".{output.name}."
    ) as temporary:
        staging = Path(temporary) / output.name
        entries: list[tuple[PurePosixPath, int, str]] = []
        for artifact in sorted(artifacts, key=lambda item: item.relative_path.as_posix()):
            destination = staging / Path(*artifact.relative_path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(artifact.source, destination)
            byte_count, digest = _digest(destination)
            entries.append((artifact.relative_path, byte_count, digest))
        (staging / MANIFEST_NAME).write_bytes(manifest_bytes(entries))
        verify_tree(staging)
        if output.exists() or output.is_symlink():
            if output.is_symlink() or not output.is_dir():
                raise ValueError(f"runtime output is not a directory: {output}")
            shutil.rmtree(output)
        os.replace(staging, output)


def _parse_manifest(path: Path) -> list[tuple[PurePosixPath, int, str]]:
    try:
        encoded = path.read_bytes()
        lines = encoded.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("runtime manifest is not ASCII") from error
    if not lines or lines[0] != f"TROE-RUNTIME-TREE {RUNTIME_SCHEMA}":
        raise ValueError("runtime manifest schema is unsupported")
    entries: list[tuple[PurePosixPath, int, str]] = []
    previous = ""
    for line in lines[1:]:
        fields = line.split(" ")
        if len(fields) != 3:
            raise ValueError("runtime manifest record is malformed")
        digest, raw_bytes, raw_path = fields
        relative = PurePosixPath(raw_path)
        if (
            len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not raw_bytes.isdecimal()
            or int(raw_bytes) <= 0
            or int(raw_bytes) > MAX_ARTIFACT_BYTES
            or relative.is_absolute()
            or len(relative.parts) != 3
            or relative.parts[0] not in ARCHITECTURES
            or relative.parts[1] != "bin"
            or not relative.parts[2].endswith(".kex")
            or not _valid_name(relative.parts[2][:-4])
            or any(part in ("", ".", "..") for part in relative.parts)
            or raw_path <= previous
        ):
            raise ValueError("runtime manifest record is noncanonical")
        previous = raw_path
        entries.append((relative, int(raw_bytes), digest))
    if not entries or len(entries) > MAX_ARTIFACTS:
        raise ValueError("runtime manifest artifact count is invalid")
    if encoded != manifest_bytes(entries):
        raise ValueError("runtime manifest encoding is noncanonical")
    return entries


def verify_tree(root: Path) -> None:
    """Verify every manifest record and reject unmanifested tree entries."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"runtime tree is unavailable: {root}")
    entries = _parse_manifest(root / MANIFEST_NAME)
    expected = {MANIFEST_NAME}
    for relative, expected_bytes, expected_digest in entries:
        candidate = root / Path(*relative.parts)
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"runtime artifact is unavailable: {relative}")
        byte_count, digest = _digest(candidate)
        if byte_count != expected_bytes or digest != expected_digest:
            raise ValueError(f"runtime artifact verification failed: {relative}")
        expected.add(relative.as_posix())
        parent = relative.parent
        while parent != PurePosixPath("."):
            expected.add(parent.as_posix())
            parent = parent.parent
    actual = {
        candidate.relative_to(root).as_posix()
        for candidate in root.rglob("*")
    }
    if actual != expected:
        raise ValueError("runtime tree contains unmanifested or missing files")


def install_tree(tree: Path, shared_root: Path) -> Path:
    """Install a verified version directory below one mounted shared root."""
    verify_tree(tree)
    if shared_root.is_symlink() or not shared_root.is_dir():
        raise ValueError(f"shared runtime media is unavailable: {shared_root}")
    runtime_parent = shared_root / RUNTIME_DIRECTORY.parent
    runtime_parent.mkdir(parents=True, exist_ok=True)
    destination = shared_root / RUNTIME_DIRECTORY
    build_tree(
        destination,
        [
            Artifact(
                relative.parts[0],
                relative.parts[2][:-4],
                tree / Path(*relative.parts),
            )
            for relative, _byte_count, _digest_value in _parse_manifest(
                tree / MANIFEST_NAME
            )
        ],
    )
    verify_tree(destination)
    return destination


def _mtools_image(image: Path) -> str:
    return f"{image.resolve(strict=True)}@@{mkshared.PARTITION_START * mkshared.SECTOR_BYTES}"


def _mtools(command: str, image: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(command)
    if executable is None:
        raise ValueError(f"{command} is required to populate shared runtime media")
    return subprocess.run(
        [executable, "-i", _mtools_image(image), *arguments],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def verify_image(tree: Path, image: Path) -> None:
    """Extract and verify the exact runtime version from one detached image."""
    verify_tree(tree)
    mkshared.verify_image(image)
    with tempfile.TemporaryDirectory(prefix="troe-runtime-image-") as temporary:
        extraction_root = Path(temporary) / "extracted"
        extraction_root.mkdir()
        _mtools(
            "mcopy",
            image,
            "-s",
            f"::/{RUNTIME_DIRECTORY.as_posix()}",
            str(extraction_root),
        )
        extracted = extraction_root / f"v{RUNTIME_SCHEMA}"
        verify_tree(extracted)
        if (extracted / MANIFEST_NAME).read_bytes() != (tree / MANIFEST_NAME).read_bytes():
            raise ValueError("shared runtime media manifest differs from source tree")


def install_image(tree: Path, image: Path) -> None:
    """Populate an empty detached GPT/FAT32 shared image and verify every byte."""
    verify_tree(tree)
    mkshared.verify_image(image)
    existing = _mtools(
        "mdir", image, f"::/{RUNTIME_DIRECTORY.as_posix()}", check=False
    )
    if existing.returncode == 0:
        raise ValueError(
            f"shared runtime media already contains /{RUNTIME_DIRECTORY.as_posix()}"
        )
    entries = _parse_manifest(tree / MANIFEST_NAME)
    directories = {PurePosixPath("runtime"), PurePosixPath(RUNTIME_DIRECTORY.as_posix())}
    for relative, _byte_count, _digest_value in entries:
        parent = PurePosixPath(RUNTIME_DIRECTORY.as_posix()) / relative.parent
        while parent != PurePosixPath("."):
            directories.add(parent)
            parent = parent.parent
    for directory in sorted(directories, key=lambda item: (len(item.parts), item.as_posix())):
        _mtools("mmd", image, f"::/{directory.as_posix()}")
    _mtools(
        "mcopy",
        image,
        str(tree / MANIFEST_NAME),
        f"::/{RUNTIME_DIRECTORY.as_posix()}/{MANIFEST_NAME}",
    )
    for relative, _byte_count, _digest_value in entries:
        _mtools(
            "mcopy",
            image,
            str(tree / Path(*relative.parts)),
            f"::/{RUNTIME_DIRECTORY.as_posix()}/{relative.as_posix()}",
        )
    verify_image(tree, image)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    build = subparsers.add_parser("build", help="build one version directory")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--artifact", action="append", default=[])
    verify = subparsers.add_parser("verify", help="verify one version directory")
    verify.add_argument("tree", type=Path)
    install = subparsers.add_parser("install", help="install below mounted /vol/shared")
    install.add_argument("tree", type=Path)
    install.add_argument("--shared-root", type=Path, required=True)
    install_image_parser = subparsers.add_parser(
        "install-image", help="populate one detached GPT/FAT32 shared image"
    )
    install_image_parser.add_argument("tree", type=Path)
    install_image_parser.add_argument("--image", type=Path, required=True)
    verify_image_parser = subparsers.add_parser(
        "verify-image", help="verify a runtime tree stored in a detached image"
    )
    verify_image_parser.add_argument("tree", type=Path)
    verify_image_parser.add_argument("--image", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.action == "build":
            artifacts = collect_artifacts(args.artifact)
            build_tree(args.output, artifacts)
            result = args.output.resolve(strict=True)
        elif args.action == "verify":
            verify_tree(args.tree)
            result = args.tree.resolve(strict=True)
        elif args.action == "install":
            result = install_tree(args.tree, args.shared_root).resolve(strict=True)
        elif args.action == "install-image":
            install_image(args.tree, args.image)
            result = args.image.resolve(strict=True)
        else:
            verify_image(args.tree, args.image)
            result = args.image.resolve(strict=True)
        print(f"runtime tree v{RUNTIME_SCHEMA}: verified -> {result}")
        return 0
    except (OSError, ValueError) as error:
        print(f"mkruntime: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
