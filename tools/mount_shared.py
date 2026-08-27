#!/usr/bin/env python3
"""Safely attach or detach TROE's persistent shared GPT/FAT32 image."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Callable, Sequence

try:
    from tools import mkshared
except ImportError:  # Direct execution from tools/.
    import mkshared  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_IMAGE = REPO_ROOT / "build" / "troe-shared-fat32.img"
DEFAULT_STATE = REPO_ROOT / "build" / ".troe-shared-fat32.mount.json"
DEFAULT_LOCK = REPO_ROOT / "build" / ".troe-shared-fat32.lock"
STATE_SCHEMA = 1
_LINUX_LOOP_PATTERN = re.compile(r"/dev/loop[0-9]+")


class MountError(RuntimeError):
    """Report one contained host attachment or lifecycle failure."""


@dataclass(frozen=True)
class MountState:
    """Persistent identity needed to detach one tool-owned attachment."""

    schema: int
    image: str
    platform: str
    backend: str
    device: str
    partition: str
    mount_point: str
    read_only: bool

    @classmethod
    def decode(cls, document: object) -> MountState:
        """Decode an exact state record and reject ambiguous lifecycle data."""
        if not isinstance(document, dict) or set(document) != {
            "schema",
            "image",
            "platform",
            "backend",
            "device",
            "partition",
            "mount_point",
            "read_only",
        }:
            raise MountError("shared-media mount state has an invalid shape")
        if document["schema"] != STATE_SCHEMA:
            raise MountError("shared-media mount state has an unsupported schema")
        for field in (
            "image",
            "platform",
            "backend",
            "device",
            "partition",
            "mount_point",
        ):
            if not isinstance(document[field], str) or not document[field]:
                raise MountError(f"shared-media mount state has an invalid {field}")
        if not isinstance(document["read_only"], bool):
            raise MountError("shared-media mount state has an invalid read_only flag")
        return cls(**document)


class SharedMediaLock:
    """Cross-platform non-blocking process lock for shared-media transitions."""

    def __init__(
        self,
        path: Path = DEFAULT_LOCK,
        *,
        busy_message: str = (
            "shared FAT32 media is busy; stop QEMU or finish the other mount command"
        ),
    ) -> None:
        self.path = path
        self.busy_message = busy_message
        self._file: BinaryIO | None = None

    def __enter__(self) -> SharedMediaLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                if lock_file.seek(0, os.SEEK_END) == 0:
                    lock_file.write(b"\0")
                    lock_file.flush()
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            lock_file.close()
            raise MountError(self.busy_message) from error
        self._file = lock_file
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exception_type, exception, traceback
        if self._file is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._file.seek(0)
                msvcrt.locking(self._file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None


def _resolved(path: Path) -> str:
    return str(path.resolve(strict=False))


def load_state(path: Path = DEFAULT_STATE) -> MountState | None:
    """Load exact tool-owned attachment state, if present."""
    try:
        payload = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError) as error:
        raise MountError(f"cannot read shared-media mount state {path}: {error}") from error
    try:
        return MountState.decode(json.loads(payload))
    except json.JSONDecodeError as error:
        raise MountError(f"shared-media mount state is not valid JSON: {error}") from error


def write_state(state: MountState, path: Path = DEFAULT_STATE) -> None:
    """Atomically publish one successful attachment record."""
    path.parent.mkdir(parents=True, exist_ok=True)
    staging_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as staging:
            staging_path = Path(staging.name)
            json.dump(asdict(state), staging, sort_keys=True)
            staging.write("\n")
            staging.flush()
            os.fsync(staging.fileno())
        staging_path.replace(path)
    finally:
        if staging_path is not None and staging_path.exists():
            staging_path.unlink()


def remove_state(path: Path = DEFAULT_STATE) -> None:
    """Remove a stale or successfully detached attachment record."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise MountError(f"cannot remove shared-media mount state {path}: {error}") from error


def attachment_is_live(state: MountState) -> bool:
    """Return whether the recorded host attachment still exists."""
    if state.platform == "darwin":
        return _macos_attachment(Path(state.image)) is not None
    if state.platform.startswith("linux"):
        return _linux_attachment(Path(state.image)) is not None
    return Path(state.device).exists()


def _run(
    command: Sequence[str],
    purpose: str,
    *,
    binary: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=not binary,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as error:
        raise MountError(f"cannot {purpose}: {error}") from error
    if completed.returncode != 0:
        output = completed.stderr or completed.stdout
        if isinstance(output, bytes):
            detail = output.decode("utf-8", errors="replace").strip()
        else:
            detail = output.strip()
        suffix = f": {detail}" if detail else ""
        raise MountError(f"cannot {purpose}{suffix}")
    return completed


def parse_macos_attach(
    payload: bytes, image: Path, *, read_only: bool
) -> MountState:
    """Parse hdiutil's stable plist response without localized text."""
    try:
        document = plistlib.loads(payload)
    except plistlib.InvalidFileException as error:
        raise MountError("hdiutil returned an invalid attachment plist") from error
    entities = document.get("system-entities") if isinstance(document, dict) else None
    if not isinstance(entities, list):
        raise MountError("hdiutil did not report attached system entities")
    device = ""
    partition = ""
    mount_point = ""
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entry = entity.get("dev-entry")
        mounted = entity.get("mount-point")
        if isinstance(entry, str) and not device:
            device = entry
        if isinstance(entry, str) and isinstance(mounted, str):
            partition = entry
            mount_point = mounted
    if not device or not partition or not mount_point:
        raise MountError("hdiutil attached the image without a mounted FAT32 volume")
    return MountState(
        schema=STATE_SCHEMA,
        image=_resolved(image),
        platform="darwin",
        backend="hdiutil",
        device=device,
        partition=partition,
        mount_point=mount_point,
        read_only=read_only,
    )


def _macos_attachment(image: Path) -> str | None:
    hdiutil = shutil.which("hdiutil")
    if hdiutil is None:
        return None
    try:
        result = subprocess.run(
            (hdiutil, "info", "-plist"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        document = plistlib.loads(result.stdout) if result.returncode == 0 else {}
    except (OSError, plistlib.InvalidFileException):
        return None
    images = document.get("images") if isinstance(document, dict) else None
    if not isinstance(images, list):
        return None
    expected = _resolved(image)
    for attached in images:
        if not isinstance(attached, dict):
            continue
        attached_path = attached.get("image-path")
        if isinstance(attached_path, str) and _resolved(Path(attached_path)) == expected:
            return attached_path
    return None


def _linux_attachment(image: Path) -> str | None:
    losetup = shutil.which("losetup")
    if losetup is None:
        return None
    try:
        result = subprocess.run(
            (losetup, "--associated", _resolved(image)),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    match = _LINUX_LOOP_PATTERN.search(result.stdout)
    return match.group(0) if match is not None else None


def discover_attachment(image: Path, platform: str = sys.platform) -> str | None:
    """Find an attachment made outside this command where the host permits it."""
    if platform == "darwin":
        return _macos_attachment(image)
    if platform.startswith("linux"):
        return _linux_attachment(image)
    return None


def require_detached(
    image: Path = DEFAULT_IMAGE,
    state_path: Path = DEFAULT_STATE,
    *,
    platform: str = sys.platform,
) -> None:
    """Fail closed if QEMU or a host attachment may own the shared image."""
    state = load_state(state_path)
    if state is not None:
        if state.image != _resolved(image):
            raise MountError("shared-media state names a different image; inspect it manually")
        if attachment_is_live(state):
            raise MountError(
                f"shared FAT32 media is mounted at {state.mount_point}; "
                "run `cargo mount --unmount` before QEMU"
            )
        remove_state(state_path)
    attachment = discover_attachment(image, platform)
    if attachment is not None:
        raise MountError(
            f"shared FAT32 media is already attached by the host ({attachment}); detach it first"
        )


def mount_macos(image: Path, *, read_only: bool) -> MountState:
    """Attach the raw GPT image through macOS DiskImages."""
    hdiutil = shutil.which("hdiutil")
    if hdiutil is None:
        raise MountError("macOS hdiutil is unavailable")
    command = [hdiutil, "attach", "-plist", "-noautoopen"]
    if read_only:
        command.append("-readonly")
    command.append(_resolved(image))
    result = _run(command, "attach shared FAT32 image", binary=True)
    if not isinstance(result.stdout, bytes):
        raise MountError("hdiutil returned an invalid response type")
    try:
        return parse_macos_attach(result.stdout, image, read_only=read_only)
    except MountError:
        try:
            document = plistlib.loads(result.stdout)
            entities = (
                document.get("system-entities") if isinstance(document, dict) else None
            )
            device = ""
            if isinstance(entities, list):
                for entity in entities:
                    entry = entity.get("dev-entry") if isinstance(entity, dict) else None
                    if isinstance(entry, str):
                        device = entry
                        break
            if device:
                subprocess.run(
                    (hdiutil, "detach", device),
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except (OSError, plistlib.InvalidFileException):
            pass
        raise


def parse_linux_loop(output: str) -> str:
    """Extract one loop device from UDisks' localized wrapper output."""
    match = _LINUX_LOOP_PATTERN.search(output)
    if match is None:
        raise MountError("UDisks did not report the allocated loop device")
    return match.group(0)


def _wait_for_path(path: Path, timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.05)
    return path.exists()


def _decode_findmnt_path(encoded: str) -> str:
    return re.sub(
        r"\\x([0-9A-Fa-f]{2})",
        lambda match: chr(int(match.group(1), 16)),
        encoded,
    )


def _linux_mount_point(partition: str, udisks_output: str) -> str:
    findmnt = shutil.which("findmnt")
    if findmnt is not None:
        result = subprocess.run(
            (findmnt, "--noheadings", "--output", "TARGET", "--source", partition),
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0 and result.stdout.strip():
            return _decode_findmnt_path(result.stdout.strip().splitlines()[0])
    match = re.search(r"\bat (/.+?)(?:\.\s*)?$", udisks_output.strip())
    if match is None:
        raise MountError("UDisks mounted FAT32 but did not report its mount point")
    return match.group(1)


def _mount_linux_udisks(image: Path, *, read_only: bool) -> MountState:
    udisksctl = shutil.which("udisksctl")
    if udisksctl is None:
        raise MountError("UDisks is unavailable")
    command = [udisksctl, "loop-setup", "--file", _resolved(image)]
    if read_only:
        command.append("--read-only")
    loop_result = _run(command, "allocate shared-media loop device")
    if not isinstance(loop_result.stdout, str):
        raise MountError("UDisks returned an invalid loop response")
    device = parse_linux_loop(loop_result.stdout)
    partition = f"{device}p1"
    try:
        udevadm = shutil.which("udevadm")
        if udevadm is not None:
            subprocess.run(
                (udevadm, "settle", "--timeout=5"),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if not _wait_for_path(Path(partition)):
            raise MountError(f"GPT partition device did not appear: {partition}")
        mount_result = _run(
            (udisksctl, "mount", "--block-device", partition),
            "mount shared FAT32 partition",
        )
        if not isinstance(mount_result.stdout, str):
            raise MountError("UDisks returned an invalid mount response")
        mount_point = _linux_mount_point(partition, mount_result.stdout)
    except BaseException:
        subprocess.run(
            (udisksctl, "loop-delete", "--block-device", device),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        raise
    return MountState(
        schema=STATE_SCHEMA,
        image=_resolved(image),
        platform=sys.platform,
        backend="linux-udisks",
        device=device,
        partition=partition,
        mount_point=mount_point,
        read_only=read_only,
    )


def _mount_linux_root(image: Path, *, read_only: bool) -> MountState:
    losetup = shutil.which("losetup")
    mount = shutil.which("mount")
    if losetup is None or mount is None:
        raise MountError("Linux loop-device or mount utilities are unavailable")
    command = [losetup, "--find", "--show", "--partscan"]
    if read_only:
        command.append("--read-only")
    command.append(_resolved(image))
    loop_result = _run(command, "allocate shared-media loop device")
    if not isinstance(loop_result.stdout, str):
        raise MountError("losetup returned an invalid response")
    device = loop_result.stdout.strip()
    if _LINUX_LOOP_PATTERN.fullmatch(device) is None:
        raise MountError("losetup returned an invalid loop device")
    partition = f"{device}p1"
    mount_point = REPO_ROOT / "build" / "troe-shared-mount"
    try:
        if not _wait_for_path(Path(partition)):
            raise MountError(f"GPT partition device did not appear: {partition}")
        mount_point.mkdir(parents=True, exist_ok=True)
        mount_command = [mount]
        if read_only:
            mount_command.extend(("--options", "ro"))
        mount_command.extend((partition, str(mount_point)))
        _run(mount_command, "mount shared FAT32 partition")
    except BaseException:
        subprocess.run(
            (losetup, "--detach", device),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        raise
    return MountState(
        schema=STATE_SCHEMA,
        image=_resolved(image),
        platform=sys.platform,
        backend="linux-root",
        device=device,
        partition=partition,
        mount_point=str(mount_point),
        read_only=read_only,
    )


def mount_linux(image: Path, *, read_only: bool) -> MountState:
    """Attach with desktop UDisks, or direct loop devices when already root."""
    if shutil.which("udisksctl") is not None:
        return _mount_linux_udisks(image, read_only=read_only)
    geteuid: Callable[[], int] | None = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return _mount_linux_root(image, read_only=read_only)
    raise MountError(
        "Linux writable mounting requires UDisks (`udisksctl` from udisks2); "
        "install it or run this command from an already-root development environment"
    )


def mount_image(
    image: Path = DEFAULT_IMAGE,
    *,
    read_only: bool,
    platform: str = sys.platform,
) -> MountState:
    """Dispatch one attachment to the exact current host backend."""
    if platform == "darwin":
        return mount_macos(image, read_only=read_only)
    if platform.startswith("linux"):
        return mount_linux(image, read_only=read_only)
    raise MountError(
        f"cargo mount does not support host platform {platform!r}; "
        "the current host backends are macOS and Linux"
    )


def unmount_image(state: MountState) -> None:
    """Detach one recorded attachment without forcing busy filesystems."""
    if state.backend == "hdiutil":
        hdiutil = shutil.which("hdiutil")
        if hdiutil is None:
            raise MountError("macOS hdiutil is unavailable")
        _run((hdiutil, "detach", state.device), "detach shared FAT32 image")
        return
    if state.backend == "linux-udisks":
        udisksctl = shutil.which("udisksctl")
        if udisksctl is None:
            raise MountError("UDisks is unavailable for detaching its loop device")
        try:
            _run(
                (udisksctl, "unmount", "--block-device", state.partition),
                "unmount shared FAT32 partition",
            )
        except MountError:
            if os.path.ismount(state.mount_point):
                raise
        _run(
            (udisksctl, "loop-delete", "--block-device", state.device),
            "release shared-media loop device",
        )
        return
    if state.backend == "linux-root":
        umount = shutil.which("umount")
        losetup = shutil.which("losetup")
        if umount is None or losetup is None:
            raise MountError("Linux unmount or loop-device utilities are unavailable")
        try:
            _run((umount, state.mount_point), "unmount shared FAT32 partition")
        except MountError:
            if os.path.ismount(state.mount_point):
                raise
        _run((losetup, "--detach", state.device), "release shared-media loop device")
        return
    raise MountError(f"unsupported recorded mount backend {state.backend!r}")


def open_mount_point(state: MountState) -> None:
    """Open the mounted directory in the platform file manager on request."""
    opener = "open" if state.platform == "darwin" else "xdg-open"
    executable = shutil.which(opener)
    if executable is None:
        raise MountError(f"cannot open mount point because {opener} is unavailable")
    try:
        subprocess.Popen(
            (executable, state.mount_point),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise MountError(f"cannot open mounted directory: {error}") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--unmount",
        "--detach",
        action="store_true",
        help="cleanly detach the tool-owned shared FAT32 attachment",
    )
    action.add_argument(
        "--status",
        action="store_true",
        help="report whether the shared FAT32 image is attached",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="attach without allowing host writes",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the mounted directory in the host file manager",
    )
    args = parser.parse_args(argv)
    if (args.unmount or args.status) and (args.read_only or args.open):
        parser.error("--read-only and --open apply only when mounting")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        with SharedMediaLock():
            state = load_state()
            if state is not None and state.image != _resolved(DEFAULT_IMAGE):
                raise MountError("shared-media state names a different image")
            if state is not None and not attachment_is_live(state):
                remove_state()
                state = None

            if args.status:
                if state is not None:
                    mode = "read-only" if state.read_only else "read-write"
                    print(f"shared FAT32: mounted {mode} at {state.mount_point}")
                else:
                    external = discover_attachment(DEFAULT_IMAGE)
                    if external is None:
                        print("shared FAT32: detached")
                    else:
                        print(f"shared FAT32: attached outside cargo mount ({external})")
                return 0

            if args.unmount:
                if state is None:
                    external = discover_attachment(DEFAULT_IMAGE)
                    if external is not None:
                        raise MountError(
                            f"image is attached outside cargo mount ({external}); detach it with the host tool"
                        )
                    print("shared FAT32: already detached")
                    return 0
                unmount_image(state)
                remove_state()
                print("shared FAT32: detached; it is safe to start QEMU")
                return 0

            if state is not None:
                if args.read_only and not state.read_only:
                    raise MountError(
                        "shared FAT32 is already mounted read-write; detach it before changing mode"
                    )
            else:
                require_detached()
                created = mkshared.ensure_image(DEFAULT_IMAGE)
                state = mount_image(DEFAULT_IMAGE, read_only=args.read_only)
                try:
                    write_state(state)
                except BaseException:
                    unmount_image(state)
                    raise
                action = "created and mounted" if created else "mounted"
                mode = "read-only" if state.read_only else "read-write"
                print(f"shared FAT32: {action} {mode} at {state.mount_point}")
            print("copy files there, then run `cargo mount --unmount` before QEMU")

        if args.open:
            open_mount_point(state)
        return 0
    except (MountError, OSError, ValueError) as error:
        print(f"cargo mount: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
