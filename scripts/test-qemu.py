#!/usr/bin/env python3
"""Drive deterministic shell acceptance tests through the QEMU serial console."""

from __future__ import annotations

import argparse
import concurrent.futures
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

from platform_profile import (
    AARCH64_UEFI_VIRTIO_MMIO,
    PLATFORM_IDS,
    REPO_ROOT,
    X86_64_Q35_UEFI,
    X86_64_UEFI_VIRTIO_PCI,
    resolve_platform,
    root_storage_image_path,
    shared_test_image_path,
    statefs_image_path,
    txslot_image_path,
)
from qemu_profile import (
    ENVIRONMENT_IDS,
    build_cloud_bundle,
    cloud_bundle_path,
    prepare_qemu_command,
    resolve_runner,
)
from test_scenarios import DEFAULT_SCENARIOS, SCENARIO_IDS


ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[=>])")
BOOT_TIMEOUT_SECONDS = 30.0
# Exhaustive dual-architecture runs can briefly deschedule one QEMU while the
# other guest is producing a framebuffer-sized memory report. Keep the bound
# finite, but large enough that host scheduling jitter is not a kernel failure.
COMMAND_TIMEOUT_SECONDS = 10.0
TXSLOT_DISK_BYTES = 4_096 * 512
TXSLOT_PARTITION_OFFSET = 2_048 * 512
TXSLOT_BYTES = 4 * 512
TXSLOT_CHECKSUM_OFFSET = 20
NETWORK_REQUEST = b"troe-stage8-request"
NETWORK_REPLY = b"troe-stage8-reply"
TCP_REQUEST = b"troe-tcp-request"
TCP_REPLY = b"troe-tcp-reply\n"
MUTABLE_ROOT_FILE = "/vol/root/troe-mutable.txt"
MUTABLE_ROOT_CONTENT = "persistent-ext4-content"
SHARED_FILE = "/vol/shared/host-visible.txt"
SHARED_CONTENT = "persistent-fat32-content"
RUNTIME_PROBE_PACKAGES = REPO_ROOT / "build" / "runtime-probe-packages"
RUNTIME_PROBE_TREE = REPO_ROOT / "build" / "runtime-tree-v2"
CPYTHON_PACKAGE_TREE = REPO_ROOT / "build" / "cpython-package"
CPYTHON_DIAGNOSTICS_TREE = (
    REPO_ROOT / "build" / "cpython-diagnostics" / "cpython-diagnostics" / "v1"
)
CPYTHON_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "cpython"
SHARED_BIN = "/vol/shared/bin"
CPYTHON_SHARED_BIN = SHARED_BIN
CPYTHON_SHARED_LIB = "/vol/shared/lib"
CPYTHON_DIAGNOSTICS_ROOT = "/vol/shared/cpython-diagnostics/v1"
# Interpreter startup, standard-library imports, and cyclic collection are
# far heavier than a coreutil launch, and both guests share one host.
CPYTHON_TIMEOUT_SCALE = 12.0


class AcceptanceError(RuntimeError):
    """A boot, console, assertion, or timeout failure."""


class UdpAcceptancePeer:
    """Answer the guest's bounded Stage 8 UDP probe on the slirp host."""

    def __init__(
        self,
        platform_id: str,
        environment: str,
        *,
        bind_address: str = "127.0.0.1",
        port: int | None = None,
    ) -> None:
        self.platform_id = platform_id
        if port is None:
            port = resolve_runner(platform_id, environment).acceptance_udp_port
        self.received = 0
        self.error: OSError | None = None
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.settimeout(0.2)
        self._socket.bind((bind_address, port))
        self._thread = threading.Thread(
            target=self._serve,
            name=f"udp-acceptance-{platform_id}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    payload, address = self._socket.recvfrom(256)
                except socket.timeout:
                    continue
                if payload != NETWORK_REQUEST:
                    continue
                self.received += 1
                # Exercise rejection of unrelated bounded traffic before the
                # valid reply. The portable queue tests supply the 10k flood.
                for _ in range(4):
                    self._socket.sendto(b"troe-stage8-noise", address)
                    time.sleep(0.005)
                self._socket.sendto(NETWORK_REPLY, address)
        except OSError as error:
            if not self._stop.is_set():
                self.error = error

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=1.0)


class TcpAcceptancePeer:
    """Answer one typed KEX TCP stream exchange on the slirp host."""

    def __init__(
        self,
        platform_id: str,
        environment: str,
        *,
        bind_address: str = "127.0.0.1",
        port: int | None = None,
    ) -> None:
        self.platform_id = platform_id
        if port is None:
            port = resolve_runner(platform_id, environment).acceptance_udp_port
        self.received = 0
        self.error: OSError | None = None
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.settimeout(0.2)
        self._socket.bind((bind_address, port))
        self._socket.listen(1)
        self._thread = threading.Thread(
            target=self._serve,
            name=f"tcp-acceptance-{platform_id}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    connection, _address = self._socket.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(0.5)
                    payload = bytearray()
                    try:
                        while len(payload) < len(TCP_REQUEST):
                            chunk = connection.recv(len(TCP_REQUEST) - len(payload))
                            if not chunk:
                                break
                            payload.extend(chunk)
                    except socket.timeout:
                        # A no-payload connection is used to prove that
                        # cancellation revokes owner state without blocking
                        # the next bounded acceptance exchange.
                        continue
                    if bytes(payload) != TCP_REQUEST:
                        continue
                    self.received += 1
                    connection.sendall(TCP_REPLY)
        except OSError as error:
            if not self._stop.is_set():
                self.error = error

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=1.0)


def txslot_path(platform_id: str) -> Path:
    """Return the platform-private writable acceptance medium."""
    return txslot_image_path(resolve_platform(platform_id))


def statefs_path(platform_id: str) -> Path:
    """Return the platform-private writable filesystem medium."""
    return statefs_image_path(resolve_platform(platform_id))


def reset_txslot(platform_id: str, environment: str) -> None:
    """Start one platform's process-reopen sequence from empty media."""
    profile = resolve_platform(platform_id)
    path = txslot_path(platform_id)
    if resolve_runner(platform_id, environment).disk_layout == "cloud-bundle-v1":
        bundle = cloud_bundle_path(profile, environment)
        shutil.copyfile(bundle / "activation.raw", path)
        shutil.copyfile(bundle / "state.raw", statefs_path(platform_id))
        return
    shutil.copyfile(
        REPO_ROOT / "build" / "storage-root.img",
        root_storage_image_path(profile),
    )
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "mkstorage.py"),
            "--manifest",
            str(REPO_ROOT / "assets" / "boot.bmnt"),
            "--persistence-selector",
            str(REPO_ROOT / "assets" / "persist.prgn"),
            "--txslot-output",
            str(path),
            "--state-selector",
            str(REPO_ROOT / "assets" / "state.prgn"),
            "--statefs-output",
            str(statefs_path(platform_id)),
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def build_runtime_probe_tree() -> None:
    """Build the optional runtimes and C probes into one shared-runtime tree."""
    if RUNTIME_PROBE_PACKAGES.exists():
        shutil.rmtree(RUNTIME_PROBE_PACKAGES)
    if RUNTIME_PROBE_TREE.exists():
        shutil.rmtree(RUNTIME_PROBE_TREE)
    RUNTIME_PROBE_PACKAGES.mkdir(parents=True, exist_ok=True)
    for source in (REPO_ROOT / "tests" / "runtime-probe", REPO_ROOT / "apps" / "lua"):
        subprocess.run(
            [
                "cargo",
                "kex",
                "build",
                source,
                "--target",
                "all",
                "--output",
                RUNTIME_PROBE_PACKAGES,
            ],
            cwd=REPO_ROOT,
            check=True,
        )
    artifacts = []
    for name in ("runtime-probe", "lua"):
        for architecture in ("x86_64", "aarch64"):
            artifacts.extend(
                [
                    "--artifact",
                    f"{architecture}:{name}="
                    f"{RUNTIME_PROBE_PACKAGES / architecture / f'{name}.kex'}",
                ]
            )
    subprocess.run(
        [
            sys.executable,
            REPO_ROOT / "tools" / "mkruntime.py",
            "build",
            "--output",
            RUNTIME_PROBE_TREE,
            *artifacts,
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def reset_shared_media(
    platform_id: str, *, install_runtime: bool, install_cpython: bool = False
) -> None:
    """Create one platform-private FAT32 medium and install runtime artifacts."""
    path = shared_test_image_path(resolve_platform(platform_id))
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools" / "mkshared.py"),
            "--output",
            str(path),
            "--reset",
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    if install_runtime:
        subprocess.run(
            [
                sys.executable,
                REPO_ROOT / "tools" / "mkruntime.py",
                "install-image",
                RUNTIME_PROBE_TREE,
                "--image",
                path,
            ],
            cwd=REPO_ROOT,
            check=True,
        )
    if install_cpython:
        install_cpython_media(path)


def cleanup_shared_media(platform_ids: tuple[str, ...]) -> None:
    """Remove platform-private acceptance media that are reset on every run."""
    for platform_id in platform_ids:
        shared_test_image_path(resolve_platform(platform_id)).unlink(missing_ok=True)


def dual_slot_state(platform_id: str, path: Path) -> tuple[int, bytes]:
    """Validate TXSLOT v1 and return its newest generation and payload."""
    image = path.read_bytes()
    if len(image) != TXSLOT_DISK_BYTES:
        raise AcceptanceError(f"{platform_id} TXSLOT image has invalid length")
    image = image[TXSLOT_PARTITION_OFFSET : TXSLOT_PARTITION_OFFSET + TXSLOT_BYTES]
    generations: list[tuple[int, bytes]] = []
    for slot in range(2):
        data = image[slot * 1024 : slot * 1024 + 512]
        commit = image[slot * 1024 + 512 : slot * 1024 + 1024]
        if data == bytes(512) and commit == bytes(512):
            continue
        checked_data = bytearray(data)
        checked_data[TXSLOT_CHECKSUM_OFFSET : TXSLOT_CHECKSUM_OFFSET + 4] = bytes(4)
        data_checksum = struct.unpack_from("<I", data, TXSLOT_CHECKSUM_OFFSET)[0]
        length = struct.unpack_from("<I", data, 16)[0]
        generation = struct.unpack_from("<Q", data, 8)[0]
        checked_commit = bytearray(commit)
        checked_commit[TXSLOT_CHECKSUM_OFFSET : TXSLOT_CHECKSUM_OFFSET + 4] = bytes(4)
        valid = (
            data[:8] == b"TXDTv1\0\0"
            and commit[:8] == b"TXCMv1\0\0"
            and generation != 0
            and length <= 512 - 32
            and data[24:32] == bytes(8)
            and data[32 + length :] == bytes(512 - 32 - length)
            and zlib.crc32(checked_data) == data_checksum
            and struct.unpack_from("<Q", commit, 8)[0] == generation
            and struct.unpack_from("<I", commit, 16)[0] == data_checksum
            and commit[24:] == bytes(512 - 24)
            and zlib.crc32(checked_commit)
            == struct.unpack_from("<I", commit, TXSLOT_CHECKSUM_OFFSET)[0]
        )
        if valid:
            generations.append((generation, data[32 : 32 + length]))
    generation_numbers = [generation for generation, _ in generations]
    if not generations or len(generation_numbers) != len(set(generation_numbers)):
        raise AcceptanceError(
            f"{platform_id} TXSLOT has no unique committed generation"
        )
    return max(generations, key=lambda state: state[0])


def txslot_state(platform_id: str) -> tuple[int, bytes]:
    """Return the activation transaction state."""
    return dual_slot_state(platform_id, txslot_path(platform_id))


def statefs_counter(platform_id: str) -> tuple[int, int]:
    """Validate STFS v1 and return transaction generation and file counter."""
    generation, payload = dual_slot_state(platform_id, statefs_path(platform_id))
    if len(payload) != 40 or payload[:8] != b"STFSv1\0\0":
        raise AcceptanceError(f"{platform_id} statefs payload is malformed")
    checked = bytearray(payload)
    checked[20:24] = bytes(4)
    valid = (
        struct.unpack_from("<HHHHI", payload, 8) == (1, 0, 32, 1, 8)
        and payload[24:32] == bytes(8)
        and zlib.crc32(checked) == struct.unpack_from("<I", payload, 20)[0]
    )
    if not valid:
        raise AcceptanceError(f"{platform_id} statefs image failed validation")
    return generation, struct.unpack_from("<Q", payload, 32)[0]


def assert_rolled_back_sact(platform_id: str, payload: bytes) -> None:
    """Require the durable SACT pointer to select generation one only."""
    if len(payload) != 128 or payload[:8] != b"SACTv1\0\0":
        raise AcceptanceError(f"{platform_id} durable SACT payload is malformed")
    checked = bytearray(payload)
    checked[112:116] = bytes(4)
    valid = (
        struct.unpack_from("<HHH", payload, 8) == (1, 0, 128)
        and struct.unpack_from("<H", payload, 14)[0] == 0
        and struct.unpack_from("<Q", payload, 16)[0] == 1
        and payload[64:112] == bytes(48)
        and payload[116:] == bytes(12)
        and zlib.crc32(checked) == struct.unpack_from("<I", payload, 112)[0]
    )
    if not valid:
        raise AcceptanceError(f"{platform_id} did not persist predecessor rollback")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=("all", *PLATFORM_IDS),
        required=True,
        help="named platform to test, or explicit 'all'",
    )
    parser.add_argument(
        "--environment",
        choices=ENVIRONMENT_IDS,
        required=True,
        help="exact execution environment runner",
    )
    parser.add_argument("--firmware-code", type=Path)
    parser.add_argument("--firmware-vars", type=Path)
    version_policy = parser.add_mutually_exclusive_group()
    version_policy.add_argument(
        "--skip-version-check",
        action="store_true",
        help="deliberately allow QEMU outside the supported 8.x-11.x range",
    )
    version_policy.add_argument(
        "--strict-tool-versions",
        action="store_true",
        help="require QEMU 11.1.0, pinned firmware, and e2fsprogs 1.47.4",
    )
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="run a fast terminal-focused scenario instead of full acceptance",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIO_IDS,
        help=(
            "run one acceptance scenario group; repeat for multiple groups; "
            "the default runs every group"
        ),
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="use boot images already present under build/",
    )
    parser.add_argument(
        "--framebuffer-console",
        action="store_true",
        help="attach a headless ramfb and require owned text-console activation",
    )
    parser.add_argument(
        "--native-keyboard",
        action="store_true",
        help="drive the x86_64 native PS/2 keyboard through a QEMU monitor",
    )
    parser.add_argument(
        "--boot-timeout",
        type=float,
        default=BOOT_TIMEOUT_SECONDS,
        help=f"seconds to wait for the initial prompt (default: {BOOT_TIMEOUT_SECONDS:g})",
    )
    parser.add_argument(
        "--command-timeout",
        type=float,
        default=COMMAND_TIMEOUT_SECONDS,
        help=f"seconds to wait for each command (default: {COMMAND_TIMEOUT_SECONDS:g})",
    )
    return parser.parse_args(argv)


def selected_scenarios(args: argparse.Namespace) -> frozenset[str]:
    """Resolve explicit acceptance groups while keeping the default exhaustive."""
    if args.smoke:
        if args.scenario:
            raise ValueError("--smoke and --scenario are mutually exclusive")
        return frozenset()
    return frozenset(args.scenario) if args.scenario else DEFAULT_SCENARIOS


def apply_scenario_requirements(
    args: argparse.Namespace, scenario_groups: frozenset[str]
) -> None:
    """Enable devices/assertions owned by an explicitly selected scenario."""
    if "framebuffer-keyboard" in scenario_groups:
        args.framebuffer_console = True
        args.native_keyboard = True


def requires_acceptance_images(scenario_groups: frozenset[str]) -> bool:
    """Return whether selected groups execute destructive acceptance probes."""
    return "fault-isolation" in scenario_groups


def normalize(data: bytes) -> str:
    """Normalize terminal control traffic while preserving shell text."""
    text = data.decode("utf-8", errors="replace").replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    return ANSI_ESCAPE.sub("", text)


def parse_owned_memory_accounting(report: str) -> int:
    """Validate complete kernel-owned counters and return current heap use."""
    for label in ("total usable", "reserved"):
        match = re.search(
            rf"^{re.escape(label)}: ([0-9]+) \([^\n]+\)$", report, re.MULTILINE
        )
        if match is None or int(match.group(1)) == 0:
            raise AcceptanceError(
                f"mem did not report a positive numeric {label} value; "
                f"command output was {report!r}"
            )
    frames = re.search(r"^frames: ([0-9]+)/([0-9]+) free$", report, re.MULTILINE)
    if (
        frames is None
        or int(frames.group(2)) == 0
        or int(frames.group(1)) > int(frames.group(2))
    ):
        raise AcceptanceError(f"mem reported invalid frame counters: {report!r}")
    heap = re.search(r"^heap: ([0-9]+)/([0-9]+) used \([^\n]+\)$", report, re.MULTILINE)
    if (
        heap is None
        or int(heap.group(2)) == 0
        or int(heap.group(1)) >= int(heap.group(2))
    ):
        raise AcceptanceError(f"mem reported invalid heap counters: {report!r}")
    high_water = re.search(
        r"^heap high-water: ([0-9]+) \([^\n]+\)$", report, re.MULTILINE
    )
    if high_water is None or int(high_water.group(1)) < int(heap.group(1)):
        raise AcceptanceError(f"mem reported invalid heap high-water: {report!r}")
    failures = re.search(r"^allocation failures: ([0-9]+)$", report, re.MULTILINE)
    if failures is None or int(failures.group(1)) < 1:
        raise AcceptanceError(
            f"bounded allocation failure was not accounted: {report!r}"
        )
    input_queue = re.search(
        r"^input queue: ([0-9]+)/([0-9]+) queued$", report, re.MULTILINE
    )
    if (
        input_queue is None
        or int(input_queue.group(2)) == 0
        or int(input_queue.group(1)) > int(input_queue.group(2))
    ):
        raise AcceptanceError(f"mem reported invalid input queue counters: {report!r}")
    for label in ("input interrupts", "input delivered"):
        match = re.search(rf"^{re.escape(label)}: ([0-9]+)$", report, re.MULTILINE)
        if match is None or int(match.group(1)) == 0:
            raise AcceptanceError(f"mem reported invalid {label}: {report!r}")
    dropped = re.search(r"^input dropped: ([0-9]+)$", report, re.MULTILINE)
    if dropped is None or int(dropped.group(1)) != 0:
        raise AcceptanceError(f"ordinary input unexpectedly overflowed: {report!r}")
    idle_waits = re.search(r"^input idle waits: ([0-9]+)$", report, re.MULTILINE)
    wakeups = re.search(r"^input wakeups: ([0-9]+)$", report, re.MULTILINE)
    if (
        idle_waits is None
        or wakeups is None
        or int(wakeups.group(1)) > int(idle_waits.group(1))
    ):
        raise AcceptanceError(f"mem reported inconsistent idle accounting: {report!r}")
    return int(heap.group(1))


def parse_runtime_counter(report: str, label: str) -> int:
    """Read one exact integer counter from the immutable diagnostics report."""
    match = re.search(rf"^{re.escape(label)}: ([0-9]+)$", report, re.MULTILINE)
    if match is None:
        raise AcceptanceError(f"mem did not report {label!r}: {report!r}")
    return int(match.group(1))


def parse_free_frames(report: str) -> int:
    """Read the current owned free-frame count from a diagnostics report."""
    match = re.search(r"^frames: ([0-9]+)/([0-9]+) free$", report, re.MULTILINE)
    if match is None:
        raise AcceptanceError(f"mem did not report owned frames: {report!r}")
    return int(match.group(1))


def assert_owned_boot(session: "SerialSession") -> None:
    """Require the concise statuses emitted across the ownership handoff."""
    transcript = session.transcript()
    for marker in (
        "Initializing memory and protection",
        "Starting devices and input",
        "Starting task and application runtime",
        "Starting console",
        "Mounting /vol/root read-write",
        "Configuring network: 10.0.2.15/24",
        "Tiny Rust Operating Environment 0.1.0",
        "Small by design. Alive on the wire.",
        "Welcome to TROE.",
    ):
        if marker not in transcript:
            raise AcceptanceError(
                f"{session.architecture} boot missed ownership marker {marker!r}"
            )
    discovery_marker = {
        X86_64_UEFI_VIRTIO_PCI: "platform discovery: ACPI validated",
        AARCH64_UEFI_VIRTIO_MMIO: "platform discovery: FDT validated",
    }.get(session.platform_id)
    if discovery_marker is not None and discovery_marker not in transcript:
        raise AcceptanceError(f"{session.platform_id} boot missed {discovery_marker!r}")


def assert_ipc_baseline(session: "SerialSession") -> None:
    """Require both IPC paths and their deterministic structural counters."""
    rows: dict[tuple[str, int], dict[str, int]] = {}
    for line in session.transcript().splitlines():
        if not line.startswith("ipc-baseline "):
            continue
        fields: dict[str, str] = {}
        for field in line.split()[1:]:
            key, separator, value = field.partition("=")
            if not separator or not key or not value:
                raise AcceptanceError(f"malformed IPC baseline row: {line!r}")
            fields[key] = value
        try:
            path = fields.pop("path")
            payload = int(fields.pop("payload"))
            counters = {key: int(value) for key, value in fields.items()}
        except (KeyError, ValueError) as error:
            raise AcceptanceError(f"malformed IPC baseline row: {line!r}") from error
        key = (path, payload)
        if key in rows:
            raise AcceptanceError(f"duplicate IPC baseline row: {line!r}")
        rows[key] = counters

    payloads = (0, 64, 256, 4096)
    expected = {
        (path, payload)
        for path in ("in-process", "isolated-diagnostics")
        for payload in payloads
    }
    if set(rows) != expected:
        raise AcceptanceError(
            f"{session.architecture} IPC baseline matrix mismatch: {sorted(rows)!r}"
        )
    for payload in payloads:
        local = rows[("in-process", payload)]
        if (
            local.get("warmup") != 64
            or local.get("samples") != 256
            or local.get("calls") != 256
            or local.get("address_space_switches") != 0
            or local.get("tlb_invalidations") != 0
            or local.get("timer_programs") != 0
        ):
            raise AcceptanceError(f"invalid in-process IPC counters: {local!r}")

        isolated = rows[("isolated-diagnostics", payload)]
        fragments = 512 if payload == 4096 else 256
        boundaries = 768 if payload == 4096 else 256
        if (
            isolated.get("warmup") != 64
            or isolated.get("samples") != 256
            or isolated.get("calls") != 256
            or isolated.get("request_allocations") != 0
            or isolated.get("reply_allocations") != 0
            or isolated.get("steady_allocations") != 0
            or isolated.get("wire_fragments") != fragments
            or isolated.get("address_space_switches") != boundaries * 2
            or isolated.get("tlb_invalidations") != boundaries * 2
            or isolated.get("timer_programs") != boundaries
            or isolated.get("retained_requests") != 1
            or isolated.get("contexts") != 1
        ):
            raise AcceptanceError(f"invalid isolated IPC counters: {isolated!r}")


class SerialSession:
    """A QEMU child with deadline-bound serial reads and deterministic cleanup."""

    def __init__(self, command: list[str], platform_id: str) -> None:
        self.platform_id = platform_id
        self.architecture = resolve_platform(platform_id).architecture
        self.process = subprocess.Popen(
            command,
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self.chunks: queue.Queue[bytes | None] = queue.Queue()
        self.output = bytearray()
        self.reader = threading.Thread(target=self._read_output, daemon=True)
        self.reader.start()

    def _read_output(self) -> None:
        assert self.process.stdout is not None
        try:
            # Raw pipe reads return the currently available bytes up to this
            # bound. Chunking avoids one synchronized queue operation per byte
            # during the editor's intentionally verbose redraw workload.
            while chunk := self.process.stdout.read(4096):
                self.chunks.put(chunk)
        finally:
            self.chunks.put(None)

    def wait_for(self, marker: bytes, timeout: float, start: int = 0) -> int:
        """Read until marker appears after start and return its end offset."""
        deadline = time.monotonic() + timeout
        while True:
            found = self.output.find(marker, start)
            if found >= 0:
                return found + len(marker)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AcceptanceError(
                    f"timed out after {timeout:g}s waiting for {marker!r}"
                )
            try:
                chunk = self.chunks.get(timeout=remaining)
            except queue.Empty as error:
                raise AcceptanceError(
                    f"timed out after {timeout:g}s waiting for {marker!r}"
                ) from error
            if chunk is None:
                status = self.process.poll()
                raise AcceptanceError(
                    f"QEMU exited with status {status} while waiting for {marker!r}"
                )
            self.output.extend(chunk)

    def _write_echoed(self, text: str, timeout: float) -> None:
        """Type printable text and require the guest to echo every chunk."""
        assert self.process.stdin is not None
        # Pace against guest echo so both firmware and native UART paths
        # remain deterministic under loaded CI hosts. Eight bytes stay
        # below the pinned UART FIFO and bounded input-queue capacities
        # while avoiding a host round trip for every printable byte.
        encoded = text.encode("utf-8")
        for offset in range(0, len(encoded), 8):
            chunk = encoded[offset : offset + 8]
            start = len(self.output)
            self.process.stdin.write(chunk)
            self.process.stdin.flush()
            self.wait_for(chunk, timeout, start)

    def _write_control(self, byte: bytes) -> None:
        """Send one unechoed control byte."""
        assert self.process.stdin is not None
        self.process.stdin.write(byte)
        self.process.stdin.flush()

    def send(self, command: str, timeout: float, line_ending: bytes = b"\n") -> int:
        """Send one console line and return the transcript offset after its newline."""
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        try:
            self._write_echoed(command, timeout)
            start = len(self.output)
            self.process.stdin.write(line_ending)
            self.process.stdin.flush()
            return self.wait_for(b"\n", timeout, start)
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error

    def typed_input_command(
        self,
        command: str,
        lines: tuple[str, ...],
        cwd: str,
        timeout: float,
        *,
        settle: float = 0.0,
        responses: tuple[str, ...] = (),
        contains: tuple[str, ...] = (),
        absent: tuple[str, ...] = (),
    ) -> str:
        """Type bounded lines into one foreground reader, then signal end of input.

        Each line is echoed by the session terminal loan, exactly as the prompt
        echoes an edited line, so the same pacing applies while the shell is not
        the reader. A reader that answers every line shares the console with
        that echo, so `responses` waits for the answer before typing the next
        line instead of interleaving two concurrent writers.
        """
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        submitted = self.send(command, timeout)
        if settle > 0:
            # Hold the reader blocked so unrelated deadlines must be observed
            # while one foreground process owns the terminal.
            time.sleep(settle)
        try:
            for index, line in enumerate(lines):
                self._write_echoed(line, timeout)
                start = len(self.output)
                self._write_control(b"\n")
                answered = self.wait_for(b"\n", timeout, start)
                if index < len(responses):
                    self.wait_for(responses[index].encode("utf-8"), timeout, answered)
            self._write_control(b"\x04")
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error
        prompt = f"sh:{cwd}> ".encode()
        end = self.wait_for(prompt, timeout, submitted)
        text = normalize(bytes(self.output[submitted : end - len(prompt)]))
        for expected in contains:
            if expected not in text:
                raise AcceptanceError(
                    f"{command!r} did not consume typed input as expected; "
                    f"missing {expected!r} in {text!r}"
                )
        for unexpected in absent:
            if unexpected in text:
                raise AcceptanceError(
                    f"{command!r} unexpectedly produced {unexpected!r}; "
                    f"session output was {text!r}"
                )
        return text

    def assert_terminal(self, start: int, timeout: float) -> None:
        """Require a bounded quiet, live terminal state without reboot markers."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                chunk = self.chunks.get(timeout=remaining)
            except queue.Empty:
                break
            if chunk is None:
                status = self.process.poll()
                raise AcceptanceError(
                    f"QEMU exited with status {status} instead of remaining parked"
                )
            self.output.extend(chunk)
        if self.process.poll() is not None:
            raise AcceptanceError("QEMU exited instead of remaining in the fatal state")
        tail = normalize(bytes(self.output[start:]))
        if "Initializing memory and protection" in tail or "sh:/> " in tail:
            raise AcceptanceError(f"machine rebooted after fatal marker: {tail!r}")

    def terminal_command(self, command: str, marker: bytes, timeout: float) -> None:
        """Require a platform-control command to emit its marker and exit QEMU."""
        start = self.send(command, timeout)
        self.wait_for(marker, timeout, start)
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise AcceptanceError(
                f"{command!r} did not terminate the QEMU machine"
            ) from error
        if status != 0:
            raise AcceptanceError(
                f"{command!r} terminated QEMU with unexpected status {status}"
            )

    def parked_command(self, command: str, marker: bytes, timeout: float) -> None:
        """Require a terminal command marker followed by a bounded parked state."""
        start = self.send(command, timeout)
        marker_end = self.wait_for(marker, timeout, start)
        self.assert_terminal(marker_end, min(timeout, 1.0))

    def cancelled_command(self, command: str, cwd: str, timeout: float) -> None:
        """Start a cooperative command and require Ctrl-C to restore the prompt."""
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        start = self.send(command, timeout)
        time.sleep(0.02)
        self.process.stdin.write(b"\x03")
        self.process.stdin.flush()
        prompt = f"sh:{cwd}> ".encode()
        self.wait_for(prompt, timeout, start)
        output = normalize(bytes(self.output[start:]))
        if "cancelled" not in output:
            raise AcceptanceError(
                f"{command!r} did not report cooperative cancellation: {output!r}"
            )

    def backspace_command(
        self,
        prefix: str,
        suffix: str,
        cwd: str,
        timeout: float,
        expected: str,
    ) -> None:
        """Type a line containing BS and verify that it edits rather than executes."""
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        start = len(self.output)
        try:
            for byte in prefix.encode("utf-8"):
                character_start = len(self.output)
                self.process.stdin.write(bytes((byte,)))
                self.process.stdin.flush()
                self.wait_for(bytes((byte,)), timeout, character_start)

            self.process.stdin.write(b"\x08")
            self.process.stdin.flush()
            # Firmware may apply cursor movement without reproducing the exact
            # bytes on its serial output, so validate the executed line below.
            time.sleep(0.05)

            for byte in suffix.encode("utf-8"):
                character_start = len(self.output)
                self.process.stdin.write(bytes((byte,)))
                self.process.stdin.flush()
                self.wait_for(bytes((byte,)), timeout, character_start)

            submit_start = len(self.output)
            self.process.stdin.write(b"\n")
            self.process.stdin.flush()
            submitted = self.wait_for(b"\n", timeout, submit_start)
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error

        prompt = f"sh:{cwd}> ".encode()
        end = self.wait_for(prompt, timeout, submitted)
        text = normalize(bytes(self.output[start : end - len(prompt)]))
        if expected not in text:
            raise AcceptanceError(
                f"backspace-edited command did not produce {expected!r}; "
                f"command output was {text!r}"
            )

    def edited_command(
        self,
        prefix: str,
        edit: bytes,
        suffix: str,
        cwd: str,
        timeout: float,
        expected: str,
    ) -> None:
        """Execute a command containing one raw editor-key sequence."""
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        start = len(self.output)
        try:
            for byte in prefix.encode("utf-8"):
                character_start = len(self.output)
                self.process.stdin.write(bytes((byte,)))
                self.process.stdin.flush()
                self.wait_for(bytes((byte,)), timeout, character_start)

            edit_start = len(self.output)
            self.process.stdin.write(edit)
            self.process.stdin.flush()
            # Pure horizontal cursor motion now uses the terminal's native
            # relative-movement sequence instead of repainting the whole line.
            marker = edit if edit in (b"\x1b[D", b"\x1b[C") else b"\x1b[K"
            self.wait_for(marker, timeout, edit_start)

            for byte in suffix.encode("utf-8"):
                character_start = len(self.output)
                self.process.stdin.write(bytes((byte,)))
                self.process.stdin.flush()
                self.wait_for(bytes((byte,)), timeout, character_start)

            submit_start = len(self.output)
            self.process.stdin.write(b"\n")
            self.process.stdin.flush()
            submitted = self.wait_for(b"\n", timeout, submit_start)
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error

        prompt = f"sh:{cwd}> ".encode()
        end = self.wait_for(prompt, timeout, submitted)
        text = normalize(bytes(self.output[start : end - len(prompt)]))
        if expected not in text:
            raise AcceptanceError(
                f"edited command did not produce {expected!r}; output was {text!r}"
            )

    def command(
        self,
        command: str,
        cwd: str,
        timeout: float,
        *,
        next_cwd: str | None = None,
        contains: tuple[str, ...] = (),
        absent: tuple[str, ...] = (),
        raw_contains: tuple[bytes, ...] = (),
        line_ending: bytes = b"\n",
    ) -> str:
        """Execute a line, wait for the next prompt, and assert its output."""
        submitted = self.send(command, timeout, line_ending)
        resulting_cwd = cwd if next_cwd is None else next_cwd
        prompt = f"sh:{resulting_cwd}> ".encode()
        end = self.wait_for(prompt, timeout, submitted)
        raw = bytes(self.output[submitted : end - len(prompt)])
        text = normalize(raw)
        echoed = f"{command}\n"
        if text.startswith(echoed):
            text = text[len(echoed) :]
        for expected in contains:
            if expected not in text:
                raise AcceptanceError(
                    f"{command!r} did not produce expected text {expected!r}; "
                    f"command output was {text!r}"
                )
        for unexpected in absent:
            if unexpected in text:
                raise AcceptanceError(
                    f"{command!r} unexpectedly produced {unexpected!r}; "
                    f"command output was {text!r}"
                )
        for expected in raw_contains:
            if expected not in raw:
                raise AcceptanceError(
                    f"{command!r} did not produce expected bytes {expected!r}"
                )
        return text

    def confirmed_command(
        self,
        command: str,
        cwd: str,
        timeout: float,
        *,
        contains: tuple[str, ...] = (),
        absent: tuple[str, ...] = (),
        program: str | None = None,
    ) -> str:
        """Approve one explicit-path warning, then assert command output.

        The warning names the application, which is the first word only for a
        single-stage command; a pipeline must state it explicitly.
        """
        submitted = self.send(command, timeout)
        warned = program if program is not None else command.split()[0]
        marker = f"Run untrusted application '{warned}' outside /bin? [y/N] ".encode()
        self.wait_for(marker, timeout, submitted)
        answered = self.send("y", timeout)
        prompt = f"sh:{cwd}> ".encode()
        end = self.wait_for(prompt, timeout, answered)
        text = normalize(bytes(self.output[submitted : end - len(prompt)]))
        for expected in contains:
            if expected not in text:
                raise AcceptanceError(
                    f"{command!r} did not produce expected text {expected!r}; "
                    f"command output was {text!r}"
                )
        for unexpected in absent:
            if unexpected in text:
                raise AcceptanceError(
                    f"{command!r} unexpectedly produced {unexpected!r}; "
                    f"command output was {text!r}"
                )
        return text

    def declined_command(
        self, command: str, cwd: str, timeout: float, *, absent: tuple[str, ...] = ()
    ) -> str:
        """Submit the default negative answer and require no execution."""
        submitted = self.send(command, timeout)
        marker = f"Run untrusted application '{command.split()[0]}' outside /bin? [y/N] ".encode()
        self.wait_for(marker, timeout, submitted)
        answered = self.send("", timeout)
        prompt = f"sh:{cwd}> ".encode()
        end = self.wait_for(prompt, timeout, answered)
        text = normalize(bytes(self.output[submitted : end - len(prompt)]))
        if "execution cancelled\n" not in text:
            raise AcceptanceError(
                f"{command!r} did not report declined execution: {text!r}"
            )
        for unexpected in absent:
            if unexpected in text:
                raise AcceptanceError(
                    f"{command!r} unexpectedly produced {unexpected!r}; "
                    f"command output was {text!r}"
                )
        return text

    def close(self) -> None:
        """Stop QEMU even when the guest has deliberately returned to firmware."""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process.stdin is not None:
            self.process.stdin.close()
        if self.process.stdout is not None:
            self.process.stdout.close()

    def transcript(self) -> str:
        """Return the normalized transcript collected so far."""
        return normalize(bytes(self.output))


def assert_storage_report(
    session: SerialSession, cwd: str, command_timeout: float
) -> None:
    """Require exact production activation and StateFS region diagnostics."""
    session.command(
        "cat /sys/storage",
        cwd,
        command_timeout,
        contains=(
            "internal activation "
            "disk=76543210fedcba9889abcdef01234567 "
            "partition=67452301efcdab8998badcfe10325476 "
            "type=8e5f0f3f1bde4fcbbf3d5d8a7ec96a21 state=active\n",
            "internal statefs "
            "disk=112233445566778899aabbccddeeff00 "
            "partition=2233445566778899aabbccddeeff0011 "
            "type=33445566778899aabbccddeeff001122 state=mounted\n",
        ),
    )


def run_boot_group(session: SerialSession, command_timeout: float) -> None:
    """Validate owned boot storage and the baseline packaged KEX launch."""
    cwd = "/"
    assert_storage_report(session, cwd, command_timeout)
    session.command(
        "echo application-ready",
        cwd,
        command_timeout,
        contains=("application-ready\n",),
    )


def run_network_group(
    session: SerialSession, command_timeout: float, tcp_port: int
) -> None:
    """Exercise bounded network observation, DHCP, ICMP, UDP, and TCP services."""
    cwd = "/"
    session.command(
        "svc status timesync",
        cwd,
        command_timeout,
        contains=("timesync ready",),
    )
    session.command(
        "net",
        cwd,
        command_timeout,
        contains=("link: ready", "ipv4: 10.0.2.15", "gateway: 10.0.2.2"),
    )
    session.command(
        "dhcp",
        cwd,
        command_timeout,
        contains=("ipv4: 10.0.2.15", "lease:"),
    )
    session.command(
        "ping 10.0.2.2",
        cwd,
        command_timeout,
        contains=("reply from 10.0.2.2", "bytes=9"),
    )
    session.command(
        "net stats",
        cwd,
        command_timeout,
        contains=("rx frames:", "arp entries:", "checkpoints:"),
    )
    session.command("arp", cwd, command_timeout, contains=("10.0.2.2",))
    before_waits = session.command("mem", cwd, command_timeout)
    idle_before = parse_runtime_counter(before_waits, "input idle waits")
    frames_before = parse_free_frames(before_waits)
    session.command("sleep 100", cwd, command_timeout)
    run_resident_process_checks(session, cwd, command_timeout)
    session.cancelled_command("sleep 86400000", cwd, command_timeout)
    session.command(
        "udp send --source-port 40001 10.0.2.2 9 application-datagram",
        cwd,
        command_timeout,
        contains=("sent 20 bytes from port 40001 to 10.0.2.2:9",),
    )
    # Without a payload operand the datagram body is read from the foreground
    # terminal instead of being sent empty.
    session.typed_input_command(
        "udp send --source-port 40003 10.0.2.2 9",
        ("typed-datagram",),
        cwd,
        command_timeout,
        contains=("sent 15 bytes from port 40003 to 10.0.2.2:9",),
    )
    session.cancelled_command("udp listen 40000", cwd, command_timeout)
    session.command("net stats", cwd, command_timeout, contains=("udp ports: 1",))
    session.command(
        "udp listen 40002",
        cwd,
        command_timeout,
        contains=("udp: operation timed out",),
    )
    session.command("net stats", cwd, command_timeout, contains=("udp ports: 1",))
    after_waits = session.command("mem", cwd, command_timeout)
    idle_after = parse_runtime_counter(after_waits, "input idle waits")
    frames_after = parse_free_frames(after_waits)
    if idle_after <= idle_before:
        raise AcceptanceError(
            "deferred timer/UDP workload did not enter the native idle-wakeup path"
        )
    if frames_after != frames_before:
        raise AcceptanceError(
            "deferred timer/UDP workload leaked application frames: "
            f"{frames_before} -> {frames_after} free"
        )
    session.cancelled_command(f"tcp 10.0.2.2 {tcp_port}", cwd, command_timeout)
    for _ in range(5):
        session.command(
            f"tcp 10.0.2.2 {tcp_port} troe-tcp-request",
            cwd,
            command_timeout,
            contains=("troe-tcp-reply\n",),
        )


def run_resident_process_checks(
    session: SerialSession, cwd: str, command_timeout: float
) -> None:
    """Require foreground/background concurrency, control, and exact reaping."""
    session.command(
        "sleep 100 &",
        cwd,
        command_timeout,
        contains=("[1] started sleep",),
    )
    session.command(
        "sleep 5000",
        cwd,
        command_timeout,
        absent=("sleep: application rejected", "sleep: operation timed out"),
    )
    session.command(
        "jobs",
        cwd,
        command_timeout,
        contains=("[1] done sleep 100",),
    )
    session.command("wait 1", cwd, command_timeout)
    session.command(
        "sleep 86400000 &",
        cwd,
        command_timeout,
        contains=("[2] started sleep",),
    )
    session.command(
        "echo prompt-responsive",
        cwd,
        command_timeout,
        contains=("prompt-responsive\n",),
    )
    session.command(
        "jobs",
        cwd,
        command_timeout,
        contains=("[2] blocked sleep 86400000",),
    )
    session.command("kill 2", cwd, command_timeout)
    session.command("wait 2", cwd, command_timeout)
    session.command(
        "sleep 100 &",
        cwd,
        command_timeout,
        contains=("[3] started sleep",),
    )
    session.command("wait 3", cwd, command_timeout)


def start_background_job(
    session: SerialSession, command: str, cwd: str, timeout: float
) -> int:
    """Start one background job and return the identifier the shell assigned."""
    report = session.command(command, cwd, timeout)
    started = re.search(r"\[(\d+)\] started ", report)
    if started is None:
        raise AcceptanceError(f"{command!r} did not report a background job: {report!r}")
    return int(started.group(1))


def run_terminal_input_checks(
    session: SerialSession, cwd: str, command_timeout: float
) -> None:
    """Require the foreground terminal-input loan, its bounds, and its release."""
    # A foreground reader consumes typed lines and observes Ctrl-D end of input.
    # Each line appears twice: once echoed by the loan, once written by `cat`.
    session.typed_input_command(
        "cat -u",
        ("terminal-alpha", "terminal-beta"),
        cwd,
        command_timeout,
        responses=("terminal-alpha\n", "terminal-beta\n"),
        contains=(
            "terminal-alpha\nterminal-alpha\n",
            "terminal-beta\nterminal-beta\n",
        ),
        absent=("cat: ",),
    )
    # A blocked foreground read stays cancellable and restores the prompt.
    session.cancelled_command("cat", cwd, command_timeout)
    # A background job receives end of input and cannot consume prompt input.
    reader = start_background_job(session, "cat -u &", cwd, command_timeout)
    session.command(f"wait {reader}", cwd, command_timeout)
    session.command(
        f"log {reader}",
        cwd,
        command_timeout,
        absent=("terminal-alpha", "background-visible"),
    )
    session.command(
        "echo background-visible",
        cwd,
        command_timeout,
        contains=("background-visible\n",),
    )
    # A resident background job keeps progressing while a foreground read blocks.
    sleeper = start_background_job(session, "sleep 100 &", cwd, command_timeout)
    session.typed_input_command(
        "cat -u",
        ("terminal-coexist",),
        cwd,
        command_timeout,
        settle=1.0,
        responses=("terminal-coexist\n",),
        contains=("terminal-coexist\nterminal-coexist\n",),
    )
    session.command(
        "jobs", cwd, command_timeout, contains=(f"[{sleeper}] done sleep 100",)
    )
    session.command(f"wait {sleeper}", cwd, command_timeout)
    # Supervised services keep running across a blocked foreground read.
    session.command(
        "svc status timesync", cwd, command_timeout, contains=("timesync ready",)
    )
    # Redirection and pipelines stay byte-identical and take no loan.
    session.command(
        "cat -u < /recovery/motd",
        cwd,
        command_timeout,
        contains=("Small by design. Alive on the wire.",),
    )
    session.command(
        "echo piped-input | cat -u", cwd, command_timeout, contains=("piped-input\n",)
    )
    # An owner-scoped child never inherits the loan.
    session.command(
        "spawn --status cat -u",
        cwd,
        command_timeout,
        contains=("spawn-status: 0\n",),
        absent=("terminal-alpha",),
    )


def run_shell_terminal_group(session: SerialSession, command_timeout: float) -> None:
    """Exercise editing, history, completion, help, manuals, and CRLF handling."""
    cwd = "/"
    # Root completion emits one line per built-in and KEX command. Once earlier
    # groups have filled the framebuffer terminal, every candidate also scrolls
    # the display, so use the same loaded-console allowance as long manuals.
    session.edited_command(
        "", b"\t", "", cwd, max(command_timeout, 30.0), expected="\ncat\n"
    )
    session.command(
        "man echo",
        cwd,
        command_timeout,
        contains=(
            "NAME\n    echo - write arguments",
            "SYNOPSIS\n    echo [-n] [-e|-E] [ARG...]",
        ),
    )
    session.command(
        "man sh",
        cwd,
        max(command_timeout, 30.0),
        contains=("bounded command scripts", "16 KiB default working buffer"),
    )
    # `date` reads the live clock, so nothing here may assert an instant. Every
    # check below is a property of the zone rather than of the current time:
    # the session default is UTC, a fixed-offset zone always renders the same
    # abbreviation and offset, and `-u` overrides whatever TZ says.
    session.command(
        "date +%Z",
        cwd,
        command_timeout,
        contains=("UTC\n",),
    )
    session.command(
        "date -u +%z",
        cwd,
        command_timeout,
        contains=("+0000\n",),
    )
    # `date` cannot be reached through `spawn --env`: a child's capabilities
    # must attenuate its launcher's, and `spawn` holds no `wall-clock`. The
    # zone `date` reports is therefore the session's, and the launcher-narrowed
    # zone is proven through `lua`, which does hold it, in the lua group.
    session.command(
        "spawn --env TZ=XYZ-7 date +%Z",
        cwd,
        command_timeout,
        contains=("spawn: child launch failed",),
        absent=("XYZ",),
    )
    session.command(
        "date +%Q",
        cwd,
        command_timeout,
        contains=("date: unsupported conversion in FORMAT",),
    )
    session.command(
        "date --bogus",
        cwd,
        command_timeout,
        contains=("date: date [-u] [+FORMAT]",),
    )
    session.command(
        "man date",
        cwd,
        max(command_timeout, 30.0),
        contains=("date - print the wall-clock time", "There is no timezone"),
    )
    session.command(
        "ps",
        cwd,
        command_timeout,
        contains=(
            "PID ORIGIN STATE    CPU-MS PAGES HANDLES PREEMPTS YIELDS NAME",
            " ps\n",
        ),
    )
    session.command(
        "top 1",
        cwd,
        command_timeout,
        raw_contains=(b"\x1b[2J\x1b[H",),
        contains=("TROE top  uptime=", "processes=", " top\n"),
    )
    session.command("help", cwd, command_timeout, contains=("help: unknown command",))
    session.backspace_command(
        "echo brokeX", "n", cwd, command_timeout, expected="\nbroken\n"
    )
    session.edited_command(
        "echo ac", b"\x1b[D", "b", cwd, command_timeout, expected="\nabc\n"
    )
    session.command(
        "echo history-ready", cwd, command_timeout, contains=("history-ready\n",)
    )
    session.edited_command(
        "", b"\x1b[A", "", cwd, command_timeout, expected="\nhistory-ready\n"
    )
    session.edited_command("pw", b"\t", "", cwd, command_timeout, expected="\n/\n")
    session.command(
        "echo crlf-ready",
        cwd,
        command_timeout,
        contains=("crlf-ready\n",),
        line_ending=b"\r\n",
    )
    run_terminal_input_checks(session, cwd, command_timeout)


def shared_lua(session: SerialSession) -> str:
    """Return the explicit shared-media path of the optional Lua runtime."""
    return f"{SHARED_BIN}/{session.architecture}/lua.kex"


def exercise_head_tail_and_mkdir(
    session: SerialSession, cwd: str, command_timeout: float
) -> None:
    """Cover directory creation and the leading/trailing line selectors."""
    # `mkdir -p` creates every missing component and is idempotent. Each step
    # asserts an observable outcome, because a command with no expectation
    # verifies nothing at all.
    session.command(
        "mkdir -v /vol/root/troe-md",
        cwd,
        command_timeout,
        contains=("mkdir: created directory '/vol/root/troe-md'\n",),
    )
    # Walking prefixes must tolerate /vol, which lies above any writable mount
    # and can never itself be created.
    session.command(
        "mkdir -pv /vol/root/troe-md/a/b/c",
        cwd,
        command_timeout,
        contains=(
            "mkdir: created directory '/vol/root/troe-md/a'\n",
            "mkdir: created directory '/vol/root/troe-md/a/b'\n",
            "mkdir: created directory '/vol/root/troe-md/a/b/c'\n",
        ),
        absent=("read-only",),
    )
    # Repeating it creates nothing and reports no failure.
    session.command(
        "mkdir -pv /vol/root/troe-md/a/b/c",
        cwd,
        command_timeout,
        absent=("created directory", "read-only", "already exists"),
    )
    # A refusal names the component that failed, not the leaf that followed.
    session.command(
        "mkdir -p /vol/rooot/data/logs",
        cwd,
        command_timeout,
        contains=("mkdir: /vol/rooot: read-only filesystem\n",),
        absent=("/vol/rooot/data",),
    )
    # An existing file cannot become a directory, and it is named too.
    session.command("printf x > /vol/root/troe-md/afile", cwd, command_timeout)
    session.command(
        "mkdir -p /vol/root/troe-md/afile/below",
        cwd,
        command_timeout,
        contains=("mkdir: /vol/root/troe-md/afile: wrong node type\n",),
    )
    # The leaf really is a directory a file can be written into.
    session.command(
        "printf deep > /vol/root/troe-md/a/b/c/file",
        cwd,
        command_timeout,
    )
    session.command(
        "cat /vol/root/troe-md/a/b/c/file",
        cwd,
        command_timeout,
        contains=("deep",),
    )
    session.command(
        "mkdir /vol/root/troe-md",
        cwd,
        command_timeout,
        contains=("mkdir: /vol/root/troe-md: already exists\n",),
    )
    session.command(
        "printf 'l1\\nl2\\nl3\\nl4\\nl5\\n' > /vol/root/troe-md/lines",
        cwd,
        command_timeout,
    )
    # Line and byte selection from each end, including the obsolete -N form.
    session.command(
        "head -n 2 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l1\nl2\n",),
    )
    session.command(
        "head -2 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l1\nl2\n",),
    )
    session.command(
        "tail -n 2 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l4\nl5\n",),
    )
    session.command(
        "tail -n +4 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l4\nl5\n",),
    )
    session.command(
        "head -c 3 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l1\n",),
    )
    session.command(
        "tail -c 3 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l5\n",),
    )
    # A count beyond the input yields the whole input rather than an error.
    session.command(
        "head -n 99 /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l1\nl2\nl3\nl4\nl5\n",),
    )
    # A pipe cannot be read backwards, so this takes the retained-window path.
    session.command(
        "cat /vol/root/troe-md/lines | tail -n 1",
        cwd,
        command_timeout,
        contains=("l5\n",),
    )
    session.command(
        "cat /vol/root/troe-md/lines | head -n 1",
        cwd,
        command_timeout,
        contains=("l1\n",),
    )
    # Multiple operands print separating headers; -q suppresses them.
    session.command(
        "head -n 1 /vol/root/troe-md/lines /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("==> /vol/root/troe-md/lines <==\nl1\n",),
    )
    session.command(
        "head -q -n 1 /vol/root/troe-md/lines /vol/root/troe-md/lines",
        cwd,
        command_timeout,
        contains=("l1\nl1\n",),
    )
    session.command(
        "head /vol/root/troe-md/missing",
        cwd,
        command_timeout,
        contains=("head: /vol/root/troe-md/missing: not found\n",),
    )
    session.command("rm -r /vol/root/troe-md", cwd, command_timeout)


def exercise_change_and_creation_times(
    session: SerialSession, cwd: str, command_timeout: float
) -> None:
    """Cover `ls -lc` and `ls -lU`, and the change time a rename advances."""
    stamp = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}"
    session.command("printf one > /vol/root/troe-ctime", cwd, command_timeout)
    # Every column is matched with the size beside it, so `ls`'s own error
    # cannot satisfy the assertion the way a bare path match would.
    for flag, label in (("-l", "modification"), ("-lc", "change"), ("-lU", "creation")):
        listing = session.command(
            f"ls {flag} /vol/root/troe-ctime", cwd, command_timeout
        )
        if not re.search(rf"- +3 {stamp} /vol/root/troe-ctime", listing):
            raise AcceptanceError(
                f"ls {flag} did not report a {label} time; output was {listing!r}"
            )

    # A rename rewrites no byte of the payload, so the modification time must
    # stand while the change time moves. This is the case `-c` exists for.
    before = session.command("ls -l /vol/root/troe-ctime", cwd, command_timeout)
    session.command(
        "mv /vol/root/troe-ctime /vol/root/troe-ctime-moved", cwd, command_timeout
    )
    after = session.command("ls -l /vol/root/troe-ctime-moved", cwd, command_timeout)
    modified_before = re.search(stamp, before)
    modified_after = re.search(stamp, after)
    if not modified_before or not modified_after:
        raise AcceptanceError(f"no time before/after rename: {before!r} {after!r}")
    if modified_before.group() != modified_after.group():
        raise AcceptanceError(
            "a rename must not advance the modification time; "
            f"{modified_before.group()!r} became {modified_after.group()!r}"
        )
    changed = session.command("ls -lc /vol/root/troe-ctime-moved", cwd, command_timeout)
    if not re.search(rf"- +3 {stamp} /vol/root/troe-ctime-moved", changed):
        raise AcceptanceError(f"ls -lc lost the change time; output was {changed!r}")
    session.command("rm /vol/root/troe-ctime-moved", cwd, command_timeout)

    # FAT32 records no change time at all, so the column is omitted rather than
    # blank -- while its creation time is present.
    session.command("printf fat > /vol/shared/troe-ctime", cwd, command_timeout)
    fat_changed = session.command("ls -lc /vol/shared/troe-ctime", cwd, command_timeout)
    if re.search(stamp, fat_changed):
        raise AcceptanceError(
            "FAT32 has no change time yet ls -lc reported one; "
            f"output was {fat_changed!r}"
        )
    fat_created = session.command("ls -lU /vol/shared/troe-ctime", cwd, command_timeout)
    if not re.search(rf"- +3 {stamp} /vol/shared/troe-ctime", fat_created):
        raise AcceptanceError(
            f"FAT32 records a creation time yet ls -lU omitted it: {fat_created!r}"
        )
    session.command("rm /vol/shared/troe-ctime", cwd, command_timeout)


def exercise_touch(session: SerialSession, cwd: str, command_timeout: float) -> None:
    """Cover creation, in-place stamping, and the providers that refuse."""
    session.command(
        "mkdir -p /vol/root/troe-touch",
        cwd,
        command_timeout,
        absent=("read-only", "not found"),
    )
    # Creating an absent file leaves it empty and stamped. The listing is matched
    # on its size and date columns, so `ls`'s own error cannot satisfy it.
    session.command("touch /vol/root/troe-touch/new", cwd, command_timeout)
    listing = session.command("ls -l /vol/root/troe-touch/new", cwd, command_timeout)
    if not re.search(r"- +0 \d{4}-\d{2}-\d{2} \d{2}:\d{2} /vol/root/troe-touch/new", listing):
        raise AcceptanceError(
            f"touch did not create a stamped empty file; output was {listing!r}"
        )
    session.command(
        "wc -c /vol/root/troe-touch/new",
        cwd,
        command_timeout,
        contains=("0 /vol/root/troe-touch/new\n",),
    )
    # An explicit instant is applied exactly, and 2026-08-29T10:40:00Z is well
    # inside every provider's range.
    session.command(
        "touch -d 1788000000 /vol/root/troe-touch/new",
        cwd,
        command_timeout,
        absent=("touch:",),
    )
    session.command(
        "ls -l /vol/root/troe-touch/new",
        cwd,
        command_timeout,
        contains=("2026-08-29 10:40 /vol/root/troe-touch/new",),
    )
    # Stamping an existing file must not truncate it: a replacement would.
    session.command(
        "printf keepme > /vol/root/troe-touch/kept", cwd, command_timeout
    )
    session.command(
        "touch -d 1788000000 /vol/root/troe-touch/kept",
        cwd,
        command_timeout,
        absent=("touch:",),
    )
    session.command(
        "cat /vol/root/troe-touch/kept",
        cwd,
        command_timeout,
        contains=("keepme",),
    )
    # -c leaves an absent file absent, without reporting a failure.
    session.command(
        "touch -c /vol/root/troe-touch/absent",
        cwd,
        command_timeout,
        absent=("touch:",),
    )
    session.command(
        "ls /vol/root/troe-touch/absent",
        cwd,
        command_timeout,
        contains=("/vol/root/troe-touch/absent: not found\n",),
    )
    # A provider that records no time still creates the file and reports
    # success, both for a new name and for one that already exists.
    session.command(
        "touch /tmp/troe-touch-tmp",
        cwd,
        command_timeout,
        absent=("touch:",),
    )
    session.command(
        "touch /tmp/troe-touch-tmp",
        cwd,
        command_timeout,
        absent=("touch:",),
    )
    # It exists and is empty, so the second call neither failed nor truncated.
    session.command(
        "wc -c /tmp/troe-touch-tmp",
        cwd,
        command_timeout,
        contains=("0 /tmp/troe-touch-tmp\n",),
    )
    session.command("rm /tmp/troe-touch-tmp", cwd, command_timeout)
    # The read-only root refuses the mutation itself.
    session.command(
        "touch /bin/echo.kex",
        cwd,
        command_timeout,
        contains=("touch: /bin/echo.kex: read-only filesystem\n",),
    )
    session.command("rm -r /vol/root/troe-touch", cwd, command_timeout)


def run_filesystem_group(session: SerialSession, command_timeout: float) -> None:
    """Exercise mounted reads, pipelines, paths, and bounded file mutation."""
    cwd = "/"
    lua = shared_lua(session)
    session.command(
        "mount",
        cwd,
        command_timeout,
        contains=(
            "root /vol/root ext4-v1 rw auto mounted\n",
            "shared /vol/shared fat32 rw auto mounted\n",
        ),
    )
    session.command("mount root", cwd, command_timeout)
    session.command(f"printf %s {SHARED_CONTENT} > {SHARED_FILE}", cwd, command_timeout)
    session.command(
        f"cat {SHARED_FILE}",
        cwd,
        command_timeout,
        contains=(SHARED_CONTENT,),
    )
    session.command(
        "cp /bin/echo.kex /vol/shared/echo-copy", cwd, command_timeout
    )
    session.command("cd /vol/shared", cwd, command_timeout, next_cwd="/vol/shared")
    cwd = "/vol/shared"
    session.declined_command(
        "./echo-copy should-not-execute",
        cwd,
        command_timeout,
        absent=("should-not-execute\n",),
    )
    session.declined_command(
        "./echo-copy logical-declined && echo should-not-execute",
        cwd,
        command_timeout,
        absent=("logical-declined\n", "should-not-execute\n"),
    )
    session.confirmed_command(
        "./echo-copy shared-relative-kex",
        cwd,
        command_timeout,
        contains=("shared-relative-kex\n",),
    )
    session.confirmed_command(
        "./echo-copy logical-path && echo logical-followup",
        cwd,
        command_timeout,
        contains=("logical-path\n", "logical-followup\n"),
    )
    session.confirmed_command(
        "/vol/shared/echo-copy shared-absolute-kex",
        cwd,
        command_timeout,
        contains=("shared-absolute-kex\n",),
    )
    session.confirmed_command(
        lua + " -e 'local ok,kind,status=os.execute(\"./echo-copy "
        "shared-child-kex\"); print(\"path-kex-status\",ok,kind,status)'",
        cwd,
        command_timeout,
        contains=("shared-child-kex\n", "path-kex-status\ttrue\texit\t0\n"),
    )
    runtime_probe = (
        f"{SHARED_BIN}/{session.architecture}/runtime-probe.kex"
    )
    first_probe = session.confirmed_command(
        runtime_probe,
        cwd,
        max(command_timeout, 30.0),
        contains=("c-runtime-probe ok image=",),
    )
    second_probe = session.confirmed_command(
        runtime_probe,
        cwd,
        max(command_timeout, 30.0),
        contains=("c-runtime-probe ok image=",),
    )
    first_image = re.search(r"image=(0x[0-9a-f]+)", first_probe)
    second_image = re.search(r"image=(0x[0-9a-f]+)", second_probe)
    if first_image is None or second_image is None or first_image.group(1) == second_image.group(1):
        raise AcceptanceError("large C runtime probe did not receive fresh ASLR placement")
    session.confirmed_command(
        lua + f" -e 'local ok,kind,status=os.execute(\"{runtime_probe}\"); "
        "print(\"runtime-child-status\",ok,kind,status)'",
        cwd,
        max(command_timeout, 30.0),
        contains=("c-runtime-probe ok image=", "runtime-child-status\ttrue\texit\t0\n"),
    )
    session.confirmed_command(
        f"{runtime_probe}.missing",
        cwd,
        command_timeout,
        contains=(f"{runtime_probe}.missing: not found",),
    )
    session.command(
        "spawn echo-copy",
        cwd,
        command_timeout,
        contains=("spawn: child launch failed",),
        absent=("shared-relative-kex",),
    )
    session.confirmed_command(
        "./missing-kex",
        cwd,
        command_timeout,
        contains=("./missing-kex: not found",),
    )
    session.command("printf not-a-kex > ./malformed-kex", cwd, command_timeout)
    session.confirmed_command(
        "./malformed-kex",
        cwd,
        command_timeout,
        contains=("./malformed-kex: application package rejected",),
    )
    session.command("rm ./malformed-kex", cwd, command_timeout)
    session.command("cd /", cwd, command_timeout, next_cwd="/")
    cwd = "/"
    session.command(
        "ls /",
        cwd,
        command_timeout,
        contains=("config", "man", "recovery", "sys", "tmp"),
        absent=("etc/",),
    )
    session.command(
        "cat /recovery/motd",
        cwd,
        command_timeout,
        contains=(
            "Tiny Rust Operating Environment 0.1.0",
            "Small by design. Alive on the wire.",
        ),
    )
    session.command(
        "cat /vol/root/hello.txt",
        cwd,
        command_timeout,
        contains=("native ext4 mount\n",),
    )
    session.command(f"printf initial > {MUTABLE_ROOT_FILE}", cwd, command_timeout)
    session.command(
        f"ln {MUTABLE_ROOT_FILE} /vol/root/troe-mutable-hard",
        cwd,
        command_timeout,
    )
    session.command(
        "ln -s troe-mutable.txt /vol/root/troe-mutable-soft",
        cwd,
        command_timeout,
    )
    session.command("cp /bin/echo.kex /vol/root/echo-copy", cwd, command_timeout)
    session.command(
        "ln -s echo-copy /vol/root/echo-link", cwd, command_timeout
    )
    session.confirmed_command(
        "/vol/root/echo-link symlinked-kex",
        cwd,
        command_timeout,
        contains=("symlinked-kex\n",),
    )
    session.command(
        "ls /vol/root",
        cwd,
        command_timeout,
        contains=("troe-mutable-hard", "troe-mutable-soft"),
    )
    session.command(
        f"printf %s {MUTABLE_ROOT_CONTENT} > /vol/root/troe-mutable-soft",
        cwd,
        command_timeout,
    )
    session.command(
        "cat /vol/root/troe-mutable-hard",
        cwd,
        command_timeout,
        contains=(MUTABLE_ROOT_CONTENT,),
    )
    session.command(
        f"cp {MUTABLE_ROOT_FILE} /vol/root/troe-copy.txt", cwd, command_timeout
    )
    session.command(
        "cat /vol/root/troe-copy.txt",
        cwd,
        command_timeout,
        contains=(MUTABLE_ROOT_CONTENT,),
    )
    session.command(
        "cp /vol/root/troe-mutable-soft /vol/root/troe-copy-soft",
        cwd,
        command_timeout,
    )
    session.command(
        "ls /vol/root",
        cwd,
        command_timeout,
        contains=("troe-copy-soft",),
    )
    session.command(
        "cat /vol/root/troe-copy-soft",
        cwd,
        command_timeout,
        contains=(MUTABLE_ROOT_CONTENT,),
    )
    session.command(
        "mv /vol/root/troe-copy.txt /vol/root/troe-moved.txt", cwd, command_timeout
    )
    session.command(
        "cat /vol/root/troe-moved.txt",
        cwd,
        command_timeout,
        contains=(MUTABLE_ROOT_CONTENT,),
    )
    session.command(
        "cp -R /vol/root/nested /vol/root/troe-copy-tree", cwd, command_timeout
    )
    session.command(
        "cat /vol/root/troe-copy-tree/state.txt",
        cwd,
        command_timeout,
        contains=("read-only activation complete\n",),
    )
    session.command(
        "mv /vol/root/troe-copy-tree /vol/root/troe-moved-tree",
        cwd,
        command_timeout,
    )
    session.command(
        "cat /vol/root/troe-moved-tree/state.txt",
        cwd,
        command_timeout,
        contains=("read-only activation complete\n",),
    )
    session.command("rm -r /vol/root/troe-moved-tree", cwd, command_timeout)
    session.command(
        "cp -r /vol/root/nested /vol/root/troe-deep", cwd, command_timeout
    )
    session.command(
        "cp -r /vol/root/nested /vol/root/troe-deep/level-one",
        cwd,
        command_timeout,
    )
    session.command(
        "cp -r /vol/root/nested /vol/root/troe-deep/level-one/level-two",
        cwd,
        command_timeout,
    )
    session.command(
        "cp -r /vol/root/troe-deep /vol/root/troe-deep-copy",
        cwd,
        command_timeout,
    )
    session.command(
        "cat /vol/root/troe-deep-copy/level-one/level-two/state.txt",
        cwd,
        command_timeout,
        contains=("read-only activation complete\n",),
    )
    session.command("rm -r /vol/root/troe-deep", cwd, command_timeout)
    session.command("rm -r /vol/root/troe-deep-copy", cwd, command_timeout)
    session.command(
        "cp -r /vol/root/nested /vol/root/troe-empty-test", cwd, command_timeout
    )
    session.command("rm /vol/root/troe-empty-test/state.txt", cwd, command_timeout)
    session.command("rmdir /vol/root/troe-empty-test", cwd, command_timeout)
    # A writable ext4 volume records a modification time, so `ls -l` gains the
    # UTC column; the read-only root stores none and omits it entirely.
    session.command(
        "printf timed > /vol/root/troe-timed",
        cwd,
        command_timeout,
    )
    listing = session.command("ls -l /vol/root/troe-timed", cwd, command_timeout)
    if not re.search(r"- +5 \d{4}-\d{2}-\d{2} \d{2}:\d{2} /vol/root/troe-timed", listing):
        raise AcceptanceError(
            f"ls -l did not report a modification time; output was {listing!r}"
        )
    root_listing = session.command("ls -l /bin/echo.kex", cwd, command_timeout)
    if re.search(r"\d{4}-\d{2}-\d{2}", root_listing):
        raise AcceptanceError(
            "the read-only root stores no time yet ls -l reported one; "
            f"output was {root_listing!r}"
        )
    session.command("rm /vol/root/troe-timed", cwd, command_timeout)
    exercise_change_and_creation_times(session, cwd, command_timeout)
    exercise_head_tail_and_mkdir(session, cwd, command_timeout)
    exercise_touch(session, cwd, command_timeout)
    session.confirmed_command(
        lua + " -e 'local ok,kind,status=os.execute(\"mv "
        "/vol/root/troe-moved.txt /vol/shared/cross-device.txt\"); "
        "print(\"mv-status\",ok,kind,status)'",
        cwd,
        command_timeout,
        contains=(
            "mv: /vol/root/troe-moved.txt: cross-device operation",
            "mv-status\tnil\texit\t1\n",
        ),
    )
    session.confirmed_command(
        lua + " -e 'local ok,kind,status=os.execute(\"cp "
        f"{MUTABLE_ROOT_FILE} /recovery/denied-copy\"); "
        "print(\"cp-readonly-status\",ok,kind,status)'",
        cwd,
        command_timeout,
        contains=("read-only filesystem", "cp-readonly-status\tnil\texit\t1\n"),
    )
    session.confirmed_command(
        lua + " -e 'local ok,kind,status=os.execute(\"rm -R /recovery\"); "
        "print(\"rm-readonly-status\",ok,kind,status)'",
        cwd,
        command_timeout,
        contains=("read-only filesystem", "rm-readonly-status\tnil\texit\t1\n"),
    )
    session.confirmed_command(
        lua + " -e 'local ok,kind,status=os.execute(\"cp "
        "/missing /vol/root/missing-copy\"); "
        "print(\"cp-missing-status\",ok,kind,status)'",
        cwd,
        command_timeout,
        contains=("cp: /missing: not found", "cp-missing-status\tnil\texit\t3\n"),
    )
    session.command("rm /vol/root/troe-moved.txt", cwd, command_timeout)
    session.command("rm /vol/root/troe-copy-soft", cwd, command_timeout)
    session.command("rm /vol/root/echo-link", cwd, command_timeout)
    session.command("rm /vol/root/echo-copy", cwd, command_timeout)
    session.command("rm /vol/root/troe-mutable-hard", cwd, command_timeout)
    session.command("rm /vol/root/troe-mutable-soft", cwd, command_timeout)
    session.command("echo alpha beta", cwd, command_timeout, contains=("alpha beta\n",))
    session.command("echo -n no-newline", cwd, command_timeout, contains=("no-newline",))
    session.command(
        r"echo -e 'one\ntwo'", cwd, command_timeout, contains=("one\ntwo\n",)
    )
    session.command(
        r"printf '%d %x\n' -42 255", cwd, command_timeout, contains=("-42 ff\n",)
    )
    session.command(
        r"printf '%#08x|%-5s|%.3s\n' 42 hi abcdef",
        cwd,
        command_timeout,
        contains=("0x00002a|hi   |abc\n",),
    )
    session.command(
        r"printf 'alpha\n\n\nbeta\n' > /tmp/text-options", cwd, command_timeout
    )
    session.command(r"printf 'a\tb\n' > /tmp/visible-options", cwd, command_timeout)
    session.command(
        "cat -ns /tmp/text-options",
        cwd,
        command_timeout,
        contains=("     1\talpha\n     2\t\n     3\tbeta\n",),
    )
    session.command(
        "cat -ET /tmp/visible-options",
        cwd,
        command_timeout,
        contains=("a^Ib$\n",),
    )
    session.command(
        "grep -in ALPHA /tmp/text-options",
        cwd,
        command_timeout,
        contains=("1:alpha\n",),
    )
    session.command(
        "grep -c a /tmp/text-options", cwd, command_timeout, contains=("2\n",)
    )
    session.command(
        r"grep -En '^(alpha|beta)$' /tmp/text-options",
        cwd,
        command_timeout,
        contains=("1:alpha\n4:beta\n",),
    )
    session.command(
        r"grep -n 'alpha\|beta' /tmp/text-options",
        cwd,
        command_timeout,
        contains=("1:alpha\n4:beta\n",),
    )
    session.command(
        "grep -Eo '[[:alpha:]]+' /tmp/text-options",
        cwd,
        command_timeout,
        contains=("alpha\nbeta\n",),
    )
    session.command(
        "grep -m 1 -e alpha -e beta /tmp/text-options",
        cwd,
        command_timeout,
        contains=("alpha\n",),
        absent=("beta\n",),
    )
    session.command(
        "spawn --status grep -F 'alpha|beta' /tmp/text-options",
        cwd,
        command_timeout,
        contains=("spawn-status: 1\n",),
    )
    session.command(
        "spawn --status grep absent /tmp/text-options",
        cwd,
        command_timeout,
        contains=("spawn-status: 1\n",),
    )
    session.command(
        "ls -1 /tmp", cwd, command_timeout, contains=("text-options\n",)
    )
    session.command(
        "ls -l /tmp", cwd, command_timeout, contains=("13 text-options\n",)
    )
    session.command(
        "ls -lh /tmp", cwd, command_timeout, contains=("13 B text-options\n",)
    )
    session.command("printf hidden > /tmp/.hidden-options", cwd, command_timeout)
    session.command(
        "ls -1 /tmp",
        cwd,
        command_timeout,
        absent=(".hidden-options\n",),
    )
    session.command(
        "ls -1A /tmp",
        cwd,
        command_timeout,
        contains=(".hidden-options\n",),
    )
    session.command(
        "ls -1F /", cwd, command_timeout, contains=("config/\n",)
    )
    session.command(
        "ls -dF /tmp",
        cwd,
        command_timeout,
        contains=("/tmp/\n",),
    )
    session.command(
        "ls -d /tmp/text-options /tmp",
        cwd,
        command_timeout,
        contains=("/tmp/text-options\n\n/tmp\n",),
    )
    session.command(
        "spawn echo nested-inherit",
        cwd,
        command_timeout,
        contains=("nested-inherit\n",),
    )
    session.command(
        "spawn --capture echo nested-pipe",
        cwd,
        command_timeout,
        contains=("nested-pipe\n",),
    )
    session.command(
        "spawn --status cat /missing",
        cwd,
        command_timeout,
        contains=("cat: /missing: not found", "spawn-status: 3\n"),
    )
    # Nested launch is bounded by depth because each level occupies one kernel
    # stack frame. Eight levels are accepted; a ninth is refused at the launch
    # boundary, whichever application launches it, and the session stays usable.
    session.command(
        'spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status echo nested-depth-eight',
        cwd,
        command_timeout,
        contains=("nested-depth-eight\n", "spawn-status: 0\n"),
        absent=("spawn-status: 1\n",),
    )
    session.command(
        'spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status echo nested-depth-nine',
        cwd,
        command_timeout,
        contains=("spawn: child launch failed", "spawn-status: 1\n"),
        absent=("nested-depth-nine\n",),
    )
    session.confirmed_command(
        lua + " -e 'print(os.execute(\"spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status spawn --status echo lua-depth-nine\"))'",
        cwd,
        command_timeout,
        contains=("spawn: child launch failed", "nil\texit\t1\n"),
        absent=("lua-depth-nine\n",),
    )
    session.command(
        "echo nested-depth-survived",
        cwd,
        command_timeout,
        contains=("nested-depth-survived\n",),
    )
    session.command(
        r"printf 'first\nsecond\t%s\n' value | grep second",
        cwd,
        command_timeout,
        contains=("second\tvalue\n",),
    )
    session.command(
        r"printf 'one two\nthree\n' | wc",
        cwd,
        command_timeout,
        contains=("2 3 14\n",),
    )
    session.command(
        "missing-logical && echo should-not-run || echo logical-fallback",
        cwd,
        command_timeout,
        contains=("missing-logical: unknown command", "logical-fallback\n"),
        absent=("should-not-run\n",),
    )
    session.command(
        "echo logical-first || echo should-not-run && echo logical-tail",
        cwd,
        command_timeout,
        contains=("logical-first\n", "logical-tail\n"),
        absent=("should-not-run\n",),
    )
    session.command(
        "echo 'quoted && literal || operators'",
        cwd,
        command_timeout,
        contains=("quoted && literal || operators\n",),
    )
    session.command(
        r"printf 'alpha beta\nbeta gamma\n' | sed 's/beta/B/g'",
        cwd,
        command_timeout,
        contains=("alpha B\nB gamma\n",),
    )
    session.command(
        r"""printf 'svc ready\njob waiting\n' | awk '$2 == "ready" { print NR, $1 }'""",
        cwd,
        command_timeout,
        contains=("1 svc\n",),
    )
    session.command("cd /vol/root", cwd, command_timeout, next_cwd="/vol/root")
    cwd = "/vol/root"
    session.command("tar -cf troe-test.tar nested", cwd, command_timeout)
    session.command(
        "tar -tf troe-test.tar",
        cwd,
        command_timeout,
        contains=("nested\n", "nested/state.txt\n"),
    )
    session.command("cd /vol/shared", cwd, command_timeout, next_cwd="/vol/shared")
    cwd = "/vol/shared"
    session.command("tar -xf /vol/root/troe-test.tar", cwd, command_timeout)
    session.command(
        "cat nested/state.txt",
        cwd,
        command_timeout,
        contains=("read-only activation complete\n",),
    )
    session.command("cd /", cwd, command_timeout, next_cwd="/")
    session.command("rm /vol/shared/echo-copy", "/", command_timeout)
    cwd = "/"
    session.command("echo alpha beta | grep beta > /tmp/result", cwd, command_timeout)
    session.command("cat /tmp/result", cwd, command_timeout, contains=("alpha beta\n",))
    session.command("pwd", cwd, command_timeout, contains=("/\n",))
    session.command("cd /man", cwd, command_timeout, next_cwd="/man")
    cwd = "/man"
    session.command("pwd", cwd, command_timeout, contains=("/man\n",))
    session.command(
        "grep bounded cat",
        cwd,
        command_timeout,
        contains=("Reads are bounded",),
    )
    session.command("cd /", cwd, command_timeout, next_cwd="/")
    cwd = "/"
    session.command("printf AB > /tmp/direct", cwd, command_timeout)
    session.command("printf CD >> /tmp/direct", cwd, command_timeout)
    session.command(
        "hexdump /tmp/direct",
        cwd,
        command_timeout,
        contains=("00000000  41 42 43 44 ",),
    )
    session.command("wc -c < /tmp/direct", cwd, command_timeout, contains=("4\n",))
    session.confirmed_command(
        lua + " -e 'print(string.rep(\"x\",70000))' > /tmp/large-stream",
        cwd,
        command_timeout,
    )
    session.command(
        "wc -c < /tmp/large-stream", cwd, command_timeout, contains=("70001\n",)
    )
    session.command("rm /tmp/large-stream", cwd, command_timeout)
    session.command("printf Q > '/tmp/quoted file'", cwd, command_timeout)
    session.command("cat '/tmp/quoted file'", cwd, command_timeout, contains=("Q",))
    session.command("rm '/tmp/quoted file'", cwd, command_timeout)
    session.command("rm /tmp/direct", cwd, command_timeout)
    session.command(
        "cat /tmp/direct",
        cwd,
        command_timeout,
        contains=("cat: /tmp/direct: not found",),
    )
    session.command(
        "cat /missing", cwd, command_timeout, contains=("cat: /missing: not found",)
    )
    session.command(
        "echo 'unterminated",
        cwd,
        command_timeout,
        contains=("parse: unclosed quote",),
    )
    session.command("pwd extra", cwd, command_timeout, contains=("pwd: pwd",))
    session.command(
        "printf nope > /recovery/motd",
        cwd,
        command_timeout,
        contains=("sh: /recovery/motd: read-only filesystem",),
    )
    session.command("rm /tmp/result", cwd, command_timeout)
    session.command(
        r"printf 'echo should-not-run\necho \"unterminated\n' > /tmp/rejected.sh",
        cwd,
        command_timeout,
    )
    session.command(
        "sh /tmp/rejected.sh",
        cwd,
        command_timeout,
        contains=("sh: line 2: command line was rejected",),
        absent=("should-not-run\n",),
    )
    session.command("rm /tmp/rejected.sh", cwd, command_timeout)
    session.command(
        r"printf 'echo stdin-script\n' | sh -",
        cwd,
        command_timeout,
        contains=("stdin-script\n",),
    )
    session.command(
        r"printf 'missing-script && echo should-not-run || echo script-fallback\n' > /tmp/logical.sh",
        cwd,
        command_timeout,
    )
    session.command(
        "sh /tmp/logical.sh",
        cwd,
        command_timeout,
        contains=("missing-script: unknown command", "script-fallback\n"),
        absent=("should-not-run\n",),
    )
    session.command("rm /tmp/logical.sh", cwd, command_timeout)
    session.command(
        r"printf 'cd /man\npwd\n' > /tmp/session.sh",
        cwd,
        command_timeout,
    )
    session.command(
        "sh /tmp/session.sh",
        cwd,
        command_timeout,
        contains=("/man\n",),
        next_cwd="/man",
    )
    cwd = "/man"
    session.command("rm /tmp/session.sh", cwd, command_timeout)
    session.command("cd /vol/shared", cwd, command_timeout, next_cwd="/vol/shared")
    cwd = "/vol/shared"
    session.command(
        "sh /share/sh/bench.sh",
        cwd,
        max(command_timeout, 180.0),
        contains=(
            "===== F00 building fixtures with printf",
            "===== W30 cross-check: awk emits 2 bytes with no newline",
            "===== S60 leading star is literal",
            "===== A80 for loop with continue and break",
            "===== R18 output fed back into the same program is stable",
            "===== END of transcript\n",
        ),
    )
    session.command("cd /", cwd, command_timeout, next_cwd="/")


def run_launch_environment_checks(
    session: SerialSession, cwd: str, command_timeout: float
) -> None:
    """Require explicit population, launcher narrowing, and no value leakage."""
    lua = shared_lua(session)
    # -E ignores Lua configuration entries while ordinary os.getenv is unchanged.
    session.confirmed_command(
        lua + " -E -e 'print(\"env-ignored\", os.getenv(\"HOME\"), "
        "package.path:find(\"/share/lua/\", 1, true) ~= nil)'",
        cwd,
        command_timeout,
        contains=("env-ignored\t/\ttrue\n",),
    )
    # A launcher narrows a child environment by replacing the inherited value of
    # the same name. HOME is inherited from the session, so appending instead of
    # replacing would produce a duplicate name, the encoding boundary would
    # refuse it, and the launch would fail. A successful launch proves
    # replacement; adding an unrelated name proves append still works.
    session.command(
        "spawn --env HOME=/override --status echo env-narrowed",
        cwd,
        command_timeout,
        contains=("env-narrowed\n", "spawn-status: 0\n"),
        absent=("child launch failed",),
    )
    session.command(
        "spawn --env TROE_EXTRA=value --status echo env-appended",
        cwd,
        command_timeout,
        contains=("env-appended\n", "spawn-status: 0\n"),
        absent=("child launch failed",),
    )
    # Delegation failures are refused before any child is created.
    session.command(
        "spawn --env HOME=/a --env HOME=/b echo unreachable",
        cwd,
        command_timeout,
        contains=("spawn: --env repeats one name",),
        absent=("unreachable",),
    )
    session.command(
        "spawn --env NOT_AN_ENTRY echo unreachable",
        cwd,
        command_timeout,
        contains=("spawn: --env requires NAME=VALUE",),
        absent=("unreachable",),
    )
    # Every launch carries an explicit zone, and the default is UTC.
    session.confirmed_command(
        lua + " -e 'print(\"env-zone\", os.getenv(\"TZ\"), "
        "os.date(\"!%Y-%m-%d %H:%M %Z\", 1784116800))'",
        cwd,
        command_timeout,
        contains=("env-zone\tUTC0\t2026-07-15 12:00 UTC\n",),
    )
    # A launcher narrowing TZ changes what local conversion means in the child.
    # 2026-07-15T12:00:00Z is 08:00 EDT and 2026-01-15T12:00:00Z is 07:00 EST,
    # so one zone proves the offset, the abbreviation, and the transition.
    session.confirmed_command(
        "spawn --env TZ=EST5EDT,M3.2.0,M11.1.0 " + lua
        + " -e 'print(\"env-local\", os.date(\"%H:%M %Z %z\", 1784116800), "
        "os.date(\"%H:%M %Z %z\", 1768478400))'",
        cwd,
        command_timeout,
        contains=("env-local\t08:00 EDT -0400\t07:00 EST -0500\n",),
    )
    # A zone that does not parse is refused before the child exists, because
    # conversion inside it could only fall back to UTC silently.
    session.command(
        "spawn --env TZ=:America/New_York echo unreachable",
        cwd,
        command_timeout,
        contains=("spawn: --env TZ names a database TROE does not carry",),
        absent=("unreachable",),
    )
    session.command(
        "spawn --env TZ=EST5EDT echo unreachable",
        cwd,
        command_timeout,
        contains=("spawn: --env TZ gives a daylight name without its rules",),
        absent=("unreachable",),
    )
    # Observation surfaces expose no environment name or value.
    session.command(
        "ps",
        cwd,
        command_timeout,
        contains=("PID ORIGIN STATE",),
        absent=("HOME=", "PATH=", "LOGNAME=", "/bin/sh"),
    )


def run_lua_group(session: SerialSession, command_timeout: float) -> None:
    """Exercise the freestanding Lua runtime, allocator, math, and loaders."""
    cwd = "/"
    lua = shared_lua(session)
    run_launch_environment_checks(session, cwd, command_timeout)
    session.confirmed_command(
        lua + " --version",
        cwd,
        command_timeout,
        contains=("Lua 5.5.1", "Lua.org, PUC-Rio"),
    )
    session.confirmed_command(
        lua + ' -e \'print("lua-inline", math.floor(math.sin(0)), '
        'string.format("%04d", 7))\'',
        cwd,
        command_timeout,
        contains=("lua-inline\t0\t0007\n",),
    )
    session.confirmed_command(
        lua + ' -e \'local ok,e=pcall(function() error("jump-ok") end); '
        'print("lua-jump", ok, type(e), e, e:match("jump%-ok") ~= nil)\'',
        cwd,
        command_timeout,
        contains=("lua-jump\tfalse\tstring\t", "jump-ok\ttrue\n"),
    )
    session.confirmed_command(
        lua + ' -e \'local a=os.clock(); local w=os.time(); local x=0; '
        'for i=1,10000 do x=x+i end; local b=os.clock(); '
        'print("lua-os",type(os),type(os.clock),b>=a,type(w),os.time()>=w,'
        'os.difftime(7,2))\'',
        cwd,
        command_timeout,
        contains=(
            "lua-os\ttable\tfunction\ttrue\tnumber\ttrue\t5.0\n",
        ),
    )
    session.confirmed_command(
        lua + " -e 'local function target() local x=0; "
        "for i=1,100 do x=x+i end end; local n=100000; "
        "local start=os.clock(); for i=1,n do end; "
        "local overhead=os.clock()-start; start=os.clock(); "
        "for i=1,n do target() end; "
        "local total=os.clock()-start-overhead; "
        "print(\"lua-clock-benchmark\",type(total),total>0)'",
        cwd,
        command_timeout,
        contains=("lua-clock-benchmark\tnumber\ttrue\n",),
        absent=("execution lease expired",),
    )
    session.confirmed_command(
        lua + " /share/lua/benchmark.lua 1 1 qemu-smoke",
        cwd,
        max(command_timeout, 180.0),
        contains=(
            "BENCHMARK version=1 label=qemu-smoke",
            "RESULT label=qemu-smoke name=integer_mix",
            "RESULT label=qemu-smoke name=floating_arithmetic",
            "RESULT label=qemu-smoke name=retained_records",
            "RESULT label=qemu-smoke name=allocation_churn",
            "END label=qemu-smoke",
        ),
        absent=(
            "not enough memory",
            "execution lease expired",
            "lua-benchmark:",
        ),
    )
    session.confirmed_command(
        lua + ' -e \'local t={year=2024,month=2,day=29,hour=1,min=2,sec=3}; '
        'local s=os.time(t); print("lua-calendar",s,'
        'os.date("!%Y-%m-%d %H:%M:%S %a %j",s),t.wday,t.yday,t.isdst)\'',
        cwd,
        command_timeout,
        contains=(
            "lua-calendar\t1709168523\t2024-02-29 01:02:03 Thu 060\t5\t60\tfalse\n",
        ),
    )
    session.confirmed_command(
        lua + " -e 'local t={year=2024,month=3,day=0}; local s=os.time(t); "
        "print(\"lua-calendar-normalize\",s,os.date(\"!%Y-%m-%d\",s),"
        "t.year,t.month,t.day)'",
        cwd,
        command_timeout,
        contains=("lua-calendar-normalize\t1709208000\t2024-02-29\t2024\t2\t29\n",),
    )
    session.confirmed_command(
        lua + " -e 'print(\"lua-floats\","
        "string.format(\"%.17g\",1.2345678901234567),"
        "string.format(\"%.17g\",0x1p-1022),"
        "string.format(\"%.17g\",0x1.fffffffffffffp+1023),"
        "string.format(\"%.2e\",1234),string.format(\"%#.4g\",9999.5))'",
        cwd,
        command_timeout,
        contains=(
            "lua-floats\t1.2345678901234567\t2.2250738585072014e-308\t"
            "1.7976931348623157e+308\t1.23e+03\t1.000e+04\n",
        ),
    )
    session.confirmed_command(
        lua + " -e 'package.preload.p=function() return 42 end; "
        "local m,w=require(\"p\"); print(\"lua-libraries\",m,w,type(debug),"
        "type(io),type(loadfile),type(dofile),collectgarbage(\"incremental\"))'",
        cwd,
        command_timeout,
        contains=(
            "lua-libraries\t42\t:preload:\ttable\ttable\tfunction\tfunction\tgenerational\n",
        ),
    )
    session.confirmed_command(
        lua + " -E -e 'package.preload.p=function() return 40 end' "
        "-l m=p -e 'print(\"lua-options\",m+2)'",
        cwd,
        command_timeout,
        contains=("lua-options\t42\n",),
    )
    session.confirmed_command(
        lua + " -e 'package.preload[\"plain-v1\"]=function() return 42 end' "
        "-l plain-v1 -e 'print(\"lua-option-plain\",plain)'",
        cwd,
        command_timeout,
        contains=("lua-option-plain\t42\n",),
    )
    session.confirmed_command(
        lua + " -W -e 'warn(\"cli-warning\")'",
        cwd,
        command_timeout,
        contains=("Lua warning: cli-warning",),
    )
    session.confirmed_command(
        lua + " -e 'local f=assert(io.open(\"/tmp/lua-chunk.luac\",\"w\")); "
        "f:write(string.dump(function() print(\"lua-bytecode-file\",42) end)); "
        "f:close()'",
        cwd,
        command_timeout,
    )
    session.confirmed_command(
        lua + " /tmp/lua-chunk.luac",
        cwd,
        command_timeout,
        contains=("lua-bytecode-file\t42\n",),
    )
    session.command("rm /tmp/lua-chunk.luac", cwd, command_timeout)
    session.confirmed_command(
        lua + " -e 'pcall(function() os.exit(7) end); "
        "print(\"lua-exit-caught\")'",
        cwd,
        command_timeout,
        absent=("lua-exit-caught",),
    )
    session.confirmed_command(
        lua + " -e 'local value <close> = setmetatable({}, "
        "{__close=function() print(\"lua-exit-closed\") end}); "
        "os.exit(0,false); print(\"lua-exit-after\")'",
        cwd,
        command_timeout,
        absent=("lua-exit-closed", "lua-exit-after"),
    )
    session.confirmed_command(
        lua + " -e 'local value <close> = setmetatable({}, "
        "{__close=function() print(\"lua-exit-closed\") end}); "
        "os.exit(0,true); print(\"lua-exit-after\")'",
        cwd,
        command_timeout,
        contains=("lua-exit-closed\n",),
        absent=("lua-exit-after",),
    )
    session.confirmed_command(
        r"""printf 'print("lua-stdin", 6*7)\n' | """ + lua + " -",
        cwd,
        command_timeout,
        contains=("lua-stdin\t42\n",),
        program=lua,
    )
    session.command(
        "printf 'local a,b=...; print(\"lua-args\",arg[-1],arg[0],"
        "arg[1],arg[2],select(\"#\",...),a,b)\\n' > /tmp/lua-args.lua",
        cwd,
        command_timeout,
    )
    session.confirmed_command(
        lua + " /tmp/lua-args.lua first second",
        cwd,
        command_timeout,
        contains=(
            "lua-args\t" + lua + "\t/tmp/lua-args.lua"
            "\tfirst\tsecond\t2\tfirst\tsecond\n",
        ),
    )
    session.command("rm /tmp/lua-args.lua", cwd, command_timeout)
    session.confirmed_command(
        lua + " /recovery/lua-smoke.lua hello",
        cwd,
        command_timeout,
        contains=("lua-file:hello sum=1250025000 sqrt=9 pow=1024",),
    )
    session.confirmed_command(
        lua + " /share/lua/examples/language.lua",
        cwd,
        command_timeout,
        contains=(
            "hello, TROE!",
            "match=8..11 upper=HELLO, TROE!",
            "packed=4 bytes values=-123,456",
            "utf8=1 codepoint, 2 bytes, U+03BB",
            "task 1: network (priority 3)",
            "vector sum: (7, 10)",
            "square(4)=16",
        ),
    )
    session.confirmed_command(
        lua + " /share/lua/examples/numbers.lua",
        cwd,
        command_timeout,
        contains=(
            " 90 degrees: sin= 1.000000 cos= 0.000000",
            "mean=5.00 standard-deviation=2.00",
            "2^10=1024 log2(1024)=10 gcd(84,30)=6",
            "random distribution\tsamples=60000 min=1 max=6 average/mean=",
            "expected-mean=3.5000 standard-deviation=",
            "random bucket range\tmin=",
            " expected=10000 max-deviation=",
            "random uniformity\tpass\tsamples=60000\n",
            "random choice\t",
            "random shuffle\t",
            "random checks\tok\t5\ttrue\n",
            "random source\tkernel CSPRNG seed -> Lua math PRNG\n",
            "random caveat\tuniformity is evidence, not proof or cryptographic safety\n",
        ),
    )
    session.confirmed_command(
        lua + " /share/lua/examples/system.lua",
        cwd,
        command_timeout,
        contains=(
            "lua-system libraries\ttable\ttable\ttable\n",
            "lua-system date\t2024-02-29 Thursday\n",
            "lua-system file\talpha,beta,gamma\n",
            "lua-system module\t42\t/tmp/lua-system-module.lua\n",
            "lua-system bytecode\t1414680389\tmain\n",
            "lua execute\n",
            "lua-system process\tlua-popen\n",
            "lua-system environment\t/bin /\n",
            "lua-system cleanup\ttrue\ttrue\n",
        ),
    )
    session.confirmed_command(
        lua + " -e 'local p=assert(io.popen(\"wc -c\",\"w\")); "
        "assert(p:write(\"12345\")); print(p:close())'",
        cwd,
        command_timeout,
        contains=("5\n", "true\texit\t0\n"),
    )
    session.confirmed_command(
        lua + " -e 'local p=assert(io.popen(\"cat /share/sh/bench.sh\",\"r\")); "
        "local data=assert(p:read(\"a\")); local ok=assert(p:close()); "
        "print(\"lua-popen-all\",#data,data:match(\"postests%.sh\")~=nil)'",
        cwd,
        command_timeout,
        contains=("lua-popen-all\t24980\ttrue\n",),
    )
    session.confirmed_command(
        lua + " -e 'local path=\"/tmp/lua-unbuffered\"; "
        "local w=assert(io.open(path,\"w\")); assert(w:setvbuf(\"no\")); "
        "assert(w:write(\"visible\")); local r=assert(io.open(path,\"r\")); "
        "print(\"lua-setvbuf\",r:read(\"a\")); r:close(); w:close(); "
        "assert(os.remove(path))'",
        cwd,
        command_timeout,
        contains=("lua-setvbuf\tvisible\n",),
    )
    session.confirmed_command(
        lua + " -e 'local t={}; local n=0; for i=1,6144 do "
        'local s=string.rep("x",1024); t[i]=s; n=n+#s end; '
        'print("lua-grow",#t,n)\'',
        cwd,
        command_timeout,
        contains=("lua-grow\t6144\t6291456\n",),
    )
    session.confirmed_command(
        lua + " -e 'local s=string.rep(\"x\",48*1024*1024); "
        "print(\"lua-large-private\",#s); s=nil; collectgarbage()'",
        cwd,
        command_timeout,
        contains=("lua-large-private\t50331648\n",),
        absent=("not enough memory", "execution lease expired"),
    )
    session.confirmed_command(
        lua + " -e 'local a,b=math.randomseed(); local r=math.random(); "
        "print(\"lua-random\",type(a),type(b),r>=0,r<1)'",
        cwd,
        command_timeout,
        contains=("lua-random\tnumber\tnumber\ttrue\ttrue\n",),
    )
    session.confirmed_command(
        lua + " -e 'error(\"expected-error\")'",
        cwd,
        command_timeout,
        contains=("expected-error", "stack traceback:"),
    )
    session.confirmed_command(
        lua + " -e 'local ok=pcall(function() "
        'string.rep("x",16*1024*1024*1024) end); collectgarbage(); '
        'print("lua-oom",ok)\'',
        cwd,
        command_timeout,
        contains=("lua-oom\tfalse\n",),
    )


def install_cpython_media(path: Path) -> None:
    """Install the built interpreter package, fixtures, and negative variants."""
    for tree in (CPYTHON_PACKAGE_TREE, CPYTHON_DIAGNOSTICS_TREE):
        if not (tree / "MANIFEST.sha256").is_file():
            raise AcceptanceError(
                f"CPython acceptance needs {tree}; build it with "
                "tools/build_cpython.py build and tools/build_cpython.py variants"
            )
    builder = str(REPO_ROOT / "tools" / "build_cpython.py")
    for action, source in (
        ("install-image", CPYTHON_PACKAGE_TREE),
        ("install-diagnostics", CPYTHON_DIAGNOSTICS_TREE),
        ("install-packages", CPYTHON_FIXTURES),
    ):
        subprocess.run(
            [sys.executable, builder, action, str(source), "--image", str(path)],
            cwd=REPO_ROOT,
            check=True,
        )


def run_cpython_repl(session: SerialSession, cwd: str, python: str, timeout: float) -> None:
    """Evaluate typed statements through the foreground terminal-input loan."""
    submitted = session.send(python, timeout)
    marker = f"Run untrusted application '{python}' outside /bin? [y/N] ".encode()
    session.wait_for(marker, timeout, submitted)
    answered = session.send("y", timeout)
    banner = session.wait_for(b">>> ", timeout, answered)
    rendered = normalize(bytes(session.output[answered:banner]))
    if "Python 3.14.7" not in rendered or "troe" not in rendered:
        raise AcceptanceError(f"CPython REPL banner was unexpected: {rendered!r}")
    for statement, expected in (
        ('print("cpy" + "-repl", 6 * 7)', "cpy-repl 42"),
        ("value = 1 << 70", None),
        ('print("cpy" + "-state", value)', "cpy-state 1180591620717411303424"),
        ('print("cpy" + "-error", 1 / 0)', "ZeroDivisionError"),
        ("print(repr(exit))", "Ctrl-D"),
    ):
        start = len(session.output)
        session.send(statement, timeout)
        end = session.wait_for(b">>> ", timeout, start)
        if expected is None:
            continue
        rendered = normalize(bytes(session.output[start:end]))
        if expected not in rendered:
            raise AcceptanceError(
                f"CPython REPL did not evaluate {statement!r}: {rendered!r}"
            )
    # `site` is not imported, so `exit` is never injected. End of input is the
    # terminal contract's own exit and it must return the loan to the shell.
    if session.process.stdin is None:
        raise AcceptanceError("QEMU serial input is unavailable")
    start = len(session.output)
    session.process.stdin.write(b"\x04")
    session.process.stdin.flush()
    session.wait_for(f"sh:{cwd}> ".encode(), timeout, start)


def run_cpython_group(session: SerialSession, command_timeout: float) -> None:
    """Exercise the shared-volume CPython package, its profile, and its limits."""
    cwd = "/"
    timeout = command_timeout * CPYTHON_TIMEOUT_SCALE
    binaries = f"{CPYTHON_SHARED_BIN}/{session.architecture}"
    packages = f"{CPYTHON_SHARED_LIB}/{session.architecture}/packages"
    diagnostics = f"{CPYTHON_DIAGNOSTICS_ROOT}/{session.architecture}/bin"
    python = f"{binaries}/python.kex"
    no_random = f"{diagnostics}/python-no-random.kex"
    no_mutate = f"{diagnostics}/python-no-mutate.kex"
    stdlib = f"{CPYTHON_SHARED_LIB}/{session.architecture}/python3.14.7/python3.14"

    # Shared-volume interpreters stay subject to the explicit-path execution
    # gate; declining must not start the interpreter at all.
    session.declined_command(f"{python} --version", cwd, timeout, absent=("Python 3.",))

    # The default alias and every version-addressable executable stay distinct.
    for name, expected in (
        ("python.kex", "Python 3.14.7"),
        ("python3.kex", "Python 3.14.7"),
        ("python3.14.kex", "Python 3.14.7"),
        ("python3.13.kex", "Python 3.13.15"),
        ("python3.12.kex", "Python 3.12.14"),
    ):
        session.confirmed_command(
            f"{binaries}/{name} --version", cwd, timeout, contains=(f"{expected}\n",)
        )

    # Command-line modes: inline code, arguments, script, module, and stdin.
    session.confirmed_command(
        f"""{python} -c 'print("cpy-inline", 6 * 7)'""",
        cwd,
        timeout,
        contains=("cpy-inline 42\n",),
    )
    session.confirmed_command(
        f"""{python} -c 'import sys; print("cpy-argv", sys.argv[1:])' -- -x""",
        cwd,
        timeout,
        contains=("cpy-argv ['--', '-x']\n",),
    )

    # CPython reaches the timezone rules through the C runtime's `localtime_r`,
    # `mktime`, and `strftime`, which nothing else in this suite executes. Both
    # instants sit far from a transition so the readings are exact, and the
    # zone is narrowed by the launcher rather than read from any ambient state.
    # 2026-07-15T12:00:00Z is 08:00 EDT and 2026-01-15T12:00:00Z is 07:00 EST.
    session.confirmed_command(
        "spawn --env TZ=EST5EDT,M3.2.0,M11.1.0 " + python
        + """ -c 'import time; s=1784116800; w=1768478400; """
        + """print("cpy-zone", time.strftime("%H:%M %Z %z", time.localtime(s)), """
        + """time.strftime("%H:%M %Z %z", time.localtime(w)))'""",
        cwd,
        timeout,
        contains=("cpy-zone 08:00 EDT -0400 07:00 EST -0500\n",),
    )
    # `mktime` reads a broken-down time as local, so it inverts `localtime`,
    # while `gmtime` stays UTC and does not move with the zone.
    session.confirmed_command(
        "spawn --env TZ=EST5EDT,M3.2.0,M11.1.0 " + python
        + """ -c 'import time; s=1784116800; """
        + """print("cpy-mktime", int(time.mktime(time.localtime(s))), """
        + """time.gmtime(s).tm_hour, time.localtime(s).tm_gmtoff)'""",
        cwd,
        timeout,
        contains=("cpy-mktime 1784116800 12 -14400\n",),
    )
    # An unconfigured zone is UTC, and `-u`-style UTC reads never move.
    session.confirmed_command(
        f"""{python} -c 'import time; print("cpy-utc", """
        + """time.strftime("%H:%M %Z %z", time.localtime(1784116800)))'""",
        cwd,
        timeout,
        contains=("cpy-utc 12:00 UTC +0000\n",),
    )
    session.confirmed_command(
        f"{python} {packages}/script_probe.py one two",
        cwd,
        timeout,
        contains=("script-probe ['one', 'two']\n",),
    )
    session.confirmed_command(
        f"{python} -m troe_fixture",
        cwd,
        timeout,
        contains=("module-probe pure-package-on-shared-volume 42\n",),
    )
    session.confirmed_command(
        f"{python} - < {packages}/script_probe.py",
        cwd,
        timeout,
        contains=("script-probe []\n",),
    )
    session.confirmed_command(
        f"""{python} -c 'print("cpy" + "-quit", callable(exit), callable(quit))'""",
        cwd,
        timeout,
        contains=("cpy-quit True True\n",),
    )
    run_cpython_repl(session, cwd, python, timeout)

    # Language semantics, the shipped library profile, and TROE-backed services.
    session.confirmed_command(
        f"{python} {packages}/language_probe.py",
        cwd,
        timeout,
        contains=("language-probe troe 3.14.7\n",),
    )
    session.confirmed_command(
        f"{python} {packages}/stdlib_probe.py",
        cwd,
        timeout,
        contains=("stdlib-probe 22 1 True\n",),
    )
    # Every module the profile ships must actually import; a shipped module
    # that raises ModuleNotFoundError is a manifest defect, not a limitation.
    session.confirmed_command(
        f"{python} {packages}/profile_probe.py",
        cwd,
        timeout * 4,
        contains=("profile-probe ",),
        absent=("profile-failures",),
    )
    session.confirmed_command(
        f"{python} {packages}/runtime_probe.py",
        cwd,
        timeout,
        contains=("runtime-probe 32 /vol/shared\n",),
    )
    session.confirmed_command(
        f"{python} {packages}/negative_probe.py",
        cwd,
        timeout,
        contains=("negative-probe 10 ",),
    )

    # The interpreter tree stays free of bytecode written during acceptance, so
    # a read-only standard library remains fully usable.
    session.command(
        f"ls {stdlib}/__pycache__",
        cwd,
        command_timeout,
        contains=(f"ls: {stdlib}/__pycache__: not found",),
    )

    # Missing authority fails explicitly instead of degrading or inventing data.
    # Withheld entropy authority stops interpreter initialization outright, so
    # no code runs on weak seeding regardless of the requested action.
    entropy_failure = "initialization failed: failed to get random numbers"
    session.confirmed_command(
        f"""{no_random} -c 'import os; print("cpy" + "-entropy", os.urandom(4))'""",
        cwd,
        timeout,
        contains=(entropy_failure,),
        absent=("cpy-entropy",),
    )
    # Argument handling that precedes interpreter startup still answers, which
    # keeps the failure attributable to initialization rather than the loader.
    session.confirmed_command(
        f"{no_random} --version", cwd, timeout, contains=("Python 3.14.7\n",)
    )
    session.confirmed_command(
        f"""{no_mutate} -c 'open("/vol/shared/no.txt", "w"); print("cpy" + "-write")'""",
        cwd,
        timeout,
        contains=("PermissionError: [Errno 13] permission denied",),
        absent=("cpy-write",),
    )

    # Repeated successful and failing launches return every accounted resource.
    baseline = parse_free_frames(session.command("mem", cwd, command_timeout))
    for _ in range(3):
        session.confirmed_command(
            f"""{python} -c 'print("cpy-cycle", sum(range(1000)))'""",
            cwd,
            timeout,
            contains=("cpy-cycle 499500\n",),
        )
        session.confirmed_command(f"""{python} -c 'raise SystemExit(3)'""", cwd, timeout)
    recovered = parse_free_frames(session.command("mem", cwd, command_timeout))
    if recovered != baseline:
        raise AcceptanceError(
            f"CPython launches did not return kernel frames: {baseline} -> {recovered}"
        )


def run_quota_memory_group(session: SerialSession, command_timeout: float) -> None:
    """Exercise the RAMFS quota and bounded transient-allocation accounting."""
    cwd = "/"
    first_memory = session.command(
        "mem --self-test",
        cwd,
        command_timeout,
        contains=("memory-self-test ok image=0x", "quantum="),
    )
    second_memory = session.command(
        "mem --self-test",
        cwd,
        command_timeout,
        contains=("memory-self-test ok image=0x", "quantum="),
    )
    first_image = re.search(r"image=(0x[0-9a-f]+)", first_memory)
    second_image = re.search(r"image=(0x[0-9a-f]+)", second_memory)
    if first_image is None or second_image is None or first_image.group(1) == second_image.group(1):
        raise AcceptanceError(
            "independent KEX launches did not demonstrate randomized image placement: "
            f"{first_memory!r} / {second_memory!r}"
        )
    for index in range(128):
        session.command(f"printf x > /tmp/q{index:03}", cwd, command_timeout)
    session.command(
        "printf x > /tmp/q128",
        cwd,
        command_timeout,
        contains=("sh: /tmp/q128: filesystem quota exceeded",),
    )
    session.command("rm /tmp/q000", cwd, command_timeout)
    session.command("printf ok > /tmp/recovered", cwd, command_timeout)
    session.command("cat /tmp/recovered", cwd, command_timeout, contains=("ok",))
    # Return the recovered directory slot before the transient create/remove
    # cycle below; otherwise the test itself keeps the 128-entry quota full.
    session.command("rm /tmp/recovered", cwd, command_timeout)

    # Fill the configured volatile history ring with the same workload shape
    # used below before taking a heap baseline. Otherwise bounded history growth
    # is indistinguishable from a transient-allocation leak in this assertion.
    for _ in range(16):
        session.command(
            "echo allocation-cycle | grep cycle",
            cwd,
            command_timeout,
            contains=("allocation-cycle\n",),
        )
        session.command("printf stable > /tmp/cycle", cwd, command_timeout)
        session.command("rm /tmp/cycle", cwd, command_timeout)

    # The first report refreshes the retained /sys/memory payload (whose text
    # length changes when accounting fields gain digits); measure the second
    # identical command so that retained observability data is already stable.
    session.command("mem", cwd, command_timeout)
    report = session.command(
        "mem",
        cwd,
        command_timeout,
        contains=(
            f"arch: {session.architecture}",
            "memory owner: kernel",
            "memory map: final map (owned)",
            "ramfs limit: 1048576",
            "pressure: normal (RAMFS policy only)",
        ),
        absent=("firmware", "advisory", "unavailable"),
    )
    baseline_heap = parse_owned_memory_accounting(report)

    for _ in range(16):
        session.command(
            "echo allocation-cycle | grep cycle",
            cwd,
            command_timeout,
            contains=("allocation-cycle\n",),
        )
        session.command("printf stable > /tmp/cycle", cwd, command_timeout)
        session.command("rm /tmp/cycle", cwd, command_timeout)
    session.command("mem", cwd, command_timeout)
    final_report = session.command(
        "mem",
        cwd,
        command_timeout,
        contains=("memory owner: kernel", "memory map: final map (owned)"),
        absent=("firmware", "advisory", "unavailable"),
    )
    final_heap = parse_owned_memory_accounting(final_report)
    # /sys/memory retains its own formatted report. Counter and high-water
    # fields can gain digits during this serial workload, so allow only a small
    # bounded observability-payload drift while still rejecting allocation
    # leaks from the repeated create/dispatch/remove operations.
    max_observability_drift = 64
    if final_heap > baseline_heap + max_observability_drift:
        raise AcceptanceError(
            f"owned heap grew across repeated transient workloads: "
            f"{baseline_heap} -> {final_heap} bytes"
        )


def run_scenario(
    session: SerialSession,
    boot_timeout: float,
    command_timeout: float,
    tcp_port: int,
    scenario_groups: frozenset[str] = DEFAULT_SCENARIOS,
) -> None:
    """Run selected groups in the same order used by exhaustive acceptance."""
    session.wait_for(b"sh:/> ", boot_timeout)
    assert_owned_boot(session)
    if "boot" in scenario_groups:
        run_boot_group(session, command_timeout)
    if "network" in scenario_groups:
        run_network_group(session, command_timeout, tcp_port)
    if "shell-terminal" in scenario_groups:
        run_shell_terminal_group(session, command_timeout)
    if "filesystem" in scenario_groups:
        run_filesystem_group(session, command_timeout)
    if "cpython" in scenario_groups:
        run_cpython_group(session, command_timeout)
    if "lua" in scenario_groups:
        run_lua_group(session, command_timeout)
    if "shell-terminal" in scenario_groups:
        session.command("clear", "/", command_timeout, raw_contains=(b"\x1b[2J",))
    if "quota-memory" in scenario_groups:
        run_quota_memory_group(session, command_timeout)
    request_poweroff(session, command_timeout)


def run_smoke_scenario(
    session: SerialSession, boot_timeout: float, command_timeout: float, tcp_port: int
) -> None:
    """Exercise the interactive console path without the exhaustive quota workload."""
    session.wait_for(b"sh:/> ", boot_timeout)
    assert_owned_boot(session)
    cwd = "/"
    assert_storage_report(session, cwd, command_timeout)
    session.command(
        "svc status timesync",
        cwd,
        command_timeout,
        contains=("timesync ready",),
    )
    session.command(
        "echo application-ready",
        cwd,
        command_timeout,
        contains=("application-ready\n",),
    )
    session.command(
        "net",
        cwd,
        command_timeout,
        contains=("link: ready", "ipv4: 10.0.2.15", "gateway: 10.0.2.2"),
    )
    session.command(
        "dhcp",
        cwd,
        command_timeout,
        contains=("ipv4: 10.0.2.15", "lease:"),
    )
    session.command(
        "ping 10.0.2.2",
        cwd,
        command_timeout,
        contains=("reply from 10.0.2.2", "bytes=9"),
    )
    session.command(
        "net stats",
        cwd,
        command_timeout,
        contains=("rx frames:", "arp entries:", "checkpoints:"),
    )
    session.command("arp", cwd, command_timeout, contains=("10.0.2.2",))
    session.command(
        "sleep 5000",
        cwd,
        command_timeout,
        absent=("sleep: application rejected", "sleep: operation timed out"),
    )
    session.cancelled_command("sleep 86400000", cwd, command_timeout)
    session.command(
        "udp send --source-port 40001 10.0.2.2 9 application-datagram",
        cwd,
        command_timeout,
        contains=("sent 20 bytes from port 40001 to 10.0.2.2:9",),
    )
    session.cancelled_command("udp listen 40000", cwd, command_timeout)
    session.command("net stats", cwd, command_timeout, contains=("udp ports: 1",))
    session.command(
        "udp listen 40002",
        cwd,
        command_timeout,
        contains=("udp: operation timed out",),
    )
    session.command("net stats", cwd, command_timeout, contains=("udp ports: 1",))
    session.command(
        f"tcp 10.0.2.2 {tcp_port} troe-tcp-request",
        cwd,
        command_timeout,
        contains=("troe-tcp-reply\n",),
    )
    session.backspace_command(
        "echo brokeX", "n", cwd, command_timeout, expected="\nbroken\n"
    )
    session.edited_command(
        "echo ac", b"\x1b[D", "b", cwd, command_timeout, expected="\nabc\n"
    )
    session.command(
        "echo history-ready", cwd, command_timeout, contains=("history-ready\n",)
    )
    session.edited_command(
        "", b"\x1b[A", "", cwd, command_timeout, expected="\nhistory-ready\n"
    )
    session.edited_command("pw", b"\t", "", cwd, command_timeout, expected="\n/\n")
    session.command("clear", cwd, command_timeout, raw_contains=(b"\x1b[2J",))
    session.command(
        "echo qemu-smoke | grep smoke",
        cwd,
        command_timeout,
        contains=("qemu-smoke\n",),
    )
    session.command(
        r"printf 'escape\nready\n' | grep ready",
        cwd,
        command_timeout,
        contains=("ready\n",),
    )
    report = session.command(
        "mem",
        cwd,
        command_timeout,
        contains=(
            f"arch: {session.architecture}",
            "memory owner: kernel",
            "memory map: final map (owned)",
        ),
        absent=("firmware", "advisory", "unavailable"),
    )
    parse_owned_memory_accounting(report)
    request_poweroff(session, command_timeout)


def request_poweroff(session: SerialSession, command_timeout: float) -> None:
    """Apply the selected platform's proven soft-off or parked policy."""
    marker = b"poweroff: requesting soft off"
    if session.platform_id == X86_64_UEFI_VIRTIO_PCI:
        session.parked_command("poweroff", marker, command_timeout)
    else:
        session.terminal_command("poweroff", marker, command_timeout)


def run_reboot_scenario(
    session: SerialSession,
    boot_timeout: float,
    command_timeout: float,
    *,
    verify_mutable_root: bool = False,
    verify_shared_media: bool = False,
) -> None:
    """Require the native reset request to terminate QEMU under -no-reboot."""
    session.wait_for(b"sh:/> ", boot_timeout)
    assert_owned_boot(session)
    if verify_mutable_root:
        session.command(
            f"cat {MUTABLE_ROOT_FILE}",
            "/",
            command_timeout,
            contains=(MUTABLE_ROOT_CONTENT,),
        )
        session.command(f"rm {MUTABLE_ROOT_FILE}", "/", command_timeout)
    if verify_shared_media:
        session.command(
            f"cat {SHARED_FILE}",
            "/",
            command_timeout,
            contains=(SHARED_CONTENT,),
        )
        session.command(f"rm {SHARED_FILE}", "/", command_timeout)
    session.terminal_command(
        "reboot", b"reboot: requesting cold reset", command_timeout
    )


def run_native_keyboard_scenario(args: argparse.Namespace) -> None:
    """Drive the q35 i8042 path independently of serial input."""
    command = prepare_qemu_command(
        X86_64_Q35_UEFI,
        args.environment,
        args.firmware_code,
        args.firmware_vars,
        skip_version_check=args.skip_version_check,
        strict_tool_versions=args.strict_tool_versions,
        build=False,
        acceptance_probes=False,
        framebuffer=args.framebuffer_console,
        data_disks=(
            shared_test_image_path(resolve_platform(X86_64_Q35_UEFI)),
        ),
    )
    # Keep this below macOS's short AF_UNIX path limit even when TMPDIR points
    # into a deeply nested per-user directory.
    with tempfile.TemporaryDirectory(prefix="qemu-monitor-", dir="/tmp") as directory:
        monitor_path = str(Path(directory) / "qemu.sock")
        monitor_index = command.index("-monitor") + 1
        command[monitor_index] = f"unix:{monitor_path},server=on,wait=off"
        session = SerialSession(command, X86_64_Q35_UEFI)
        monitor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            deadline = time.monotonic() + args.boot_timeout
            while True:
                try:
                    monitor.connect(monitor_path)
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    status = session.process.poll()
                    if status is not None:
                        raise AcceptanceError(
                            f"QEMU exited with status {status} before its monitor was ready"
                        )
                    if time.monotonic() >= deadline:
                        raise AcceptanceError("timed out connecting to QEMU monitor")
                    time.sleep(0.01)

            session.wait_for(b"sh:/> ", args.boot_timeout)
            keys = (
                ("e", b"e"),
                ("c", b"c"),
                ("h", b"h"),
                ("o", b"o"),
                ("spc", b" "),
                ("p", b"p"),
                ("s", b"s"),
                ("2", b"2"),
                ("minus", b"-"),
                ("r", b"r"),
                ("e", b"e"),
                ("a", b"a"),
                ("d", b"d"),
                ("y", b"y"),
            )
            for key, echoed in keys:
                start = len(session.output)
                monitor.sendall(f"sendkey {key}\n".encode())
                session.wait_for(echoed, args.command_timeout, start)
            start = len(session.output)
            monitor.sendall(b"sendkey ret\n")
            session.wait_for(b"ps2-ready\n", args.command_timeout, start)
            session.wait_for(b"sh:/> ", args.command_timeout, start)
        except Exception:
            print("--- x86_64 native keyboard transcript ---", file=sys.stderr)
            print(session.transcript(), file=sys.stderr)
            raise
        finally:
            monitor.close()
            session.close()


def run_fault_scenario(
    session: SerialSession,
    boot_timeout: float,
    command_timeout: float,
    fault: str,
) -> None:
    """Prove that one forbidden access reaches the native fatal vector."""
    session.wait_for(b"sh:/> ", boot_timeout)
    assert_owned_boot(session)
    assert_ipc_baseline(session)
    if "native persistence: committed and flushed" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not complete the native TXSLOT transaction"
        )
    if "native content: selected ext4 CSPK verified" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not verify selected ext4 content"
        )
    if "native identity: generation snapshot verified" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not validate generation-bound identity metadata"
        )
    if "native statefs: mutation committed and flushed" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not commit persistent filesystem mutation"
        )
    if "native network: UDP host exchange complete" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not complete the native UDP host exchange"
        )
    session.command(
        "hexdump /vol/state/state.bin",
        "/",
        command_timeout,
        contains=("00000000  ",),
    )
    if fault == "write":
        session.command(
            "service-probe fault",
            "/",
            command_timeout,
            contains=(
                "mem: diagnostics unavailable",
                "isolated diagnostics server fault contained",
            ),
        )
        session.command(
            "mem",
            "/",
            command_timeout,
            contains=("memory owner: kernel", "memory map: final map (owned)"),
        )
    start = len(session.output)
    command = "task-probe guard" if fault == "guard" else f"mmu-probe {fault}"
    session.send(command, command_timeout)
    if fault == "exception":
        expected = b"fault: native exception\n"
    elif fault == "fatal":
        expected = b"fatal: acceptance post-handoff failure\n"
    elif fault in ("write", "execute"):
        expected = f"fault: {fault} permission violation\n".encode()
    else:
        expected = b"fault: write permission violation\n"
    marker_end = session.wait_for(expected, command_timeout, start)
    session.assert_terminal(marker_end, min(command_timeout, 1.0))


def test_platform(
    platform_id: str,
    args: argparse.Namespace,
) -> None:
    scenario_groups = selected_scenarios(args)
    command = prepare_qemu_command(
        platform_id,
        args.environment,
        args.firmware_code,
        args.firmware_vars,
        skip_version_check=args.skip_version_check,
        strict_tool_versions=args.strict_tool_versions,
        build=False,
        acceptance_probes=False,
        framebuffer=args.framebuffer_console,
        data_disks=(shared_test_image_path(resolve_platform(platform_id)),),
    )
    network_selected = args.smoke or "network" in scenario_groups
    tcp_peer = (
        TcpAcceptancePeer(platform_id, args.environment) if network_selected else None
    )
    if tcp_peer is not None:
        tcp_peer.start()
    session = SerialSession(command, platform_id)
    try:
        tcp_port = resolve_runner(platform_id, args.environment).acceptance_udp_port
        if args.smoke:
            run_smoke_scenario(
                session, args.boot_timeout, args.command_timeout, tcp_port
            )
        else:
            run_scenario(
                session,
                args.boot_timeout,
                args.command_timeout,
                tcp_port,
                scenario_groups,
            )
        if (
            args.framebuffer_console
            and b"Starting console and framebuffer" not in session.output
        ):
            raise AcceptanceError(
                f"{platform_id} did not activate the owned framebuffer text console"
            )
    except Exception:
        print(f"--- {platform_id} QEMU transcript ---", file=sys.stderr)
        print(session.transcript(), file=sys.stderr)
        print(f"raw tail: {bytes(session.output[-256:])!r}", file=sys.stderr)
        raise
    finally:
        session.close()
        if tcp_peer is not None:
            tcp_peer.close()
    if tcp_peer is not None and tcp_peer.error is not None:
        raise AcceptanceError(
            f"{platform_id} TCP acceptance peer failed: {tcp_peer.error}"
        )
    expected_tcp_streams = 1 if args.smoke else 5
    if tcp_peer is not None and tcp_peer.received != expected_tcp_streams:
        raise AcceptanceError(
            f"{platform_id} TCP acceptance peer received "
            f"{tcp_peer.received} streams, expected {expected_tcp_streams}"
        )
    if args.smoke or scenario_groups.intersection(("filesystem", "persistence")):
        reboot_session = SerialSession(command, platform_id)
        try:
            run_reboot_scenario(
                reboot_session,
                args.boot_timeout,
                args.command_timeout,
                verify_mutable_root=not args.smoke and "filesystem" in scenario_groups,
                verify_shared_media=not args.smoke
                and "filesystem" in scenario_groups,
            )
        except Exception:
            print(f"--- {platform_id} reboot transcript ---", file=sys.stderr)
            print(reboot_session.transcript(), file=sys.stderr)
            raise
        finally:
            reboot_session.close()

    if "fault-isolation" in scenario_groups:
        network_peer = UdpAcceptancePeer(platform_id, args.environment)
        network_peer.start()
        try:
            for expected_generation, fault in enumerate(
                ("write", "execute", "guard", "exception", "fatal"), start=2
            ):
                command = prepare_qemu_command(
                    platform_id,
                    args.environment,
                    args.firmware_code,
                    args.firmware_vars,
                    skip_version_check=args.skip_version_check,
                    strict_tool_versions=args.strict_tool_versions,
                    build=False,
                    acceptance_probes=True,
                    framebuffer=args.framebuffer_console,
                )
                fault_session = SerialSession(command, platform_id)
                try:
                    run_fault_scenario(
                        fault_session,
                        args.boot_timeout,
                        args.command_timeout,
                        fault,
                    )
                    if expected_generation == 2 and (
                        "native generation: candidate published"
                        not in fault_session.transcript()
                        or "native generation: health rollback committed"
                        not in fault_session.transcript()
                    ):
                        raise AcceptanceError(
                            f"{platform_id} did not exercise health rollback"
                        )
                except Exception:
                    print(
                        f"--- {platform_id} {fault} fault transcript ---",
                        file=sys.stderr,
                    )
                    print(fault_session.transcript(), file=sys.stderr)
                    raise
                finally:
                    fault_session.close()
                actual_generation, payload = txslot_state(platform_id)
                if actual_generation != expected_generation:
                    raise AcceptanceError(
                        f"{platform_id} TXSLOT recovered generation "
                        f"{actual_generation}, expected {expected_generation}"
                    )
                assert_rolled_back_sact(platform_id, payload)
                state_generation, counter = statefs_counter(platform_id)
                expected_state = expected_generation - 1
                if state_generation != expected_state or counter != expected_state:
                    raise AcceptanceError(
                        f"{platform_id} statefs recovered generation "
                        f"{state_generation} and counter {counter}, "
                        f"expected {expected_state}"
                    )
        finally:
            network_peer.close()
        if network_peer.error is not None:
            raise AcceptanceError(
                f"{platform_id} UDP acceptance peer failed: {network_peer.error}"
            )
        if network_peer.received != 5:
            raise AcceptanceError(
                f"{platform_id} UDP acceptance peer received "
                f"{network_peer.received} probes, expected 5"
            )
    if (
        args.native_keyboard
        and (args.smoke or "framebuffer-keyboard" in scenario_groups)
        and platform_id == X86_64_Q35_UEFI
    ):
        run_native_keyboard_scenario(args)
    suite = "smoke" if args.smoke else "acceptance"
    groups = "smoke" if args.smoke else ",".join(sorted(scenario_groups))
    print(f"QEMU {suite} ({platform_id}; groups={groups}): passed")


def main() -> int:
    args = parse_args()
    try:
        scenario_groups = selected_scenarios(args)
    except ValueError as error:
        print(f"QEMU acceptance failed: {error}", file=sys.stderr)
        return 2
    apply_scenario_requirements(args, scenario_groups)
    if args.boot_timeout <= 0 or args.command_timeout <= 0:
        print("QEMU acceptance failed: timeouts must be positive", file=sys.stderr)
        return 2
    platform_ids = PLATFORM_IDS if args.platform == "all" else (args.platform,)
    if args.platform == "all" and (
        args.firmware_code is not None or args.firmware_vars is not None
    ):
        print(
            "QEMU acceptance failed: explicit firmware paths require one platform",
            file=sys.stderr,
        )
        return 2

    try:
        for platform_id in platform_ids:
            resolve_runner(platform_id, args.environment)
        if not args.skip_build:
            build_platform = args.platform
            variant_arguments = (
                ("--all-variants",)
                if requires_acceptance_images(scenario_groups)
                else ()
            )
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "build.py"),
                    "--platform",
                    build_platform,
                    "--fixture-identities",
                    *variant_arguments,
                    *(("--strict-tool-versions",) if args.strict_tool_versions else ()),
                ],
                cwd=REPO_ROOT,
                check=True,
            )
        if not args.skip_build:
            for platform_id in platform_ids:
                profile = resolve_platform(platform_id)
                runner = resolve_runner(platform_id, args.environment)
                if runner.disk_layout != "cloud-bundle-v1":
                    continue
                build_cloud_bundle(profile, args.environment)
                if requires_acceptance_images(scenario_groups):
                    build_cloud_bundle(
                        profile,
                        args.environment,
                        acceptance_probes=True,
                    )
        install_runtime = not args.smoke and "filesystem" in scenario_groups
        if install_runtime:
            if args.skip_build:
                subprocess.run(
                    [
                        sys.executable,
                        REPO_ROOT / "tools" / "mkruntime.py",
                        "verify",
                        RUNTIME_PROBE_TREE,
                    ],
                    cwd=REPO_ROOT,
                    check=True,
                )
            else:
                build_runtime_probe_tree()
        install_cpython = "cpython" in scenario_groups
        for platform_id in platform_ids:
            reset_txslot(platform_id, args.environment)
            reset_shared_media(
                platform_id,
                install_runtime=install_runtime,
                install_cpython=install_cpython,
            )
        if len(platform_ids) == 1:
            test_platform(platform_ids[0], args)
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(platform_ids), thread_name_prefix="qemu-acceptance"
            ) as executor:
                futures = {
                    executor.submit(test_platform, platform_id, args): platform_id
                    for platform_id in platform_ids
                }
                for future in concurrent.futures.as_completed(futures):
                    future.result()
    except (AcceptanceError, FileNotFoundError, OSError, RuntimeError) as error:
        print(f"QEMU acceptance failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"QEMU acceptance failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    except KeyboardInterrupt:
        return 130
    finally:
        cleanup_shared_media(platform_ids)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
