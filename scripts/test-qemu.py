#!/usr/bin/env python3
"""Drive deterministic shell acceptance tests through the QEMU serial console."""

from __future__ import annotations

import argparse
import concurrent.futures
import queue
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

from qemu_profile import QEMU_EXECUTABLES, REPO_ROOT, prepare_qemu_command


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
NETWORK_PORTS = {"x86_64": 40123, "aarch64": 40124}
NETWORK_REQUEST = b"troe-stage8-request"
NETWORK_REPLY = b"troe-stage8-reply"


class AcceptanceError(RuntimeError):
    """A boot, console, assertion, or timeout failure."""


class UdpAcceptancePeer:
    """Answer the guest's bounded Stage 8 UDP probe on the slirp host."""

    def __init__(self, architecture: str) -> None:
        self.architecture = architecture
        self.received = 0
        self.error: OSError | None = None
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.settimeout(0.2)
        self._socket.bind(("127.0.0.1", NETWORK_PORTS[architecture]))
        self._thread = threading.Thread(
            target=self._serve,
            name=f"udp-acceptance-{architecture}",
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


def txslot_path(architecture: str) -> Path:
    """Return the architecture-private writable acceptance medium."""
    return REPO_ROOT / "build" / f"storage-txslot-{architecture}.img"


def statefs_path(architecture: str) -> Path:
    """Return the architecture-private writable filesystem medium."""
    return REPO_ROOT / "build" / f"storage-statefs-{architecture}.img"


def reset_txslot(architecture: str) -> None:
    """Start one architecture's process-reopen sequence from empty media."""
    path = txslot_path(architecture)
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
            str(statefs_path(architecture)),
        ],
        cwd=REPO_ROOT,
        check=True,
    )


def dual_slot_state(architecture: str, path: Path) -> tuple[int, bytes]:
    """Validate TXSLOT v1 and return its newest generation and payload."""
    image = path.read_bytes()
    if len(image) != TXSLOT_DISK_BYTES:
        raise AcceptanceError(f"{architecture} TXSLOT image has invalid length")
    image = image[TXSLOT_PARTITION_OFFSET:TXSLOT_PARTITION_OFFSET + TXSLOT_BYTES]
    generations: list[tuple[int, bytes]] = []
    for slot in range(2):
        data = image[slot * 1024:slot * 1024 + 512]
        commit = image[slot * 1024 + 512:slot * 1024 + 1024]
        if data == bytes(512) and commit == bytes(512):
            continue
        checked_data = bytearray(data)
        checked_data[TXSLOT_CHECKSUM_OFFSET:TXSLOT_CHECKSUM_OFFSET + 4] = bytes(4)
        data_checksum = struct.unpack_from("<I", data, TXSLOT_CHECKSUM_OFFSET)[0]
        length = struct.unpack_from("<I", data, 16)[0]
        generation = struct.unpack_from("<Q", data, 8)[0]
        checked_commit = bytearray(commit)
        checked_commit[TXSLOT_CHECKSUM_OFFSET:TXSLOT_CHECKSUM_OFFSET + 4] = bytes(4)
        valid = (
            data[:8] == b"TXDTv1\0\0"
            and commit[:8] == b"TXCMv1\0\0"
            and generation != 0
            and length <= 512 - 32
            and data[24:32] == bytes(8)
            and data[32 + length:] == bytes(512 - 32 - length)
            and zlib.crc32(checked_data) == data_checksum
            and struct.unpack_from("<Q", commit, 8)[0] == generation
            and struct.unpack_from("<I", commit, 16)[0] == data_checksum
            and commit[24:] == bytes(512 - 24)
            and zlib.crc32(checked_commit)
            == struct.unpack_from("<I", commit, TXSLOT_CHECKSUM_OFFSET)[0]
        )
        if valid:
            generations.append((generation, data[32:32 + length]))
    generation_numbers = [generation for generation, _ in generations]
    if not generations or len(generation_numbers) != len(set(generation_numbers)):
        raise AcceptanceError(f"{architecture} TXSLOT has no unique committed generation")
    return max(generations, key=lambda state: state[0])


def txslot_state(architecture: str) -> tuple[int, bytes]:
    """Return the activation transaction state."""
    return dual_slot_state(architecture, txslot_path(architecture))


def statefs_counter(architecture: str) -> tuple[int, int]:
    """Validate STFS v1 and return transaction generation and file counter."""
    generation, payload = dual_slot_state(architecture, statefs_path(architecture))
    if len(payload) != 40 or payload[:8] != b"STFSv1\0\0":
        raise AcceptanceError(f"{architecture} statefs payload is malformed")
    checked = bytearray(payload)
    checked[20:24] = bytes(4)
    valid = (
        struct.unpack_from("<HHHHI", payload, 8) == (1, 0, 32, 1, 8)
        and payload[24:32] == bytes(8)
        and zlib.crc32(checked) == struct.unpack_from("<I", payload, 20)[0]
    )
    if not valid:
        raise AcceptanceError(f"{architecture} statefs image failed validation")
    return generation, struct.unpack_from("<Q", payload, 32)[0]


def assert_rolled_back_sact(architecture: str, payload: bytes) -> None:
    """Require the durable SACT pointer to select generation one only."""
    if len(payload) != 128 or payload[:8] != b"SACTv1\0\0":
        raise AcceptanceError(f"{architecture} durable SACT payload is malformed")
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
        raise AcceptanceError(f"{architecture} did not persist predecessor rollback")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architecture",
        "--arch",
        choices=("all", *QEMU_EXECUTABLES),
        default="all",
        help="architecture to test (default: all)",
    )
    parser.add_argument("--firmware-code", type=Path)
    parser.add_argument("--firmware-vars", type=Path)
    parser.add_argument("--skip-version-check", action="store_true")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="run a fast terminal-focused scenario instead of full acceptance",
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
    return parser.parse_args()


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
    if frames is None or int(frames.group(2)) == 0 or int(frames.group(1)) > int(frames.group(2)):
        raise AcceptanceError(f"mem reported invalid frame counters: {report!r}")
    heap = re.search(
        r"^heap: ([0-9]+)/([0-9]+) used \([^\n]+\)$", report, re.MULTILINE
    )
    if heap is None or int(heap.group(2)) == 0 or int(heap.group(1)) >= int(heap.group(2)):
        raise AcceptanceError(f"mem reported invalid heap counters: {report!r}")
    high_water = re.search(
        r"^heap high-water: ([0-9]+) \([^\n]+\)$", report, re.MULTILINE
    )
    if high_water is None or int(high_water.group(1)) < int(heap.group(1)):
        raise AcceptanceError(f"mem reported invalid heap high-water: {report!r}")
    failures = re.search(r"^allocation failures: ([0-9]+)$", report, re.MULTILINE)
    if failures is None or int(failures.group(1)) < 1:
        raise AcceptanceError(f"bounded allocation failure was not accounted: {report!r}")
    input_queue = re.search(
        r"^input queue: ([0-9]+)/([0-9]+) queued$", report, re.MULTILINE
    )
    if (
        input_queue is None
        or int(input_queue.group(2)) == 0
        or int(input_queue.group(1)) > int(input_queue.group(2))
    ):
        raise AcceptanceError(f"mem reported invalid input queue counters: {report!r}")
    for label in ("input interrupts", "input delivered", "input idle waits", "input wakeups"):
        match = re.search(rf"^{re.escape(label)}: ([0-9]+)$", report, re.MULTILINE)
        if match is None or int(match.group(1)) == 0:
            raise AcceptanceError(f"mem reported invalid {label}: {report!r}")
    dropped = re.search(r"^input dropped: ([0-9]+)$", report, re.MULTILINE)
    if dropped is None or int(dropped.group(1)) != 0:
        raise AcceptanceError(f"ordinary input unexpectedly overflowed: {report!r}")
    idle_waits = re.search(r"^input idle waits: ([0-9]+)$", report, re.MULTILINE)
    wakeups = re.search(r"^input wakeups: ([0-9]+)$", report, re.MULTILINE)
    if idle_waits is None or wakeups is None or int(wakeups.group(1)) > int(idle_waits.group(1)):
        raise AcceptanceError(f"mem reported inconsistent idle accounting: {report!r}")
    return int(heap.group(1))


def assert_owned_boot(session: "SerialSession") -> None:
    """Require every marker emitted across the one-way ownership handoff."""
    transcript = session.transcript()
    for marker in (
        "native console: ready",
        "boot services: exited",
        "frame bitmap: ready",
        "allocation failure path: bounded",
        "exception vectors: ready",
        "owned page tables: ready",
        "W^X mappings: active",
        "interrupt-driven input: ready",
        "cooperative tasks: deterministic",
        "task stack guards: active",
        "task resources: reclaimed",
        "isolated address spaces: active",
        "copied task messages: bounded",
        "isolated faults: contained",
        "isolated resources: reclaimed",
        "KEX staging: owned and bounded",
        "KEX load plans: mapped atomically",
        "application ABI exit: active",
        "application ABI resume: active",
        "copied handle calls: active",
        "execution lease: enforced",
        "application resources: reclaimed",
        "in-process console dispatch: ready",
        "memory and console: owned",
    ):
        if marker not in transcript:
            raise AcceptanceError(
                f"{session.architecture} boot missed ownership marker {marker!r}"
            )
    if "native storage: /vol/root read-only" not in transcript:
        raise AcceptanceError(
            f"{session.architecture} boot did not activate the BMNT-selected ext4 root volume"
        )


class SerialSession:
    """A QEMU child with deadline-bound serial reads and deterministic cleanup."""

    def __init__(self, command: list[str], architecture: str) -> None:
        self.architecture = architecture
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

    def send(self, command: str, timeout: float, line_ending: bytes = b"\n") -> int:
        """Send one console line and return the transcript offset after its newline."""
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        try:
            # Pace against guest echo so both firmware and native polling UART
            # paths remain deterministic under loaded CI hosts.
            for byte in command.encode("utf-8"):
                start = len(self.output)
                self.process.stdin.write(bytes((byte,)))
                self.process.stdin.flush()
                self.wait_for(bytes((byte,)), timeout, start)
            start = len(self.output)
            self.process.stdin.write(line_ending)
            self.process.stdin.flush()
            return self.wait_for(b"\n", timeout, start)
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error

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
        if "UEFI bootstrap: ready" in tail or "shell:/> " in tail:
            raise AcceptanceError(f"machine rebooted after fatal marker: {tail!r}")

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

        prompt = f"shell:{cwd}> ".encode()
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
            self.wait_for(b"\x1b[K", timeout, edit_start)

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

        prompt = f"shell:{cwd}> ".encode()
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
        prompt = f"shell:{resulting_cwd}> ".encode()
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


def run_scenario(session: SerialSession, boot_timeout: float, command_timeout: float) -> None:
    """Exercise every required built-in plus bounded failure behavior."""
    session.wait_for(b"shell:/> ", boot_timeout)
    assert_owned_boot(session)
    cwd = "/"

    session.edited_command(
        "", b"\t", "", cwd, command_timeout, expected="\ncat\n"
    )
    session.command(
        "man echo",
        cwd,
        command_timeout,
        contains=("NAME\n    echo - write arguments", "SYNOPSIS\n    echo [ARG...]"),
    )
    session.command(
        "help", cwd, command_timeout, contains=("help: unknown command",)
    )
    session.backspace_command(
        "echo brokeX", "n", cwd, command_timeout, expected="\nbroken\n"
    )
    session.edited_command(
        "echo ac", b"\x1b[D", "b", cwd, command_timeout, expected="\nabc\n"
    )
    session.command("echo history-ready", cwd, command_timeout, contains=("history-ready\n",))
    session.edited_command(
        "", b"\x1b[A", "", cwd, command_timeout, expected="\nhistory-ready\n"
    )
    session.edited_command(
        "pw", b"\t", "", cwd, command_timeout, expected="\n/\n"
    )
    session.command(
        "echo crlf-ready",
        cwd,
        command_timeout,
        contains=("crlf-ready\n",),
        line_ending=b"\r\n",
    )
    session.command("ls /", cwd, command_timeout, contains=("etc/", "man/", "sys/", "tmp/"))
    session.command(
        "cat /etc/motd",
        cwd,
        command_timeout,
        contains=("Welcome to the tiny Rust operating environment.",),
    )
    session.command(
        "cat /vol/root/hello.txt",
        cwd,
        command_timeout,
        contains=("native ext4 mount\n",),
    )
    session.command("echo alpha beta", cwd, command_timeout, contains=("alpha beta\n",))
    session.command(
        "echo alpha beta | grep beta | write /tmp/result", cwd, command_timeout
    )
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
    session.command("write /tmp/direct AB", cwd, command_timeout)
    session.command(
        "hexdump /tmp/direct", cwd, command_timeout, contains=("00000000  41 42 ",)
    )
    session.command("rm /tmp/direct", cwd, command_timeout)
    session.command(
        "cat /tmp/direct", cwd, command_timeout, contains=("cat: /tmp/direct: not found",)
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
        "write /etc/motd nope",
        cwd,
        command_timeout,
        contains=("write: /etc/motd: read-only filesystem",),
    )
    session.command(
        "clear", cwd, command_timeout, raw_contains=(b"\x1b[2J",)
    )
    session.command("rm /tmp/result", cwd, command_timeout)

    for index in range(128):
        session.command(f"write /tmp/q{index:03} x", cwd, command_timeout)
    session.command(
        "write /tmp/q128 x",
        cwd,
        command_timeout,
        contains=("write: /tmp/q128: filesystem quota exceeded",),
    )
    session.command("rm /tmp/q000", cwd, command_timeout)
    session.command("write /tmp/recovered ok", cwd, command_timeout)
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
        session.command("write /tmp/cycle stable", cwd, command_timeout)
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
            "echo allocation-cycle | grep cycle", cwd, command_timeout,
            contains=("allocation-cycle\n",),
        )
        session.command("write /tmp/cycle stable", cwd, command_timeout)
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

    start = len(session.output)
    session.send("halt", command_timeout)
    session.wait_for(b"halting: parking CPU", command_timeout, start)


def run_smoke_scenario(
    session: SerialSession, boot_timeout: float, command_timeout: float
) -> None:
    """Exercise the interactive console path without the exhaustive quota workload."""
    session.wait_for(b"shell:/> ", boot_timeout)
    assert_owned_boot(session)
    cwd = "/"
    session.backspace_command(
        "echo brokeX", "n", cwd, command_timeout, expected="\nbroken\n"
    )
    session.edited_command(
        "echo ac", b"\x1b[D", "b", cwd, command_timeout, expected="\nabc\n"
    )
    session.command("echo history-ready", cwd, command_timeout, contains=("history-ready\n",))
    session.edited_command(
        "", b"\x1b[A", "", cwd, command_timeout, expected="\nhistory-ready\n"
    )
    session.edited_command(
        "pw", b"\t", "", cwd, command_timeout, expected="\n/\n"
    )
    session.command(
        "clear", cwd, command_timeout, raw_contains=(b"\x1b[2J",)
    )
    session.command(
        "echo qemu-smoke | grep smoke",
        cwd,
        command_timeout,
        contains=("qemu-smoke\n",),
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
    start = len(session.output)
    session.send("halt", command_timeout)
    session.wait_for(b"halting: parking CPU", command_timeout, start)


def run_native_keyboard_scenario(args: argparse.Namespace) -> None:
    """Drive the q35 i8042 path independently of serial input."""
    command = prepare_qemu_command(
        "x86_64",
        args.firmware_code,
        args.firmware_vars,
        skip_version_check=args.skip_version_check,
        build=False,
        acceptance_probes=False,
        framebuffer=args.framebuffer_console,
    )
    # Keep this below macOS's short AF_UNIX path limit even when TMPDIR points
    # into a deeply nested per-user directory.
    with tempfile.TemporaryDirectory(prefix="qemu-monitor-", dir="/tmp") as directory:
        monitor_path = str(Path(directory) / "qemu.sock")
        monitor_index = command.index("-monitor") + 1
        command[monitor_index] = f"unix:{monitor_path},server=on,wait=off"
        session = SerialSession(command, "x86_64")
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

            session.wait_for(b"shell:/> ", args.boot_timeout)
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
            session.wait_for(b"shell:/> ", args.command_timeout, start)
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
    session.wait_for(b"shell:/> ", boot_timeout)
    assert_owned_boot(session)
    if "native persistence: committed and flushed" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not complete the native TXSLOT transaction"
        )
    if "native content: selected ext4 CSPK verified" not in session.transcript():
        raise AcceptanceError(
            f"{session.architecture} did not verify selected ext4 content"
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


def test_architecture(
    architecture: str,
    args: argparse.Namespace,
) -> None:
    command = prepare_qemu_command(
        architecture,
        args.firmware_code,
        args.firmware_vars,
        skip_version_check=args.skip_version_check,
        build=False,
        acceptance_probes=False,
        framebuffer=args.framebuffer_console,
    )
    session = SerialSession(command, architecture)
    try:
        scenario = run_smoke_scenario if args.smoke else run_scenario
        scenario(session, args.boot_timeout, args.command_timeout)
        if args.framebuffer_console and b"owned framebuffer text console: ready" not in session.output:
            raise AcceptanceError(
                f"{architecture} did not activate the owned framebuffer text console"
            )
    except Exception:
        print(f"--- {architecture} QEMU transcript ---", file=sys.stderr)
        print(session.transcript(), file=sys.stderr)
        print(f"raw tail: {bytes(session.output[-256:])!r}", file=sys.stderr)
        raise
    finally:
        session.close()
    if not args.smoke:
        network_peer = UdpAcceptancePeer(architecture)
        network_peer.start()
        try:
            for expected_generation, fault in enumerate(
                ("write", "execute", "guard", "exception", "fatal"), start=2
            ):
                command = prepare_qemu_command(
                    architecture,
                    args.firmware_code,
                    args.firmware_vars,
                    skip_version_check=args.skip_version_check,
                    build=False,
                    acceptance_probes=True,
                    framebuffer=args.framebuffer_console,
                )
                fault_session = SerialSession(command, architecture)
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
                            f"{architecture} did not exercise health rollback"
                        )
                except Exception:
                    print(
                        f"--- {architecture} {fault} fault transcript ---",
                        file=sys.stderr,
                    )
                    print(fault_session.transcript(), file=sys.stderr)
                    raise
                finally:
                    fault_session.close()
                actual_generation, payload = txslot_state(architecture)
                if actual_generation != expected_generation:
                    raise AcceptanceError(
                        f"{architecture} TXSLOT recovered generation "
                        f"{actual_generation}, expected {expected_generation}"
                    )
                assert_rolled_back_sact(architecture, payload)
                state_generation, counter = statefs_counter(architecture)
                expected_state = expected_generation - 1
                if state_generation != expected_state or counter != expected_state:
                    raise AcceptanceError(
                        f"{architecture} statefs recovered generation "
                        f"{state_generation} and counter {counter}, "
                        f"expected {expected_state}"
                    )
        finally:
            network_peer.close()
        if network_peer.error is not None:
            raise AcceptanceError(
                f"{architecture} UDP acceptance peer failed: {network_peer.error}"
            )
        if network_peer.received != 5:
            raise AcceptanceError(
                f"{architecture} UDP acceptance peer received "
                f"{network_peer.received} probes, expected 5"
            )
    if args.native_keyboard and architecture == "x86_64":
        run_native_keyboard_scenario(args)
    suite = "smoke" if args.smoke else "acceptance"
    print(f"QEMU {suite} ({architecture}): passed")


def main() -> int:
    args = parse_args()
    if args.boot_timeout <= 0 or args.command_timeout <= 0:
        print("QEMU acceptance failed: timeouts must be positive", file=sys.stderr)
        return 2
    architectures = QEMU_EXECUTABLES if args.architecture == "all" else (args.architecture,)
    if args.architecture == "all" and (
        args.firmware_code is not None or args.firmware_vars is not None
    ):
        print(
            "QEMU acceptance failed: explicit firmware paths require one architecture",
            file=sys.stderr,
        )
        return 2

    try:
        if not args.skip_build:
            build_architecture = args.architecture
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "build.py"),
                    "--architecture",
                    build_architecture,
                ],
                cwd=REPO_ROOT,
                check=True,
            )
            if not args.smoke:
                subprocess.run(
                    [
                        sys.executable,
                        str(REPO_ROOT / "scripts" / "build.py"),
                        "--architecture",
                        build_architecture,
                        "--acceptance-probes",
                    ],
                    cwd=REPO_ROOT,
                    check=True,
                )
            subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools" / "mkstorage.py"),
                    "--manifest",
                    str(REPO_ROOT / "assets" / "boot.bmnt"),
                    "--output",
                    str(REPO_ROOT / "build" / "storage-root.img"),
                    "--content",
                    str(REPO_ROOT / "assets" / "system.cspk"),
                ],
                cwd=REPO_ROOT,
                check=True,
            )
        for architecture in architectures:
            reset_txslot(architecture)
        if len(architectures) == 1:
            test_architecture(architectures[0], args)
        else:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=len(architectures), thread_name_prefix="qemu-acceptance"
            ) as executor:
                futures = {
                    executor.submit(test_architecture, architecture, args): architecture
                    for architecture in architectures
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
