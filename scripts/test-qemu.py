#!/usr/bin/env python3
"""Drive deterministic shell acceptance tests through the QEMU serial console."""

from __future__ import annotations

import argparse
import concurrent.futures
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from qemu_profile import QEMU_EXECUTABLES, REPO_ROOT, prepare_qemu_command


ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[=>])")
BOOT_TIMEOUT_SECONDS = 30.0
COMMAND_TIMEOUT_SECONDS = 5.0


class AcceptanceError(RuntimeError):
    """A boot, console, assertion, or timeout failure."""


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
        "--skip-build",
        action="store_true",
        help="use boot images already present under build/",
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
            while chunk := self.process.stdout.read(1):
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

    def send(self, command: str, timeout: float) -> None:
        """Send one firmware-console line after a prompt has been observed."""
        if self.process.stdin is None:
            raise AcceptanceError("QEMU serial input is unavailable")
        try:
            # EDK2's serial-backed Simple Text Input queue is shallow. Pacing is
            # required or a host pipe can overrun it between firmware polls.
            # Waiting for each echoed byte is faster and more reliable than a
            # machine-dependent sleep interval.
            for byte in command.encode("utf-8"):
                start = len(self.output)
                self.process.stdin.write(bytes((byte,)))
                self.process.stdin.flush()
                self.wait_for(bytes((byte,)), timeout, start)
            start = len(self.output)
            self.process.stdin.write(b"\n")
            self.process.stdin.flush()
            self.wait_for(b"\n", timeout, start)
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error

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

            self.process.stdin.write(b"\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise AcceptanceError(f"cannot write QEMU serial input: {error}") from error

        prompt = f"kllm:{cwd}> ".encode()
        end = self.wait_for(prompt, timeout, start)
        text = normalize(bytes(self.output[start : end - len(prompt)]))
        if expected not in text:
            raise AcceptanceError(
                f"backspace-edited command did not produce {expected!r}; "
                f"command output was {text!r}"
            )

    def command(
        self,
        command: str,
        cwd: str,
        timeout: float,
        *,
        next_cwd: str | None = None,
        contains: tuple[str, ...] = (),
        raw_contains: tuple[bytes, ...] = (),
    ) -> str:
        """Execute a line, wait for the next prompt, and assert its output."""
        start = len(self.output)
        self.send(command, timeout)
        resulting_cwd = cwd if next_cwd is None else next_cwd
        prompt = f"kllm:{resulting_cwd}> ".encode()
        end = self.wait_for(prompt, timeout, start)
        raw = bytes(self.output[start : end - len(prompt)])
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
    session.wait_for(b"kllm:/> ", boot_timeout)
    cwd = "/"

    session.command(
        "help",
        cwd,
        command_timeout,
        contains=(
            "cat",
            "echo",
            "grep",
            "ls",
            "pwd",
            "cd",
            "help",
            "mem",
            "clear",
            "halt",
            "write",
            "rm",
            "hexdump",
        ),
    )
    session.command("help echo", cwd, command_timeout, contains=("echo [ARG...]",))
    session.backspace_command(
        "echo brokeX", "n", cwd, command_timeout, expected="\nbroken\n"
    )
    session.command("ls /", cwd, command_timeout, contains=("etc/", "help/", "sys/", "tmp/"))
    session.command(
        "cat /etc/motd",
        cwd,
        command_timeout,
        contains=("Welcome to kllm 0.1.0.",),
    )
    session.command("echo alpha beta", cwd, command_timeout, contains=("alpha beta\n",))
    session.command(
        "echo alpha beta | grep beta | write /tmp/result", cwd, command_timeout
    )
    session.command("cat /tmp/result", cwd, command_timeout, contains=("alpha beta\n",))
    session.command("pwd", cwd, command_timeout, contains=("/\n",))
    session.command("cd /help", cwd, command_timeout, next_cwd="/help")
    cwd = "/help"
    session.command("pwd", cwd, command_timeout, contains=("/help\n",))
    session.command(
        "grep bounded pipelines",
        cwd,
        command_timeout,
        contains=("bounded byte streams",),
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
    session.command(
        "mem",
        cwd,
        command_timeout,
        contains=(
            f"arch: {session.architecture}",
            "memory owner: firmware",
            "ramfs limit: 1048576",
            "pressure: normal (RAMFS policy only)",
        ),
    )

    start = len(session.output)
    session.send("halt", command_timeout)
    session.wait_for(b"halting: returning control to firmware", command_timeout, start)


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
    )
    session = SerialSession(command, architecture)
    try:
        run_scenario(session, args.boot_timeout, args.command_timeout)
    except Exception:
        print(f"--- {architecture} QEMU transcript ---", file=sys.stderr)
        print(session.transcript(), file=sys.stderr)
        print(f"raw tail: {bytes(session.output[-256:])!r}", file=sys.stderr)
        raise
    finally:
        session.close()
    print(f"QEMU acceptance ({architecture}): passed")


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
