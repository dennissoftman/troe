#!/usr/bin/env python3
"""Run formatting, lint, test, consistency, image, and QEMU boot gates."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .platform_profile import PLATFORM_IDS, PLATFORM_PROFILES
    from .qemu_profile import QEMU_ENVIRONMENT
    from .repository_policy import (
        KEX_TARGETS,
        buildable_shared_volume_directories,
        lintable_application_directories,
        require_supported_python,
        rootfs_application_directories,
        service_directories,
        unlintable_application_exclusions,
    )
else:
    from platform_profile import PLATFORM_IDS, PLATFORM_PROFILES
    from qemu_profile import QEMU_ENVIRONMENT
    from repository_policy import (
        KEX_TARGETS,
        buildable_shared_volume_directories,
        lintable_application_directories,
        require_supported_python,
        rootfs_application_directories,
        service_directories,
        unlintable_application_exclusions,
    )


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = REPO_ROOT / "tools"
DEFAULT_PROGRESS_INTERVAL = 60.0
KEX_APPLICATIONS = rootfs_application_directories()
SHARED_VOLUME_KEX_APPLICATIONS = buildable_shared_volume_directories()
APPLICATIONS_MANIFEST = REPO_ROOT / "apps" / "Cargo.toml"
UNLINTABLE_APPLICATION_EXCLUSIONS = unlintable_application_exclusions()
SERVICES_MANIFEST = REPO_ROOT / "services" / "Cargo.toml"
KEX_SERVICES = (
    (REPO_ROOT / "services" / "diagnostics", "diagnostics-server", 8),
    (
        REPO_ROOT / "services" / "diagnostics-benchmark",
        "diagnostics-benchmark-server",
        8,
    ),
    (
        REPO_ROOT / "services" / "diagnostics-fault",
        "diagnostics-fault-server",
        8,
    ),
)


@dataclass(frozen=True)
class Step:
    """One labeled verification command owned by the exhaustive gate."""

    label: str
    command: tuple[str | Path, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-qemu",
        action="store_true",
        help="skip boot acceptance when a supported QEMU/firmware pair is unavailable",
    )
    parser.add_argument(
        "--require-filesystem-tools",
        action="store_true",
        help="require and run e2fsprogs, dosfstools, and mtools interoperability tests",
    )
    parser.add_argument(
        "--strict-tool-versions",
        action="store_true",
        help="require release-pinned QEMU, UEFI firmware, and e2fsprogs versions",
    )
    parser.add_argument(
        "--build-sbsa-firmware",
        action="store_true",
        help=(
            "build the pinned Arm SBSA reference firmware before acceptance; "
            "it is fetched and compiled from source, so this is opt-in and "
            "only needed once per machine"
        ),
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=DEFAULT_PROGRESS_INTERVAL,
        metavar="SECONDS",
        help="seconds between liveness lines inside one gate; 0 disables them",
    )
    args = parser.parse_args()
    if args.progress_interval < 0:
        parser.error("--progress-interval must not be negative")
    return args


def format_duration(seconds: float) -> str:
    """Render one elapsed interval in stable, scannable units."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    hours, remainder = divmod(int(seconds), 3600)
    minutes, whole_seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{whole_seconds:02d}s"
    return f"{minutes}m{whole_seconds:02d}s"


def report(message: str) -> None:
    """Print one progress line that stays ordered with child process output."""
    print(message, flush=True)


def display(command: tuple[str | Path, ...]) -> str:
    """Render argv relative to the repository without implying shell semantics."""
    prefix = f"{REPO_ROOT}{os.sep}"
    arguments = []
    for argument in command:
        text = str(argument)
        if text.startswith(prefix):
            text = text[len(prefix) :]
        arguments.append(repr(text) if any(c.isspace() for c in text) else text)
    return " ".join(arguments)


class LivenessReporter:
    """Print periodic progress while one silent long-running gate executes."""

    def __init__(self, prefix: str, started: float, interval: float) -> None:
        self._prefix = prefix
        self._started = started
        self._interval = interval
        self._finished = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> LivenessReporter:
        if self._interval > 0:
            self._thread = threading.Thread(
                target=self._announce, name="verification-progress", daemon=True
            )
            self._thread.start()
        return self

    def __exit__(self, *exception: object) -> None:
        self._finished.set()
        if self._thread is not None:
            self._thread.join()

    def _announce(self) -> None:
        while not self._finished.wait(self._interval):
            elapsed = format_duration(time.monotonic() - self._started)
            report(
                f"{self._prefix}: still running after {elapsed} "
                f"({time.strftime('%H:%M:%S')})"
            )


def target_clippy_commands() -> list[Step]:
    """Return one exact target gate per named platform."""
    return [
        Step(
            f"clippy troe-kernel ({profile.identifier})",
            (
                "cargo",
                "clippy",
                "-p",
                "troe-kernel",
                "--target",
                profile.target,
                "--features",
                f"{profile.kernel_feature},acceptance-probes",
                "--",
                "-D",
                "warnings",
            ),
        )
        for profile in PLATFORM_PROFILES.values()
    ]


def package_clippy_commands() -> list[Step]:
    """Return one bare-metal lint gate per shipped command and service.

    One package at a time, not one workspace-wide invocation: Cargo unifies
    features across everything it builds together, and `ls` and `mem` take
    `troe-kex-runtime` without its `alloc` feature while `cp`, `mv`, and `rm`
    take it with. A single workspace build would lint those commands against a
    feature set they never ship with, and would not even compile.
    """
    targets: tuple[str, ...] = ()
    for target in KEX_TARGETS:
        targets = (*targets, "--target", target)
    return [
        Step(
            f"clippy {kind} ({directory.name})",
            (
                "cargo",
                "clippy",
                "--manifest-path",
                directory / "Cargo.toml",
                *targets,
                "--",
                "-D",
                "warnings",
            ),
        )
        for kind, directories in (
            ("app", lintable_application_directories()),
            ("service", service_directories()),
        )
        for directory in directories
    ]


def image_and_qemu_commands(
    *, skip_qemu: bool, strict_tool_versions: bool = False
) -> list[Step]:
    """Return one owner for production/acceptance builds without duplication.

    Boot acceptance takes one named platform per invocation so that a single
    emulated guest, not one guest per platform, competes for host memory, cores,
    and local ports. The exhaustive gate still covers every named platform.
    """
    if skip_qemu:
        return [
            Step(
                "build images (all platforms)",
                (
                    sys.executable,
                    REPO_ROOT / "scripts" / "build.py",
                    "--platform",
                    "all",
                    "--fixture-identities",
                    "--all-variants",
                    *(("--strict-tool-versions",) if strict_tool_versions else ()),
                ),
            )
        ]
    return [
        Step(
            f"qemu acceptance ({platform_id})",
            (
                sys.executable,
                REPO_ROOT / "scripts" / "test-qemu.py",
                "--platform",
                platform_id,
                "--environment",
                QEMU_ENVIRONMENT,
                "--framebuffer-console",
                "--native-keyboard",
                *(("--strict-tool-versions",) if strict_tool_versions else ()),
            ),
        )
        for platform_id in PLATFORM_IDS
    ]


def verification_steps(args: argparse.Namespace) -> list[Step]:
    """Return every gate in execution order with its short progress label."""
    steps: list[Step] = [
        Step("cargo fmt", ("cargo", "fmt", "--all", "--", "--check")),
        *(
            Step(
                f"cargo fmt ({label})",
                ("cargo", "fmt", "--all", "--manifest-path", manifest, "--", "--check"),
            )
            for label, manifest in (
                ("applications", APPLICATIONS_MANIFEST),
                ("services", SERVICES_MANIFEST),
            )
        ),
        Step(
            "clippy workspace",
            (
                "cargo",
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ),
        ),
        *target_clippy_commands(),
        *package_clippy_commands(),
        Step(
            "clippy applications (host unit tests)",
            (
                "cargo",
                "clippy",
                "--manifest-path",
                APPLICATIONS_MANIFEST,
                "--workspace",
                *UNLINTABLE_APPLICATION_EXCLUSIONS,
                "--tests",
                "--",
                "-D",
                "warnings",
            ),
        ),
        Step("cargo test workspace", ("cargo", "test", "--workspace")),
        Step(
            "cargo test applications",
            (
                "cargo",
                "test",
                "--manifest-path",
                APPLICATIONS_MANIFEST,
                "--workspace",
                *UNLINTABLE_APPLICATION_EXCLUSIONS,
                "--lib",
            ),
        ),
        Step(
            "python unit tests",
            (
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                REPO_ROOT / "tests",
                "-p",
                "test_*.py",
            ),
        ),
        Step("dependency audit", (sys.executable, REPO_ROOT / "scripts" / "audit.py")),
        *(
            Step(
                f"kefs check ({architecture})",
                (
                    sys.executable,
                    TOOLS_DIR / "mkefs.py",
                    REPO_ROOT / "rootfs",
                    REPO_ROOT / "assets" / f"root-{architecture}.kefs",
                    "--architecture",
                    architecture,
                    "--check",
                ),
            )
            for architecture in ("x86_64", "aarch64")
        ),
        *(
            Step(
                f"kex app ({application.name})",
                (
                    "cargo",
                    "kex",
                    "build",
                    application,
                    "--target",
                    "all",
                    "--check",
                ),
            )
            for application in KEX_APPLICATIONS
        ),
        *(
            Step(
                f"kex service ({name})",
                (
                    "cargo",
                    "kex",
                    "build",
                    service,
                    "--name",
                    name,
                    "--target",
                    "all",
                    "--output",
                    REPO_ROOT / "tests" / "kex-corpus",
                    "--stack-pages",
                    str(stack_pages),
                    "--check",
                ),
            )
            for service, name, stack_pages in KEX_SERVICES
        ),
        # A shared-volume deliverable ships no committed `.kex`, so there is no
        # `--check` for it and only a QEMU acceptance run would otherwise build
        # one. Build it here so the builder's workspace-member path handling is
        # exercised for every member it can reach, not only the ones with a
        # committed artifact to compare against.
        *(
            Step(
                f"kex shared app ({application.name})",
                (
                    "cargo",
                    "kex",
                    "build",
                    application,
                    "--target",
                    "all",
                    "--output",
                    REPO_ROOT / "build" / "shared-volume-packages",
                ),
            )
            for application in SHARED_VOLUME_KEX_APPLICATIONS
        ),
        Step(
            "kex runtime probe",
            (
                "cargo",
                "kex",
                "build",
                REPO_ROOT / "tests" / "runtime-probe",
                "--target",
                "all",
                "--output",
                REPO_ROOT / "build" / "runtime-probe-packages",
            ),
        ),
        Step(
            "host smoke",
            (
                "cargo",
                "run",
                "--quiet",
                "-p",
                "troe-host",
                "--",
                "--script",
                REPO_ROOT / "tests" / "smoke.sh",
            ),
        ),
    ]
    if args.build_sbsa_firmware:
        # Placed immediately before the image and acceptance gates: it is an
        # input to them, and building it after the fast checks means an
        # ordinary mistake still fails in seconds rather than after a compile.
        steps.append(
            Step(
                "sbsa firmware",
                (sys.executable, str(TOOLS_DIR / "build_sbsa_firmware.py")),
            )
        )
    steps.extend(
        image_and_qemu_commands(
            skip_qemu=args.skip_qemu,
            strict_tool_versions=args.strict_tool_versions,
        )
    )
    return steps


def announce_plan(steps: list[Step]) -> None:
    """Print the ordered plan so a long run is legible before it starts."""
    total = len(steps)
    report(f"verification plan: {total} gates, one at a time")
    for index, step in enumerate(steps, start=1):
        report(f"  [{index:0{len(str(total))}d}/{total}] {step.label}")


def run_steps(steps: list[Step], *, progress_interval: float) -> None:
    """Run every gate in order, reporting start, liveness, and completion."""
    total = len(steps)
    announce_plan(steps)
    started = time.monotonic()
    for index, step in enumerate(steps, start=1):
        prefix = f"verification [{index:0{len(str(total))}d}/{total}] {step.label}"
        step_started = time.monotonic()
        report(f"{prefix}: started {time.strftime('%H:%M:%S')}")
        report(f"  {display(step.command)}")
        try:
            with LivenessReporter(prefix, step_started, progress_interval):
                subprocess.run(
                    [str(argument) for argument in step.command],
                    cwd=REPO_ROOT,
                    check=True,
                )
        except BaseException:
            print(
                f"{prefix}: failed after "
                f"{format_duration(time.monotonic() - step_started)} "
                f"({index - 1} of {total} gates passed in "
                f"{format_duration(time.monotonic() - started)})",
                file=sys.stderr,
                flush=True,
            )
            raise
        report(
            f"{prefix}: passed in "
            f"{format_duration(time.monotonic() - step_started)} "
            f"(gate elapsed {format_duration(time.monotonic() - started)})"
        )
    report(
        f"verification: {total} gates passed in "
        f"{format_duration(time.monotonic() - started)}"
    )


def main() -> int:
    try:
        require_supported_python()
    except RuntimeError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    args = parse_args()
    if args.require_filesystem_tools:
        os.environ["TROE_REQUIRE_FS_TOOLS"] = "1"

    try:
        run_steps(verification_steps(args), progress_interval=args.progress_interval)
    except FileNotFoundError as error:
        print(
            f"verification failed: command not found: {error.filename}", file=sys.stderr
        )
        return 1
    except OSError as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"verification failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    except KeyboardInterrupt:
        print("verification failed: interrupted", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
