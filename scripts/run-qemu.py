#!/usr/bin/env python3
"""Build and run a kllm boot image with QEMU 11.1.0."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_QEMU_VERSION = "11.1.0"
QEMU_EXECUTABLES = {
    "x86_64": "qemu-system-x86_64",
    "aarch64": "qemu-system-aarch64",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architecture",
        "--arch",
        choices=tuple(QEMU_EXECUTABLES),
        default="x86_64",
        help="architecture to emulate (default: x86_64)",
    )
    parser.add_argument(
        "--firmware-code",
        type=Path,
        required=True,
        help="path to the read-only UEFI firmware code image",
    )
    parser.add_argument(
        "--firmware-vars",
        type=Path,
        required=True,
        help="path to the writable UEFI variable-store template",
    )
    parser.add_argument(
        "--skip-version-check",
        action="store_true",
        help="deliberately allow a QEMU version other than 11.1.0",
    )
    return parser.parse_args()


def qemu_version(executable: str) -> str:
    result = subprocess.run(
        [executable, "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout.splitlines()[0] if result.stdout else "no version output"


def main() -> int:
    args = parse_args()
    executable_name = QEMU_EXECUTABLES[args.architecture]
    executable = shutil.which(executable_name)
    if executable is None:
        print(f"QEMU executable not found on PATH: {executable_name}", file=sys.stderr)
        return 1

    try:
        if not args.skip_version_check:
            version = qemu_version(executable)
            expected_version = rf"\bversion {re.escape(EXPECTED_QEMU_VERSION)}\b"
            if re.search(expected_version, version) is None:
                raise RuntimeError(
                    f"expected QEMU {EXPECTED_QEMU_VERSION}, got: {version} "
                    "(use --skip-version-check deliberately)"
                )

        firmware = args.firmware_code.expanduser().resolve(strict=True)
        vars_source = args.firmware_vars.expanduser().resolve(strict=True)
        subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build.py"),
                "--architecture",
                args.architecture,
            ],
            cwd=REPO_ROOT,
            check=True,
        )

        image = REPO_ROOT / "build" / f"kllm-{args.architecture}.img"
        variables = REPO_ROOT / "build" / f"qemu-vars-{args.architecture}.fd"
        shutil.copyfile(vars_source, variables)

        command = [
            executable,
            "-machine",
            "q35" if args.architecture == "x86_64" else "virt",
        ]
        if args.architecture == "aarch64":
            command.extend(("-cpu", "cortex-a72"))
        command.extend(
            (
                "-m",
                "64M" if args.architecture == "x86_64" else "128M",
                "-drive",
                f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
                "-drive",
                f"if=pflash,format=raw,unit=1,file={variables}",
                "-drive",
                f"if=virtio,format=raw,file={image}",
                "-no-reboot",
            )
        )
        return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode
    except (FileNotFoundError, OSError, RuntimeError) as error:
        print(f"QEMU launch failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"QEMU launch failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
