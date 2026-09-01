#!/usr/bin/env python3
"""Run production-identity TROE acceptance on pinned Cloud Hypervisor/KVM."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

from cloud_hypervisor_profile import (
    PROFILE_PATH,
    CloudHypervisorProfile,
    cloud_hypervisor_command,
    load_profile,
    stage_runtime_bundle,
    verify_artifact,
    verify_host,
    verify_production_bundle,
    verify_version,
)
from platform_profile import REPO_ROOT

BOOT_TIMEOUT_SECONDS = 45.0
COMMAND_TIMEOUT_SECONDS = 15.0
STATE_PARTITION_OFFSET = 2_048 * 512
STATE_SLOT_BYTES = 1_024
STATE_DATA_BYTES = 512
STATE_PAYLOAD_OFFSET = 32
ROLLBACK_MARKERS = (
    "native generation: candidate published",
    "native generation: health rollback committed",
)


def _load_serial_acceptance() -> ModuleType:
    path = REPO_ROOT / "scripts" / "test-qemu.py"
    spec = importlib.util.spec_from_file_location("troe_serial_acceptance", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load shared serial acceptance from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SERIAL = _load_serial_acceptance()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=PROFILE_PATH)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--vmm", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--tap", required=True)
    parser.add_argument("--boot-timeout", type=float, default=BOOT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--command-timeout", type=float, default=COMMAND_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="verify immutable inputs, stage runtime copies, and print the command",
    )
    parser.add_argument(
        "--keep-runtime",
        action="store_true",
        help="retain per-machine disks and diagnostics after success or failure",
    )
    return parser.parse_args(argv)


def _paths(runtime: Path) -> tuple[Path, Path, Path]:
    return (
        runtime / "cloud-hypervisor.sock",
        runtime / "cloud-hypervisor.log",
        runtime / "events.json",
    )


def _command(
    profile: CloudHypervisorProfile,
    *,
    vmm: Path,
    firmware: Path,
    disks: dict[str, Path],
    tap: str,
    runtime: Path,
) -> list[str]:
    api_socket, log_file, event_file = _paths(runtime)
    for ephemeral in (api_socket, log_file, event_file):
        ephemeral.unlink(missing_ok=True)
    return cloud_hypervisor_command(
        profile,
        vmm=vmm,
        firmware=firmware,
        disks=disks,
        tap=tap,
        api_socket=api_socket,
        log_file=log_file,
        event_file=event_file,
    )


def _wait_for_control(
    control: Path, api_socket: Path, process: subprocess.Popen[bytes]
) -> None:
    deadline = time.monotonic() + 10.0
    last_error = "API socket did not appear"
    while time.monotonic() < deadline:
        status = process.poll()
        if status is not None:
            raise SERIAL.AcceptanceError(
                f"Cloud Hypervisor exited with status {status} before API readiness"
            )
        if api_socket.is_socket():
            completed = subprocess.run(
                [str(control), f"--api-socket={api_socket}", "ping"],
                check=False,
                capture_output=True,
                timeout=5,
            )
            if completed.returncode == 0:
                return
            last_error = completed.stderr.decode(errors="replace").strip()
        time.sleep(0.05)
    raise SERIAL.AcceptanceError(f"Cloud Hypervisor API readiness failed: {last_error}")


def _require_rollback(session: object, activation: Path, platform: str) -> None:
    transcript = session.transcript()
    for marker in ROLLBACK_MARKERS:
        if marker not in transcript:
            raise SERIAL.AcceptanceError(
                f"production boot missed rollback marker {marker!r}"
            )
    _generation, payload = SERIAL.dual_slot_state(platform, activation)
    SERIAL.assert_rolled_back_sact(platform, payload)


def _run_network(
    session: object,
    profile: CloudHypervisorProfile,
    command_timeout: float,
) -> None:
    """Exercise the exact static TAP contract without assuming host DHCP."""
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
        contains=(
            "link: ready",
            f"ipv4: {profile.network.guest.ip}",
            f"gateway: {profile.network.host.ip}",
        ),
    )
    session.command(
        f"ping {profile.network.host.ip}",
        cwd,
        command_timeout,
        contains=(f"reply from {profile.network.host.ip}", "bytes=9"),
    )
    session.command(
        "arp", cwd, command_timeout, contains=(str(profile.network.host.ip),)
    )
    before = session.command("mem", cwd, command_timeout)
    frames_before = SERIAL.parse_free_frames(before)
    SERIAL.run_resident_process_checks(session, cwd, command_timeout)
    session.command(
        (
            f"udp send --source-port 40001 {profile.network.host.ip} "
            "9 production-datagram"
        ),
        cwd,
        command_timeout,
        contains=("sent 19 bytes from port 40001",),
    )
    session.cancelled_command("udp listen 40000", cwd, command_timeout)
    session.cancelled_command(
        f"tcp {profile.network.host.ip} {profile.network.peer_port}",
        cwd,
        command_timeout,
    )
    for _ in range(5):
        session.command(
            (
                f"tcp {profile.network.host.ip} {profile.network.peer_port} "
                "troe-tcp-request"
            ),
            cwd,
            command_timeout,
            contains=("troe-tcp-reply\n",),
        )
    after = session.command("mem", cwd, command_timeout)
    if SERIAL.parse_free_frames(after) != frames_before:
        raise SERIAL.AcceptanceError("Cloud Hypervisor network workload leaked frames")


def _poweroff_and_close(session: object, command_timeout: float) -> None:
    try:
        SERIAL.request_poweroff(session, command_timeout)
    finally:
        session.close()


def _save_transcript(session: object, runtime: Path, phase: str) -> None:
    """Retain one bounded normalized serial transcript for evidence or diagnosis."""
    (runtime / f"serial-{phase}.log").write_text(session.transcript(), encoding="utf-8")


def _start_session(
    profile: CloudHypervisorProfile,
    *,
    vmm: Path,
    control: Path,
    firmware: Path,
    disks: dict[str, Path],
    tap: str,
    runtime: Path,
) -> object:
    command = _command(
        profile,
        vmm=vmm,
        firmware=firmware,
        disks=disks,
        tap=tap,
        runtime=runtime,
    )
    session = SERIAL.SerialSession(command, profile.platform)
    try:
        _wait_for_control(control, _paths(runtime)[0], session.process)
    except Exception:
        session.close()
        raise
    return session


def _run_first_boot(
    profile: CloudHypervisorProfile,
    *,
    vmm: Path,
    control: Path,
    firmware: Path,
    disks: dict[str, Path],
    tap: str,
    runtime: Path,
    boot_timeout: float,
    command_timeout: float,
) -> None:
    bind_address = str(profile.network.host.ip)
    udp = SERIAL.UdpAcceptancePeer(
        profile.platform,
        profile.environment,
        bind_address=bind_address,
        port=profile.network.peer_port,
    )
    tcp = SERIAL.TcpAcceptancePeer(
        profile.platform,
        profile.environment,
        bind_address=bind_address,
        port=profile.network.peer_port,
    )
    udp.start()
    tcp.start()
    session = None
    try:
        session = _start_session(
            profile,
            vmm=vmm,
            control=control,
            firmware=firmware,
            disks=disks,
            tap=tap,
            runtime=runtime,
        )
        session.wait_for(b"sh:/> ", boot_timeout)
        SERIAL.assert_owned_boot(session)
        SERIAL.run_boot_group(session, command_timeout)
        _run_network(session, profile, command_timeout)
        SERIAL.run_shell_terminal_group(session, command_timeout)
        SERIAL.run_lua_group(session, command_timeout)
        SERIAL.run_quota_memory_group(session, command_timeout)
        session.command(
            "printf production-persistent > /vol/root/cloud-hypervisor.txt",
            "/",
            command_timeout,
        )
        _require_rollback(session, disks["activation"], profile.platform)
        _poweroff_and_close(session, command_timeout)
    except Exception:
        if session is not None:
            session.close()
        raise
    finally:
        if session is not None:
            _save_transcript(session, runtime, "first-boot")
        udp.close()
        tcp.close()
    if udp.error is not None or udp.received == 0:
        raise SERIAL.AcceptanceError("Cloud Hypervisor UDP boot peer did not complete")
    if tcp.error is not None or tcp.received != 5:
        raise SERIAL.AcceptanceError(
            "Cloud Hypervisor TCP acceptance peer did not complete"
        )


def _run_reboot(
    profile: CloudHypervisorProfile,
    *,
    vmm: Path,
    control: Path,
    firmware: Path,
    disks: dict[str, Path],
    tap: str,
    runtime: Path,
    boot_timeout: float,
    command_timeout: float,
) -> None:
    udp = SERIAL.UdpAcceptancePeer(
        profile.platform,
        profile.environment,
        bind_address=str(profile.network.host.ip),
        port=profile.network.peer_port,
    )
    udp.start()
    session = None
    try:
        session = _start_session(
            profile,
            vmm=vmm,
            control=control,
            firmware=firmware,
            disks=disks,
            tap=tap,
            runtime=runtime,
        )
        session.wait_for(b"sh:/> ", boot_timeout)
        SERIAL.assert_owned_boot(session)
        session.command(
            "cat /vol/root/cloud-hypervisor.txt",
            "/",
            command_timeout,
            contains=("production-persistent",),
        )
        reboot_start = len(session.output)
        session.send("reboot", command_timeout)
        session.wait_for(
            b"reboot: requesting cold reset", command_timeout, reboot_start
        )
        session.wait_for(b"Welcome to TROE.", boot_timeout, reboot_start)
        session.wait_for(b"sh:/> ", boot_timeout, reboot_start)
        session.command(
            "cat /vol/root/cloud-hypervisor.txt",
            "/",
            command_timeout,
            contains=("production-persistent",),
        )
        _require_rollback(session, disks["activation"], profile.platform)
        _poweroff_and_close(session, command_timeout)
    except Exception:
        if session is not None:
            session.close()
        raise
    finally:
        if session is not None:
            _save_transcript(session, runtime, "reboot")
        udp.close()
    if udp.error is not None or udp.received < 2:
        raise SERIAL.AcceptanceError(
            "Cloud Hypervisor reboot did not repeat the native UDP exchange"
        )


def _slot_generation(image: bytes, slot: int) -> int | None:
    base = STATE_PARTITION_OFFSET + slot * STATE_SLOT_BYTES
    data = image[base : base + STATE_DATA_BYTES]
    commit = image[base + STATE_DATA_BYTES : base + STATE_SLOT_BYTES]
    if data[:8] != b"TXDTv1\0\0" or commit[:8] != b"TXCMv1\0\0":
        return None
    generation = int.from_bytes(data[8:16], "little")
    if generation == 0 or int.from_bytes(commit[8:16], "little") != generation:
        return None
    return generation


def corrupt_latest_state_slot(path: Path) -> int:
    """Invalidate only the newest StateFS slot, preserving its predecessor."""
    image = bytearray(path.read_bytes())
    candidates = [
        (generation, slot)
        for slot in range(2)
        if (generation := _slot_generation(image, slot)) is not None
    ]
    if len(candidates) != 2:
        raise ValueError("StateFS corruption test requires two committed slots")
    generation, slot = max(candidates)
    payload = STATE_PARTITION_OFFSET + slot * STATE_SLOT_BYTES + STATE_PAYLOAD_OFFSET
    image[payload] ^= 0x80
    path.write_bytes(image)
    return generation


def _run_corruption_recovery(
    profile: CloudHypervisorProfile,
    *,
    vmm: Path,
    control: Path,
    firmware: Path,
    disks: dict[str, Path],
    tap: str,
    runtime: Path,
    boot_timeout: float,
    command_timeout: float,
) -> None:
    corrupted_generation = corrupt_latest_state_slot(disks["state"])
    udp = SERIAL.UdpAcceptancePeer(
        profile.platform,
        profile.environment,
        bind_address=str(profile.network.host.ip),
        port=profile.network.peer_port,
    )
    udp.start()
    session = None
    try:
        session = _start_session(
            profile,
            vmm=vmm,
            control=control,
            firmware=firmware,
            disks=disks,
            tap=tap,
            runtime=runtime,
        )
        session.wait_for(b"sh:/> ", boot_timeout)
        SERIAL.assert_owned_boot(session)
        session.command(
            "cat /vol/root/cloud-hypervisor.txt",
            "/",
            command_timeout,
            contains=("production-persistent",),
        )
        session.command("rm /vol/root/cloud-hypervisor.txt", "/", command_timeout)
        if "native statefs: mutation committed and flushed" not in session.transcript():
            raise SERIAL.AcceptanceError(
                "StateFS predecessor recovery did not recommit"
            )
        recovered_generation, _payload = SERIAL.dual_slot_state(
            profile.platform, disks["state"]
        )
        if recovered_generation < corrupted_generation:
            raise SERIAL.AcceptanceError(
                "StateFS recovery regressed below the corrupted slot generation"
            )
        _require_rollback(session, disks["activation"], profile.platform)
        _poweroff_and_close(session, command_timeout)
    except Exception:
        if session is not None:
            session.close()
        raise
    finally:
        if session is not None:
            _save_transcript(session, runtime, "corruption-recovery")
        udp.close()
    if udp.error is not None or udp.received == 0:
        raise SERIAL.AcceptanceError(
            "Cloud Hypervisor recovery boot did not complete the native UDP exchange"
        )


def _write_evidence(
    profile: CloudHypervisorProfile,
    runtime: Path,
    bundle_manifest: dict[str, object],
) -> Path:
    evidence = {
        "checks": [
            "production-bundle",
            "api-control",
            "boot-and-owned-handoff",
            "network",
            "persistent-root",
            "failed-activation-rollback",
            "reboot",
            "statefs-corruption-recovery",
            "destroy",
        ],
        "environment": profile.environment,
        "firmware_sha256": profile.firmware.sha256,
        "platform": profile.platform,
        "schema": 1,
        "system_sha256": bundle_manifest["disks"]["system"]["sha256"],
        "vmm_sha256": profile.vmm.sha256,
    }
    path = runtime.with_name(f"{runtime.name}-acceptance-evidence.json")
    with path.open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return path


def main() -> int:
    args = parse_args()
    runtime = args.runtime_dir.expanduser().resolve(strict=False)
    keep_runtime = args.keep_runtime
    try:
        profile = load_profile(args.profile)
        if args.platform != profile.platform or args.environment != profile.environment:
            raise ValueError(
                "CLI platform/environment does not match the pinned profile"
            )
        if args.boot_timeout <= 0 or args.command_timeout <= 0:
            raise ValueError("timeouts must be positive")
        vmm = verify_artifact(args.vmm, profile.vmm, executable=True)
        control = verify_artifact(args.control, profile.control, executable=True)
        firmware = verify_artifact(args.firmware, profile.firmware, executable=False)
        verify_version(vmm, "cloud-hypervisor", profile.vmm.release)
        verify_version(control, "ch-remote", profile.control.release)
        bundle = args.bundle.expanduser().resolve(strict=True)
        manifest = verify_production_bundle(bundle, profile)
        disks = stage_runtime_bundle(bundle, runtime)
        command = _command(
            profile,
            vmm=vmm,
            firmware=firmware,
            disks=disks,
            tap=args.tap,
            runtime=runtime,
        )
        if args.dry_run:
            print(shlex.join(command))
            keep_runtime = True
            return 0
        verify_host(profile, tap=args.tap, runtime_parent=runtime.parent)
        _run_first_boot(
            profile,
            vmm=vmm,
            control=control,
            firmware=firmware,
            disks=disks,
            tap=args.tap,
            runtime=runtime,
            boot_timeout=args.boot_timeout,
            command_timeout=args.command_timeout,
        )
        _run_reboot(
            profile,
            vmm=vmm,
            control=control,
            firmware=firmware,
            disks=disks,
            tap=args.tap,
            runtime=runtime,
            boot_timeout=args.boot_timeout,
            command_timeout=args.command_timeout,
        )
        _run_corruption_recovery(
            profile,
            vmm=vmm,
            control=control,
            firmware=firmware,
            disks=disks,
            tap=args.tap,
            runtime=runtime,
            boot_timeout=args.boot_timeout,
            command_timeout=args.command_timeout,
        )
        evidence = _write_evidence(profile, runtime, manifest)
        print(f"Cloud Hypervisor production acceptance passed: {evidence}")
        return 0
    except (OSError, RuntimeError, ValueError, SERIAL.AcceptanceError) as error:
        print(f"Cloud Hypervisor acceptance failed: {error}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired as error:
        print(f"Cloud Hypervisor acceptance timed out: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if runtime.exists() and not keep_runtime:
            shutil.rmtree(runtime)


if __name__ == "__main__":
    raise SystemExit(main())
