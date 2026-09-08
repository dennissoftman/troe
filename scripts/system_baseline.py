"""ADR 0035 compatibility IPC, network and internally timed boot evidence."""

from __future__ import annotations

import json
import math
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path
from typing import Any

import storage_baseline as storage
from platform_profile import REPO_ROOT, PlatformProfile, shared_test_image_path

PACKAGES = REPO_ROOT / "build" / "network-baseline-packages"
NETWORK_CONTRACT = {
    "version": 1,
    "warmup": 64,
    "samples": 256,
    "udp_bytes": 1472,
    "tcp_bytes": 16384,
    "payload": "5a-with-u64le-index",
    "timer": "architecture-counter",
}
CONTRACT = {
    "version": 1,
    "ipc": {
        "paths": ["in-process", "isolated-diagnostics"],
        "payload_bytes": [0, 64, 256, 4096],
        "warmup": 64,
        "samples": 256,
        "zero_ticks": "permitted-counter-quantization",
    },
    "network": NETWORK_CONTRACT,
    "boot": {
        "samples": 5,
        "timer": "nanosecond-normalized-architecture-counter",
        "start": "post-handoff-entry",
        "end": "first-shell-prompt-ready",
        "excluded": "acceptance-ipc-benchmark-including-record-output",
    },
}
EXTRA_SOURCES = (
    "scripts/system_baseline.py",
    "kernel/src/probes.rs",
    "kernel/src/main.rs",
    "kernel/src/boot_baseline.rs",
    "kernel/src/handoff.rs",
    "kernel/src/machine.rs",
    "kernel/src/shell.rs",
    "tests/network-baseline/Cargo.toml",
    "tests/network-baseline/Cargo.lock",
    "tests/network-baseline/completion.cmpl",
    "tests/network-baseline/src/main.rs",
)


def build_probe(*, skip_build: bool) -> None:
    """Build the isolated, non-shipped network probe for both architectures."""
    if not skip_build:
        subprocess.run(
            (
                "cargo",
                "kex",
                "build",
                REPO_ROOT / "tests/network-baseline",
                "--target",
                "all",
                "--output",
                PACKAGES,
            ),
            cwd=REPO_ROOT,
            check=True,
        )
    for architecture in ("x86_64", "aarch64"):
        if not (PACKAGES / architecture / "network-baseline.kex").is_file():
            raise FileNotFoundError("build network-baseline before --skip-build")


def install_probe(profile: PlatformProfile) -> None:
    """Install only on the disposable shared FAT32 medium."""
    subprocess.run(
        (
            "mcopy",
            "-i",
            f"{shared_test_image_path(profile)}@@1048576",
            PACKAGES / profile.architecture / "network-baseline.kex",
            "::/network-baseline.kex",
        ),
        cwd=REPO_ROOT,
        check=True,
    )


def statistics(
    ticks: list[int],
    frequency: int,
    count: int,
    byte_count: int,
    *,
    allow_zero: bool = False,
) -> dict[str, Any]:
    """Recompute exact rank statistics and round-trip payload throughput."""
    if type(frequency) is not int or not 0 < frequency < 1 << 64:
        raise ValueError("invalid baseline frequency")
    if len(ticks) != count or any(
        type(tick) is not int or not int(not allow_zero) <= tick < 1 << 64
        for tick in ticks
    ):
        raise ValueError("invalid baseline sample count or ticks")
    if sum(ticks) == 0:
        raise ValueError("baseline has no elapsed ticks")
    ordered = sorted(ticks)
    total = sum(ticks)
    return {
        "ticks": ticks,
        "frequency_hz": frequency,
        "total_ticks": total,
        "p50_ticks": ordered[math.ceil(count * 0.50) - 1],
        "p95_ticks": ordered[math.ceil(count * 0.95) - 1],
        "p99_ticks": ordered[math.ceil(count * 0.99) - 1],
        "max_ticks": ordered[-1],
        "min_ticks": ordered[0],
        "bytes_per_second": count * byte_count * frequency / total,
    }


def ipc_rows(output: str) -> dict[str, Any]:
    """Pair unsorted native samples with the existing exact structural records."""
    raw = {}
    counters = {}
    for line in output.splitlines():
        if not line.startswith(("ipc-samples ", "ipc-baseline ")):
            continue
        row = storage.fields(line)
        if not {"path", "payload"} <= set(row):
            raise ValueError("missing IPC row identity")
        key = f"{row.pop('path')}/{int(row.pop('payload'))}"
        destination = raw if line.startswith("ipc-samples ") else counters
        if key in destination:
            raise ValueError("duplicate IPC baseline row")
        destination[key] = row
    expected = {
        f"{path}/{size}"
        for path in CONTRACT["ipc"]["paths"]
        for size in CONTRACT["ipc"]["payload_bytes"]
    }
    if set(raw) != expected or set(counters) != expected:
        raise ValueError("incomplete IPC baseline matrix")
    result = {}
    for key, raw_row in raw.items():
        if set(raw_row) != {"counter_hz", "ticks"}:
            raise ValueError("invalid IPC sample fields")
        size = int(key.split("/")[1])
        summary = statistics(
            [int(tick) for tick in raw_row["ticks"].split(",")],
            int(raw_row["counter_hz"]),
            256,
            size * 2,
            allow_zero=True,
        )
        counts = {name: int(value) for name, value in counters[key].items()}
        result[key] = {"measurement": summary, "counters": counts}
    validate_ipc(result)
    return result


def validate_ipc(rows: dict[str, Any]) -> None:
    """Require the current compatibility path's structural and latency matrix."""
    expected = {
        f"{path}/{size}"
        for path in CONTRACT["ipc"]["paths"]
        for size in CONTRACT["ipc"]["payload_bytes"]
    }
    if set(rows) != expected:
        raise ValueError("incomplete IPC baseline matrix")
    for key, row in rows.items():
        path, size_text = key.split("/")
        size = int(size_text)
        measurement = row["measurement"]
        if set(row) != {"measurement", "counters"} or measurement != statistics(
            measurement["ticks"],
            measurement["frequency_hz"],
            256,
            size * 2,
            allow_zero=True,
        ):
            raise ValueError("IPC statistics disagree with samples")
        copies = 256 if size else 0
        expected_counts = {
            "warmup": 64,
            "samples": 256,
            "calls": 256,
            "counter_hz": measurement["frequency_hz"],
            **{
                name: measurement[name]
                for name in ("p50_ticks", "p95_ticks", "p99_ticks", "max_ticks")
            },
            "request_bytes": size * 256,
            "reply_bytes": size * 256,
            "request_copies": 0,
            "request_allocations": 0,
            "reply_copies": copies,
            "reply_allocations": copies,
            "address_space_switches": 0,
            "tlb_invalidations": 0,
            "timer_programs": 0,
        }
        if path == "isolated-diagnostics":
            fragments = 512 if size == 4096 else 256
            boundaries = 768 if size == 4096 else 256
            expected_counts.update(
                request_copies=fragments * 2 if size else 0,
                reply_copies=fragments * 2 if size else 0,
                reply_allocations=0,
                address_space_switches=boundaries * 2,
                tlb_invalidations=boundaries * 2,
                timer_programs=boundaries,
                wire_fragments=fragments,
                retained_requests=1,
                contexts=1,
                steady_allocations=0,
            )
        if row["counters"] != expected_counts:
            raise ValueError("IPC structural counters or percentiles changed")


def network_rows(output: str) -> dict[str, Any]:
    """Require two completed, payload-verified native network rows."""
    lines = output.splitlines()
    headers = [
        index
        for index, line in enumerate(lines)
        if line.startswith("NETWORK-BASELINE ")
    ]
    if (
        len(headers) != 1
        or storage.fields(lines[headers[0]])
        != {key: str(value) for key, value in NETWORK_CONTRACT.items()}
        or lines.count("END network-baseline") != 1
    ):
        raise ValueError("incomplete network baseline contract")
    end = lines.index("END network-baseline")
    rows = {}
    for index, line in enumerate(lines):
        if not line.startswith("NETWORK "):
            continue
        fields = storage.fields(line)
        if (
            set(fields) != {"protocol", "frequency_hz", "ticks"}
            or not headers[0] < index < end
        ):
            raise ValueError("invalid network record")
        protocol = fields["protocol"]
        if protocol not in ("udp", "tcp") or protocol in rows:
            raise ValueError("duplicate or unknown network row")
        rows[protocol] = statistics(
            [int(value) for value in fields["ticks"].split(",")],
            int(fields["frequency_hz"]),
            256,
            NETWORK_CONTRACT[f"{protocol}_bytes"] * 2,
        )
    if set(rows) != {"udp", "tcp"}:
        raise ValueError("incomplete network matrix")
    return rows


def boot_record(output: str) -> dict[str, int]:
    """Require one internal interval before the first interactive prompt."""
    lines = [
        line
        for line in output.splitlines()
        if line.startswith("TROE-BOOT-BASELINE-v1 ")
    ]
    if (
        len(lines) != 1
        or output.count("TROE-BOOT-BASELINE-v1 ") != 1
        or output.index(lines[0]) > output.index("sh:/> ")
    ):
        raise ValueError("missing or misplaced boot interval")
    row = {key: int(value) for key, value in storage.fields(lines[0]).items()}
    validate_boot_record(row)
    return row


def validate_boot_record(row: dict[str, int]) -> None:
    """Check bounded counter arithmetic rather than accepting a printed delta."""
    if set(row) != {
        "start_ticks",
        "end_ticks",
        "excluded_ipc_ticks",
        "ticks",
        "counter_hz",
    } or any(
        type(value) is not int or not 0 < value < 1 << 64 for value in row.values()
    ):
        raise ValueError("invalid boot counters")
    if (
        row["end_ticks"] - row["start_ticks"] - row["excluded_ipc_ticks"]
        != row["ticks"]
    ):
        raise ValueError("boot interval arithmetic mismatch")


def normalized_boot_ticks(row: dict[str, int]) -> int:
    """Normalize each boot's calibrated raw counter to integer nanoseconds."""
    return row["ticks"] * 1_000_000_000 // row["counter_hz"]


def validate_document(document: dict[str, Any], platform_id: str) -> None:
    """Check frozen provenance, all matrices, and the five-boot median."""
    try:
        if (
            set(document) != {"adr", "contract", "provenance", "ipc", "network", "boot"}
            or document["adr"] != 35
            or document["contract"] != CONTRACT
        ):
            raise ValueError("system baseline contract changed")
        origin = document["provenance"]
        if origin["platform"] != platform_id or origin["environment"] != "qemu":
            raise ValueError("system baseline platform mismatch")
        for key in ("qemu", "rust", "host", "command", "base_commit"):
            if not origin[key]:
                raise ValueError("incomplete system baseline provenance")
        hashes = [origin["probe_sha256"]]
        for key in ("input_sha256", "source_sha256"):
            if not origin[key]:
                raise ValueError("missing baseline hashes")
            hashes.extend(origin[key].values())
        if any(
            not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value)
            for value in hashes
        ):
            raise ValueError("invalid baseline hash")
        peer = origin["network_peer"]
        if (
            set(peer) != {"host", "udp_port", "tcp_port", "tcp_nodelay"}
            or peer["host"] != "10.0.2.2"
            or peer["tcp_nodelay"] is not True
            or any(
                type(peer[key]) is not int or not 0 < peer[key] < 65536
                for key in ("udp_port", "tcp_port")
            )
        ):
            raise ValueError("invalid network peer provenance")
        validate_ipc(document["ipc"])
        if set(document["network"]) != {"udp", "tcp"}:
            raise ValueError("incomplete network matrix")
        frequencies = {
            row["measurement"]["frequency_hz"] for row in document["ipc"].values()
        }
        for protocol, row in document["network"].items():
            if row != statistics(
                row["ticks"],
                row["frequency_hz"],
                256,
                NETWORK_CONTRACT[f"{protocol}_bytes"] * 2,
            ):
                raise ValueError("network statistics disagree with samples")
            frequencies.add(row["frequency_hz"])
        boot = document["boot"]
        if set(boot) != {"records", "measurement"} or len(boot["records"]) != 5:
            raise ValueError("boot baseline requires five fresh boots")
        for row in boot["records"]:
            validate_boot_record(row)

        frequencies.add(boot["records"][0]["counter_hz"])
        if boot["measurement"] != statistics(
            [normalized_boot_ticks(row) for row in boot["records"]], 1_000_000_000, 5, 0
        ):
            raise ValueError("boot statistics disagree with samples")
        if len(frequencies) != 1:
            raise ValueError("baseline counter frequency changed")
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError("malformed system baseline") from error


def settle(document: dict[str, Any], record_directory: Path | None) -> None:
    """Never replace a frozen oracle during ordinary verification or capture."""
    platform_id = document["provenance"]["platform"]
    validate_document(document, platform_id)
    filename = f"system-{platform_id}.json"
    encoded = json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if record_directory is not None:
        record_directory.mkdir(parents=True, exist_ok=True)
        with (record_directory / filename).open("x", encoding="utf-8") as destination:
            destination.write(encoded)
    else:
        validate_document(
            json.loads((storage.FIXTURES / filename).read_text("utf-8")), platform_id
        )
        observed = REPO_ROOT / "build/system-baseline-results"
        observed.mkdir(parents=True, exist_ok=True)
        (observed / filename).write_text(encoded, "utf-8")


class NetworkPeer:
    """Verify and echo exactly 320 indexed messages per transport on local ports."""

    def __init__(self) -> None:
        self.error: Exception | None = None
        self.received = {"udp": 0, "tcp": 0}
        self.stop = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp.bind(("127.0.0.1", 0))
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(1)
        self.udp.settimeout(0.2)
        self.tcp.settimeout(0.2)
        self.threads = [
            threading.Thread(target=self.serve, args=(protocol,), daemon=True)
            for protocol in ("udp", "tcp")
        ]

    def start(self) -> None:
        """Start both bounded peer loops after all sockets have bound."""
        for thread in self.threads:
            thread.start()

    @staticmethod
    def payload(index: int, size: int) -> bytes:
        """Match the guest's explicit byte sequence, including its sample index."""
        return index.to_bytes(8, "little") + b"\x5a" * (size - 8)

    def serve(self, protocol: str) -> None:
        """Retain failures for the harness; timeouts never imply completion."""
        try:
            if protocol == "udp":
                while not self.stop.is_set() and self.received["udp"] < 320:
                    try:
                        payload, address = self.udp.recvfrom(1473)
                    except TimeoutError:
                        continue
                    if payload != self.payload(self.received["udp"], 1472):
                        raise ValueError("UDP payload or order mismatch")
                    self.udp.sendto(payload, address)
                    self.received["udp"] += 1
            else:
                while not self.stop.is_set():
                    try:
                        connection, _address = self.tcp.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        connection.settimeout(5)
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        for index in range(320):
                            payload = bytearray()
                            while len(payload) < 16384:
                                chunk = connection.recv(16384 - len(payload))
                                if not chunk:
                                    raise ValueError(
                                        "TCP stream ended before complete sample"
                                    )
                                payload.extend(chunk)
                            if payload != self.payload(index, 16384):
                                raise ValueError("TCP payload or order mismatch")
                            connection.sendall(payload)
                            self.received["tcp"] += 1
                        if connection.recv(1):
                            raise ValueError("TCP stream exceeded declared samples")
                    return
        except (OSError, ValueError) as error:
            if not self.stop.is_set():
                self.error = error

    def close(self) -> None:
        """Close sockets and wait for the finite peer timeouts."""
        self.stop.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=6)


def snapshot_inputs(command: list[str], directory: Path) -> list[tuple[Path, Path]]:
    """Save every mutable QEMU file so each boot starts from identical bytes."""
    saved = []
    for index, argument in enumerate(command):
        if "readonly=on" in argument:
            continue
        for field in argument.split(","):
            if field.startswith("file="):
                path = Path(field.removeprefix("file="))
                if path.is_relative_to(REPO_ROOT / "build"):
                    backup = directory / str(index)
                    shutil.copyfile(path, backup)
                    saved.append((path, backup))
    return saved
