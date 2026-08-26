#!/usr/bin/env python3
"""Run conservative verification selected from changed repository paths."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable

if __package__:
    from .platform_profile import X86_64_Q35_UEFI
    from .qemu_profile import QEMU_ENVIRONMENT
    from .repository_policy import require_supported_python
    from .test import target_clippy_commands
    from .test_scenarios import DEFAULT_SCENARIOS
else:
    from platform_profile import X86_64_Q35_UEFI
    from qemu_profile import QEMU_ENVIRONMENT
    from repository_policy import require_supported_python
    from test import target_clippy_commands
    from test_scenarios import DEFAULT_SCENARIOS


REPO_ROOT = Path(__file__).resolve().parents[1]
ALL_QEMU_SCENARIOS = DEFAULT_SCENARIOS
NETWORK_APPS = frozenset(("arp", "dhcp", "net", "ping", "tcp", "udp"))
FILESYSTEM_APPS = frozenset(
    (
        "awk",
        "cat",
        "grep",
        "hexdump",
        "ln",
        "ls",
        "printf",
        "rm",
        "sed",
        "tar",
        "wc",
    )
)
TERMINAL_APPS = frozenset(("clear", "echo", "man", "pwd"))
LOW_LEVEL_PACKAGES = frozenset(
    (
        "troe-block",
        "troe-driver",
        "troe-machine",
        "troe-memory",
        "troe-platform",
        "troe-storage",
        "troe-task",
        "troe-terminal",
        "troe-virtio",
        "troe-kernel",
    )
)
PACKAGE_SCENARIOS = {
    "troe-abi": set(ALL_QEMU_SCENARIOS),
    "troe-application": set(ALL_QEMU_SCENARIOS),
    "troe-block": {"boot", "filesystem", "persistence"},
    "troe-config": {"boot", "filesystem", "persistence"},
    "troe-content": {"boot", "filesystem", "persistence"},
    "troe-core": {"boot", "shell-terminal"},
    "troe-dispatch": set(ALL_QEMU_SCENARIOS),
    "troe-driver": {"boot", "network", "filesystem"},
    "troe-ext4": {"boot", "filesystem", "persistence"},
    "troe-fat": {"boot", "filesystem"},
    "troe-gpt": {"boot", "filesystem", "persistence"},
    "troe-identity": {"boot", "persistence"},
    "troe-machine": {"boot", "network", "filesystem", "fault-isolation"},
    "troe-memory": {"boot", "quota-memory", "fault-isolation"},
    "troe-mount": {"boot", "filesystem"},
    "troe-net": {"boot", "network"},
    "troe-persist": {"boot", "persistence", "fault-isolation"},
    "troe-platform": {"boot", "network", "framebuffer-keyboard"},
    "troe-shell": {"boot", "shell-terminal", "filesystem"},
    "troe-statefs": {"boot", "filesystem", "persistence", "fault-isolation"},
    "troe-storage": {"boot", "filesystem", "persistence", "fault-isolation"},
    "troe-task": {"boot", "quota-memory", "fault-isolation"},
    "troe-terminal": {"boot", "shell-terminal", "framebuffer-keyboard"},
    "troe-vfs": {"boot", "filesystem", "quota-memory"},
    "troe-virtio": {"boot", "network", "filesystem"},
    "troe-host": {"shell-terminal", "filesystem"},
    "troe-kernel": set(ALL_QEMU_SCENARIOS),
    "troe-kex": set(ALL_QEMU_SCENARIOS),
    "troe-kex-alloc": {"lua"},
    "troe-kex-tool": set(ALL_QEMU_SCENARIOS),
}
PYTHON_IMPACTS = {
    "config/volumes.toml": (
        "test_mkshared.py",
        "test_mkstorage.py",
        "test_cloud_artifacts.py",
    ),
    "scripts/audit.py": ("test_audit_policy.py",),
    "scripts/build.py": ("test_build_policy.py", "test_cloud_artifacts.py"),
    "scripts/platform_profile.py": ("test_build_policy.py", "test_qemu_profile.py"),
    "scripts/qemu_profile.py": ("test_cloud_artifacts.py", "test_qemu_profile.py"),
    "scripts/repository_policy.py": ("test_repository_policy.py",),
    "tools/elf2kex.py": ("test_elf2kex.py",),
    "tools/gen_kex_corpus.py": ("test_elf2kex.py",),
    "tools/mkcloud.py": ("test_cloud_artifacts.py",),
    "tools/mkconfig.py": ("test_cloud_artifacts.py",),
    "tools/mkcontent.py": ("test_cloud_artifacts.py", "test_identity_provisioning.py"),
    "tools/mkefs.py": ("test_image_builders.py",),
    "tools/mkfat.py": ("test_cloud_artifacts.py", "test_image_builders.py"),
    "tools/mkidentity.py": ("test_identity_provisioning.py",),
    "tools/mkstorage.py": ("test_cloud_artifacts.py", "test_mkstorage.py"),
    "tools/mkshared.py": (
        "test_mkshared.py",
        "test_mkstorage.py",
        "test_qemu_profile.py",
    ),
    "tools/cloud-environments.json": (
        "test_cloud_artifacts.py",
        "test_qemu_profile.py",
    ),
    "tools/platforms.json": (
        "test_build_policy.py",
        "test_qemu_profile.py",
        "test_repository_policy.py",
    ),
    "tools/qemu-firmware-profile.json": ("test_qemu_profile.py",),
    "tools/size_report.py": ("test_build_policy.py",),
}
RUNTIME_TOOL_SCENARIOS = {
    "config/volumes.toml": ("boot", "filesystem"),
    "scripts/build.py": ("boot",),
    "tools/mkcloud.py": ("boot", "filesystem", "persistence"),
    "tools/mkconfig.py": ("boot", "persistence"),
    "tools/mkcontent.py": ("boot", "persistence"),
    "tools/mkefs.py": ("boot", "filesystem"),
    "tools/mkfat.py": ("boot",),
    "tools/mkstorage.py": ("boot", "filesystem", "persistence"),
    "tools/mkshared.py": ("boot", "filesystem"),
    "tools/size_report.py": ("boot",),
}
FULL_GATE_PATHS = frozenset(
    (
        ".cargo/config.toml",
        "Cargo.lock",
        "Cargo.toml",
        "rust-toolchain.toml",
        "scripts/test.py",
        "scripts/test_changed.py",
        "scripts/test_scenarios.py",
        "tests/test_test_selection.py",
    )
)


@dataclass(frozen=True)
class WorkspacePackage:
    """One workspace package and the package names that directly consume it."""

    name: str
    root: PurePosixPath
    reverse_dependencies: frozenset[str]


@dataclass
class TestPlan:
    """Ordered selected commands plus human-auditable selection reasons."""

    changed_paths: tuple[PurePosixPath, ...]
    full_reasons: list[str] = field(default_factory=list)
    rust_packages: set[str] = field(default_factory=set)
    python_tests: set[str] = field(default_factory=set)
    applications: set[str] = field(default_factory=set)
    all_applications: bool = False
    run_fmt: bool = False
    run_audit: bool = False
    run_host_smoke: bool = False
    qemu_scenarios: set[str] = field(default_factory=set)
    qemu_all_platforms: bool = False
    reasons: dict[str, set[str]] = field(default_factory=dict)

    def note(self, item: str, path: PurePosixPath) -> None:
        """Record why one path selected an item."""
        self.reasons.setdefault(item, set()).add(path.as_posix())

    def require_full(self, path: PurePosixPath, reason: str) -> None:
        """Fail closed when an impact cannot be bounded soundly."""
        self.full_reasons.append(f"{path.as_posix()}: {reason}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        default="HEAD",
        help="Git revision to compare with the index, worktree, and untracked files",
    )
    parser.add_argument(
        "--full", action="store_true", help="run the canonical exhaustive gate"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="print commands without executing them"
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print changed-path reasons for every selected gate",
    )
    parser.add_argument(
        "--skip-qemu",
        action="store_true",
        help="omit focused QEMU groups when the pinned runner is unavailable",
    )
    parser.add_argument(
        "--require-filesystem-tools",
        action="store_true",
        help="make missing filesystem interoperability tools a failure",
    )
    return parser.parse_args(argv)


def _git_lines(*arguments: str) -> tuple[str, ...]:
    result = subprocess.run(
        ("git", *arguments),
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return tuple(line for line in result.stdout.splitlines() if line)


def changed_paths(base: str) -> tuple[PurePosixPath, ...]:
    """Return committed, staged, unstaged, and untracked paths after one base."""
    tracked = _git_lines(
        "diff",
        "--name-only",
        "--no-renames",
        "--diff-filter=ACDMRTUXB",
        base,
        "--",
    )
    untracked = _git_lines("ls-files", "--others", "--exclude-standard")
    return tuple(sorted({PurePosixPath(path) for path in (*tracked, *untracked)}))


def workspace_packages() -> dict[str, WorkspacePackage]:
    """Load workspace roots and reverse edges from Cargo's authoritative metadata."""
    result = subprocess.run(
        ("cargo", "metadata", "--format-version", "1", "--no-deps"),
        cwd=REPO_ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    raw_packages = {
        package["name"]: package
        for package in metadata["packages"]
        if package["id"] in members
    }
    reverse: dict[str, set[str]] = {name: set() for name in raw_packages}
    for consumer, package in raw_packages.items():
        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if dependency_name in reverse:
                reverse[dependency_name].add(consumer)
    packages: dict[str, WorkspacePackage] = {}
    for name, package in raw_packages.items():
        manifest = Path(package["manifest_path"]).resolve()
        root = PurePosixPath(manifest.parent.relative_to(REPO_ROOT).as_posix())
        packages[name] = WorkspacePackage(name, root, frozenset(reverse[name]))
    return packages


def reverse_closure(
    roots: Iterable[str], packages: dict[str, WorkspacePackage]
) -> set[str]:
    """Return changed packages and every transitive workspace consumer."""
    selected = set(roots)
    pending = list(selected)
    while pending:
        package = pending.pop()
        for consumer in packages[package].reverse_dependencies:
            if consumer not in selected:
                selected.add(consumer)
                pending.append(consumer)
    return selected


def package_for_path(
    path: PurePosixPath, packages: dict[str, WorkspacePackage]
) -> str | None:
    """Resolve the deepest workspace package root that owns a changed path."""
    matches = [
        package
        for package in packages.values()
        if path == package.root or package.root in path.parents
    ]
    if not matches:
        return None
    return max(matches, key=lambda package: len(package.root.parts)).name


def _add_python(plan: TestPlan, path: PurePosixPath, *tests: str) -> None:
    for test in tests:
        plan.python_tests.add(test)
        plan.note(f"python:{test}", path)


def _add_qemu(plan: TestPlan, path: PurePosixPath, *scenarios: str) -> None:
    plan.qemu_scenarios.update(scenarios)
    for scenario in scenarios:
        plan.note(f"qemu:{scenario}", path)


def _classify_app(plan: TestPlan, path: PurePosixPath) -> bool:
    if not path.parts or path.parts[0] != "apps":
        return False
    plan.run_fmt = True
    if len(path.parts) == 2 and path.name == "common.rs":
        plan.all_applications = True
        plan.note("kex:all", path)
        _add_qemu(plan, path, *ALL_QEMU_SCENARIOS)
        return True
    if len(path.parts) < 2:
        plan.require_full(path, "application catalog root changed")
        return True
    application = path.parts[1]
    plan.applications.add(application)
    plan.note(f"kex:{application}", path)
    if path.name in {"Cargo.toml", "Cargo.lock"}:
        _add_python(plan, path, "test_repository_policy.py")
    if application in NETWORK_APPS:
        _add_qemu(plan, path, "network")
    elif application in FILESYSTEM_APPS:
        _add_qemu(plan, path, "filesystem")
    elif application == "mem":
        _add_qemu(plan, path, "quota-memory")
    elif application == "sleep":
        _add_qemu(plan, path, "network", "shell-terminal")
    elif application == "lua":
        _add_qemu(plan, path, "lua")
    elif application in TERMINAL_APPS:
        _add_qemu(plan, path, "shell-terminal")
    else:
        _add_qemu(plan, path, *ALL_QEMU_SCENARIOS)
    return True


def build_plan(
    paths: Iterable[PurePosixPath], packages: dict[str, WorkspacePackage]
) -> TestPlan:
    """Conservatively map changes to tests, falling back to the full gate."""
    normalized = tuple(sorted(set(paths)))
    plan = TestPlan(normalized)
    changed_packages: set[str] = set()

    for path in normalized:
        path_text = path.as_posix()
        if path_text in FULL_GATE_PATHS or path_text.startswith(".github/workflows/"):
            plan.require_full(path, "global verification or dependency policy changed")
            continue

        package = package_for_path(path, packages)
        if package is not None:
            changed_packages.add(package)
            plan.run_fmt = True
            plan.note(f"rust:{package}", path)
            for scenario in PACKAGE_SCENARIOS.get(package, set()):
                _add_qemu(plan, path, scenario)
            if package in LOW_LEVEL_PACKAGES:
                plan.qemu_all_platforms = True
            if package == "troe-kex-tool":
                _add_python(plan, path, "test_elf2kex.py", "test_kex_tool.py")
                plan.all_applications = True
                plan.note("kex:all", path)
            elif package == "troe-kex":
                _add_python(plan, path, "test_kex_tool.py")
                plan.all_applications = True
                plan.note("kex:all", path)
            elif package == "troe-kex-alloc":
                plan.applications.add("lua")
                plan.note("kex:lua", path)
            continue

        if _classify_app(plan, path):
            continue

        if path_text.startswith("tests/test_") and path.suffix == ".py":
            _add_python(plan, path, path.name)
            continue
        if path_text in PYTHON_IMPACTS:
            _add_python(plan, path, *PYTHON_IMPACTS[path_text])
            if path_text == "scripts/audit.py":
                plan.run_audit = True
            if path_text in {
                "scripts/platform_profile.py",
                "scripts/qemu_profile.py",
                "tools/cloud-environments.json",
                "tools/platforms.json",
                "tools/qemu-firmware-profile.json",
            }:
                plan.qemu_all_platforms = True
                _add_qemu(plan, path, *ALL_QEMU_SCENARIOS)
            if path_text in RUNTIME_TOOL_SCENARIOS:
                plan.qemu_all_platforms = True
                _add_qemu(plan, path, *RUNTIME_TOOL_SCENARIOS[path_text])
            continue
        if path_text in {"scripts/test-qemu.py", "scripts/run-qemu.py"}:
            _add_python(plan, path, "test_qemu_profile.py")
            _add_qemu(plan, path, *ALL_QEMU_SCENARIOS)
            plan.qemu_all_platforms = True
            continue
        if path_text == "tests/smoke.sh":
            plan.run_host_smoke = True
            plan.note("host-smoke", path)
            _add_qemu(plan, path, "shell-terminal", "filesystem")
            continue
        if path_text.startswith("rootfs/bin/"):
            application = path.stem
            plan.applications.add(application)
            plan.note(f"kex:{application}", path)
            _add_python(plan, path, "test_kex_tool.py", "test_image_builders.py")
            continue
        if path_text.startswith("rootfs/"):
            _add_python(plan, path, "test_image_builders.py")
            plan.run_host_smoke = True
            plan.note("host-smoke", path)
            _add_qemu(plan, path, "boot", "shell-terminal", "filesystem")
            continue
        if path_text.startswith("assets/"):
            _add_python(
                plan,
                path,
                "test_cloud_artifacts.py",
                "test_image_builders.py",
                "test_qemu_profile.py",
            )
            _add_qemu(plan, path, "boot", "filesystem", "persistence")
            plan.qemu_all_platforms = True
            continue
        if path_text in {"THIRD_PARTY.md", "tools/rustsec-exceptions.json"}:
            plan.run_audit = True
            plan.note("audit", path)
            _add_python(plan, path, "test_audit_policy.py", "test_repository_policy.py")
            continue
        if (
            path.suffix == ".md"
            or path_text.startswith("docs/")
            or path_text.startswith("skills/")
        ):
            _add_python(plan, path, "test_repository_policy.py")
            continue
        plan.require_full(path, "no reviewed impact rule")

    if changed_packages:
        plan.rust_packages.update(reverse_closure(changed_packages, packages))
        for package in plan.rust_packages:
            plan.note(f"rust:{package}", PurePosixPath("Cargo reverse dependency"))
    if plan.all_applications:
        plan.applications.clear()
    return plan


def commands_for_plan(
    plan: TestPlan,
    *,
    skip_qemu: bool,
    require_filesystem_tools: bool,
) -> list[tuple[str, ...]]:
    """Render one stable command sequence from a selected plan."""
    if plan.full_reasons:
        command = [sys.executable, str(REPO_ROOT / "scripts" / "test.py")]
        if skip_qemu:
            command.append("--skip-qemu")
        if require_filesystem_tools:
            command.append("--require-filesystem-tools")
        return [tuple(command)]

    commands: list[tuple[str, ...]] = []
    if plan.run_fmt:
        commands.append(("cargo", "fmt", "--all", "--", "--check"))
        format_applications = (
            sorted(
                path.name
                for path in (REPO_ROOT / "apps").iterdir()
                if path.is_dir() and (path / "Cargo.toml").is_file()
            )
            if plan.all_applications
            else sorted(plan.applications)
        )
        for application in format_applications:
            manifest = REPO_ROOT / "apps" / application / "Cargo.toml"
            commands.append(
                ("cargo", "fmt", "--manifest-path", str(manifest), "--", "--check")
            )
    for package in sorted(plan.rust_packages):
        commands.append(
            ("cargo", "clippy", "-p", package, "--all-targets", "--", "-D", "warnings")
        )
    if "troe-kernel" in plan.rust_packages:
        commands.extend(
            tuple(str(argument) for argument in command)
            for command in target_clippy_commands()
        )
    for package in sorted(plan.rust_packages):
        commands.append(("cargo", "test", "-p", package))
    for test in sorted(plan.python_tests):
        commands.append(
            (
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(REPO_ROOT / "tests"),
                "-p",
                test,
            )
        )
    if plan.run_audit:
        commands.append((sys.executable, str(REPO_ROOT / "scripts" / "audit.py")))
    applications = (
        sorted(
            path.name
            for path in (REPO_ROOT / "apps").iterdir()
            if path.is_dir() and (path / "Cargo.toml").is_file()
        )
        if plan.all_applications
        else sorted(plan.applications)
    )
    for application in applications:
        commands.append(
            (
                "cargo",
                "kex",
                "build",
                str(REPO_ROOT / "apps" / application),
                "--target",
                "all",
                "--check",
            )
        )
    if plan.run_host_smoke:
        commands.append(
            (
                "cargo",
                "run",
                "--quiet",
                "-p",
                "troe-host",
                "--",
                "--script",
                str(REPO_ROOT / "tests" / "smoke.sh"),
            )
        )
    if plan.qemu_scenarios and not skip_qemu:
        qemu = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "test-qemu.py"),
            "--platform",
            "all" if plan.qemu_all_platforms else X86_64_Q35_UEFI,
            "--environment",
            QEMU_ENVIRONMENT,
        ]
        for scenario in sorted(plan.qemu_scenarios):
            qemu.extend(("--scenario", scenario))
        if "framebuffer-keyboard" in plan.qemu_scenarios:
            qemu.extend(("--framebuffer-console", "--native-keyboard"))
        commands.append(tuple(qemu))
    return commands


def _display(command: tuple[str, ...]) -> str:
    """Render argv without implying shell evaluation semantics."""
    return " ".join(
        repr(argument) if any(c.isspace() for c in argument) else argument
        for argument in command
    )


def main() -> int:
    try:
        require_supported_python()
    except RuntimeError as error:
        print(f"focused verification failed: {error}", file=sys.stderr)
        return 1
    args = parse_args()
    if args.require_filesystem_tools:
        os.environ["TROE_REQUIRE_FS_TOOLS"] = "1"
    try:
        paths = () if args.full else changed_paths(args.base)
        packages = workspace_packages()
        plan = TestPlan(tuple()) if args.full else build_plan(paths, packages)
        if args.full:
            plan.full_reasons.append("--full requested")
        commands = commands_for_plan(
            plan,
            skip_qemu=args.skip_qemu,
            require_filesystem_tools=args.require_filesystem_tools,
        )
        if not commands:
            print(f"focused verification: no changes relative to {args.base}")
            return 0
        if plan.full_reasons:
            print("focused verification widened to the full gate:")
            for reason in plan.full_reasons:
                print(f"  - {reason}")
        elif args.explain:
            print("focused verification impact reasons:")
            for item in sorted(plan.reasons):
                print(f"  - {item}: {', '.join(sorted(plan.reasons[item]))}")
        print("focused verification commands:")
        for command in commands:
            print(f"  {_display(command)}")
        if args.dry_run:
            return 0
        for command in commands:
            subprocess.run(command, cwd=REPO_ROOT, check=True)
    except (
        FileNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        print(f"focused verification failed: {error}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(
            f"focused verification failed: command exited with status {error.returncode}",
            file=sys.stderr,
        )
        return error.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
