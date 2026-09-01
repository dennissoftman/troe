#!/usr/bin/env python3
"""Build the pinned Arm SBSA reference firmware banks from source.

QEMU's `sbsa-ref` machine boots the way certified Arm hardware does: Trusted
Firmware owns EL3 and hands its payload to a UEFI implementation in a second
flash bank. No distribution packages that pair the way `AAVMF` packages the
firmware for QEMU's own `virt` board, so both banks are built here from
commits pinned in `sbsa-firmware-sources.lock.json`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_LOCK = Path(__file__).resolve().parent / "sbsa-firmware-sources.lock.json"
DEFAULT_OUTPUT = REPO_ROOT / "build" / "sbsa-firmware"
DEFAULT_WORK = REPO_ROOT / "build" / "sbsa-firmware-work"
MANIFEST_NAME = "MANIFEST.sha256"
EPOCH = 946684800

# The reference platform lives in edk2-platforms and is built for the only
# architecture, toolchain, and target the machine is exercised with.
PLATFORM_DESCRIPTION = "Platform/Qemu/SbsaQemu/SbsaQemu.dsc"
ARCHITECTURE = "AARCH64"
TOOLCHAIN = "CLANGDWARF"
TARGET = "RELEASE"
BUILD_OUTPUT = Path("Build") / "SbsaQemu" / f"{TARGET}_{TOOLCHAIN}" / "FV"
# The flash description names both first-stage artifacts by workspace-relative
# path, so Trusted Firmware's output is staged where that description reads it.
TRUSTED_FIRMWARE_STAGE = Path("Platform") / "Qemu" / "Sbsa"
TRUSTED_FIRMWARE_PLATFORM = "qemu_sbsa"
FLASH_BANKS = ("SBSA_FLASH0.fd", "SBSA_FLASH1.fd")

# The toolchain definition concatenates its bin directory onto exactly these.
PREFIXED_TOOLS = ("clang", "llvm-ar", "llvm-objcopy")
LLVM_BIN_CANDIDATES = (
    Path("/opt/homebrew/opt/llvm/bin"),
    Path("/usr/local/opt/llvm/bin"),
    Path("/usr/lib/llvm/bin"),
    Path("/usr/bin"),
)
OPENSSL_CANDIDATES = (
    Path("/opt/homebrew/opt/openssl@3"),
    Path("/usr/local/opt/openssl@3"),
    Path("/usr"),
)


@dataclass(frozen=True)
class Repository:
    """One pinned upstream source tree."""

    name: str
    url: str
    commit: str
    release: str | None
    submodules: tuple[str, ...]


@dataclass(frozen=True)
class HostTools:
    """Absolute host tools the two builds are driven with.

    Trusted Firmware resolves a tool it cannot find on `PATH` through a `sed`
    idiom that only GNU `sed` accepts, so every tool handed to it is absolute
    and resolution never reaches that path.
    """

    git: str
    make: str
    acpi_compiler: str
    python: str
    cross_compiler: str
    host_compiler: str
    host_archiver: str
    llvm_bin: Path
    lld_bin: Path
    openssl_dir: Path


def absolute_path(value: str) -> Path:
    """Anchor one command-line path to the caller's working directory.

    Build steps run with their own working directories, so a relative path
    would silently resolve against the wrong one.
    """
    return Path(value).expanduser().absolute()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sources() -> tuple[int, list[Repository]]:
    document = load_json(SOURCE_LOCK)
    if document.get("schema") != 1:
        raise RuntimeError("unsupported SBSA firmware source lock schema")
    bank_bytes = document["bank_bytes"]
    if not isinstance(bank_bytes, int) or bank_bytes <= 0:
        raise RuntimeError("the pinned flash bank size must be a positive integer")
    repositories = [
        Repository(
            name=item["name"],
            url=item["url"],
            commit=item["commit"],
            release=item["release"],
            submodules=tuple(item["submodules"]),
        )
        for item in document["repositories"]
    ]
    expected = {"edk2", "edk2-platforms", "trusted-firmware-a"}
    if {item.name for item in repositories} != expected:
        raise RuntimeError(f"the source lock must pin exactly {sorted(expected)}")
    for item in repositories:
        if len(item.commit) != 40 or not all(c in "0123456789abcdef" for c in item.commit):
            raise RuntimeError(f"{item.name} is not pinned to a full commit identity")
    return bank_bytes, repositories


def parse_args() -> argparse.Namespace:
    bank_bytes, repositories = sources()
    releases = ", ".join(
        f"{item.name} {item.release or item.commit[:12]}" for item in repositories
    )
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=f"pinned sources: {releases}; flash banks: {bank_bytes} bytes each",
    )
    parser.add_argument(
        "--output",
        type=absolute_path,
        default=DEFAULT_OUTPUT,
        help="directory receiving both padded flash banks and their manifest",
    )
    parser.add_argument(
        "--work",
        type=absolute_path,
        default=DEFAULT_WORK,
        help="directory holding the checked-out sources and build trees",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, (os.cpu_count() or 2) - 1),
        help="parallel build jobs",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="require every pinned commit to be present already",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="verify an existing output directory without building",
    )
    parser.add_argument("--git", help="git executable")
    parser.add_argument("--make", help="GNU make executable, 3.82 or newer")
    parser.add_argument("--iasl", help="ACPICA ASL compiler")
    parser.add_argument("--llvm-bin", type=absolute_path, help="directory holding clang and lld")
    parser.add_argument("--openssl-dir", type=absolute_path, help="OpenSSL prefix with headers")
    return parser.parse_args()


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def find_tool(explicit: str | None, names: tuple[str, ...], candidates: tuple[Path, ...]) -> str:
    if explicit:
        resolved = shutil.which(explicit) if "/" not in explicit else explicit
        if resolved and Path(resolved).is_file():
            return str(Path(resolved).resolve())
        raise RuntimeError(f"required tool not found: {explicit}")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return str(Path(resolved).resolve())
    raise RuntimeError(f"required tool not found: {names[0]}")


def gnu_make(explicit: str | None) -> str:
    """Find a GNU make new enough for the `undefine` directive.

    Trusted Firmware needs 3.82 or newer for that directive alone, and macOS
    still ships 3.81 as `make`, so the newer build is looked for by its
    Homebrew name first.
    """
    resolved = find_tool(explicit, ("gmake", "make"), ())
    version = run([resolved, "--version"], capture=True).splitlines()[0]
    if not version.startswith("GNU Make"):
        raise RuntimeError(f"{resolved} is not GNU make: {version}")
    parts = (version.split()[2].split(".") + ["0"])[:2]
    release = tuple(int(part) for part in parts)
    if release < (3, 82):
        raise RuntimeError(
            f"{resolved} is GNU make {version.split()[2]}; 3.82 or newer is "
            "required (install GNU make and pass --make, or use gmake)"
        )
    return resolved


def find_llvm_bin(explicit: Path | None) -> Path:
    """Find the directory the UEFI toolchain definition prefixes tool names with.

    Only the tools it actually prefixes need to live there. The linker is
    reached by clang through `-fuse-ld=lld` and is resolved separately,
    because packagers do ship it apart from the rest of LLVM.
    """
    if explicit is not None:
        candidates: tuple[Path, ...] = (explicit,)
    else:
        clang = shutil.which("clang")
        discovered = (Path(clang).resolve().parent,) if clang else ()
        candidates = LLVM_BIN_CANDIDATES + discovered
    for candidate in candidates:
        if all((candidate / tool).is_file() for tool in PREFIXED_TOOLS):
            return candidate.resolve()
    required = ", ".join(PREFIXED_TOOLS)
    raise RuntimeError(
        f"no directory holding {required} was found; install LLVM and pass "
        "--llvm-bin"
    )


def find_lld_bin(llvm_bin: Path) -> Path:
    """Find the directory holding the LLVM linker clang will be asked for.

    The AArch64 link emits ELF, which the host linker on a macOS build cannot
    produce, so `ld.lld` has to be on the path clang searches.
    """
    if (llvm_bin / "ld.lld").is_file():
        return llvm_bin
    resolved = shutil.which("ld.lld")
    if resolved:
        return Path(resolved).resolve().parent
    raise RuntimeError("ld.lld was not found; install the LLVM linker")


def find_openssl(explicit: Path | None) -> Path:
    """Find an OpenSSL prefix whose headers the firmware signer can include."""
    for candidate in (explicit,) if explicit is not None else OPENSSL_CANDIDATES:
        if candidate is not None and (candidate / "include" / "openssl" / "sha.h").is_file():
            return candidate.resolve()
    raise RuntimeError(
        "no OpenSSL prefix with development headers was found; install "
        "OpenSSL 3 and pass --openssl-dir"
    )


def host_tools(args: argparse.Namespace) -> HostTools:
    llvm_bin = find_llvm_bin(args.llvm_bin)
    # A host compiler distinct from the cross one: Trusted Firmware builds its
    # own signing and packaging tools for this machine, not for the target.
    host_compiler = find_tool(None, ("clang", "cc", "gcc"), ())
    return HostTools(
        git=find_tool(args.git, ("git",), ()),
        make=gnu_make(args.make),
        # The reference platform compiles its own ACPI tables, and the failure
        # without this is a build rule reporting a missing command.
        acpi_compiler=find_tool(args.iasl, ("iasl",), ()),
        python=sys.executable,
        cross_compiler=str(llvm_bin / "clang"),
        host_compiler=host_compiler,
        host_archiver=find_tool(None, ("ar",), ()),
        llvm_bin=llvm_bin,
        lld_bin=find_lld_bin(llvm_bin),
        openssl_dir=find_openssl(args.openssl_dir),
    )


def checkout(repository: Repository, work: Path, tools: HostTools, offline: bool) -> Path:
    """Place one pinned commit, and only the submodules it needs, on disk.

    A recursive clone of edk2 costs about 2.3 GiB, most of it trees this
    platform never compiles, so the source lock names the submodules and they
    are initialised individually.

    That list is not only what gets compiled. A package description declares
    its include directories, and the build rejects one that is absent whether
    or not anything includes from it, so every submodule named in an
    `[Includes]` section of a package this platform references has to be on
    disk too. The host compression tool is the one entry outside that rule.
    """
    root = work / repository.name
    git = tools.git
    if not (root / ".git").is_dir():
        if offline:
            raise RuntimeError(f"{repository.name} is absent and fetching is disabled")
        root.mkdir(parents=True, exist_ok=True)
        run([git, "init", "--quiet"], cwd=root)
        run([git, "remote", "add", "origin", repository.url], cwd=root)
    elif not offline:
        # The lock is authoritative, including about where a source comes
        # from, so a checkout left by an older lock is repointed rather than
        # fetched from wherever it happens to still name.
        run([git, "remote", "set-url", "origin", repository.url], cwd=root)
    head = ""
    try:
        head = run([git, "rev-parse", "HEAD"], cwd=root, capture=True)
    except subprocess.CalledProcessError:
        head = ""
    if head != repository.commit:
        if offline:
            raise RuntimeError(
                f"{repository.name} is at {head or 'no commit'}, not the pinned "
                f"{repository.commit}, and fetching is disabled"
            )
        pinned = repository.release or repository.commit[:12]
        print(f"  fetching {repository.name} {pinned}", flush=True)
        try:
            run(
                [git, "fetch", "--quiet", "--depth", "1", "origin", repository.commit],
                cwd=root,
            )
        except subprocess.CalledProcessError:
            # A server that refuses to serve an arbitrary commit shallowly
            # still serves the history containing it.
            run([git, "fetch", "--quiet", "origin"], cwd=root)
        run([git, "checkout", "--quiet", "--force", repository.commit], cwd=root)
    for submodule in repository.submodules:
        present = root / submodule
        if present.is_dir() and any(present.iterdir()):
            continue
        if offline:
            raise RuntimeError(f"{repository.name} submodule {submodule} is absent")
        print(f"  fetching {repository.name} submodule {submodule}", flush=True)
        try:
            run(
                [git, "submodule", "update", "--init", "--depth", "1", "--", submodule],
                cwd=root,
            )
        except subprocess.CalledProcessError:
            run([git, "submodule", "update", "--init", "--", submodule], cwd=root)
    return root


def build_trusted_firmware(work: Path, tools: HostTools, jobs: int) -> tuple[Path, Path]:
    """Build the secure-world first stage and its package.

    No BL33 is packaged: the flash description preloads the UEFI volume into
    the second bank instead, which is where the reference platform expects it.
    """
    root = work / "trusted-firmware-a"
    command = [
        tools.make,
        f"-j{jobs}",
        f"PLAT={TRUSTED_FIRMWARE_PLATFORM}",
        # The pinned release predates warnings this LLVM raises, and its own
        # documented switch for that situation is to stop treating them as
        # errors rather than to patch the tree.
        "E=0",
        f"aarch64-cc={tools.cross_compiler}",
        f"HOSTCC={tools.host_compiler}",
        f"HOSTCPP={tools.host_compiler}",
        f"HOSTAS={tools.host_compiler}",
        f"HOSTLD={tools.host_compiler}",
        f"HOSTAR={tools.host_archiver}",
        f"OPENSSL_DIR={tools.openssl_dir}",
        "all",
        "fip",
    ]
    run(command, cwd=root)
    output = root / "build" / TRUSTED_FIRMWARE_PLATFORM / "release"
    first_stage = output / "bl1.bin"
    package = output / "fip.bin"
    for artifact in (first_stage, package):
        if not artifact.is_file():
            raise RuntimeError(f"Trusted Firmware did not produce {artifact.name}")
    return first_stage, package


def prepare_configuration(work: Path, edk2: Path) -> Path:
    """Create the build configuration the UEFI build reads.

    `edksetup.sh` copies three templates verbatim into a configuration
    directory and exports the environment below. Doing both here keeps the
    build independent of a shell and of whatever a previous run left behind.
    """
    configuration = work / "Conf"
    configuration.mkdir(parents=True, exist_ok=True)
    for name in ("target", "tools_def", "build_rule"):
        shutil.copyfile(
            edk2 / "BaseTools" / "Conf" / f"{name}.template",
            configuration / f"{name}.txt",
        )
    return configuration


def uefi_environment(work: Path, edk2: Path, platforms: Path, tools: HostTools) -> dict[str, str]:
    base_tools = edk2 / "BaseTools"
    configuration = prepare_configuration(work, edk2)
    environment = dict(os.environ)
    environment.update(
        {
            "WORKSPACE": str(work),
            "PACKAGES_PATH": os.pathsep.join((str(edk2), str(platforms))),
            "EDK_TOOLS_PATH": str(base_tools),
            "CONF_PATH": str(configuration),
            "PYTHON_COMMAND": tools.python,
            "PYTHONPATH": str(base_tools / "Source" / "Python"),
            # The toolchain definition concatenates this prefix directly onto
            # each tool name, so it must end with a separator.
            f"{TOOLCHAIN}_BIN": f"{tools.llvm_bin}{os.sep}",
            "PATH": os.pathsep.join(
                (
                    str(base_tools / "BinWrappers" / "PosixLike"),
                    str(base_tools / "Source" / "C" / "bin"),
                    str(tools.llvm_bin),
                    str(tools.lld_bin),
                    # The build rules invoke the ASL compiler by bare name, so
                    # an override has to reach them through the search path.
                    str(Path(tools.acpi_compiler).parent),
                    os.environ.get("PATH", ""),
                )
            ),
        }
    )
    return environment


def build_uefi(work: Path, tools: HostTools, jobs: int) -> list[Path]:
    """Build the non-secure UEFI payload and both flash images."""
    edk2 = work / "edk2"
    platforms = work / "edk2-platforms"
    environment = uefi_environment(work, edk2, platforms, tools)
    # The build invokes these by name; they are C programs, not scripts.
    run(
        [tools.make, f"-j{jobs}", "-C", str(edk2 / "BaseTools")],
        cwd=edk2,
        env=environment,
    )
    run(
        [
            tools.python,
            str(edk2 / "BaseTools" / "Source" / "Python" / "build" / "build.py"),
            "-a",
            ARCHITECTURE,
            "-t",
            TOOLCHAIN,
            "-b",
            TARGET,
            "-p",
            PLATFORM_DESCRIPTION,
            "-n",
            str(jobs),
        ],
        cwd=work,
        env=environment,
    )
    produced = [work / BUILD_OUTPUT / name for name in FLASH_BANKS]
    for artifact in produced:
        if not artifact.is_file():
            raise RuntimeError(f"the UEFI build did not produce {artifact.name}")
    return produced


def publish(banks: list[Path], output: Path, bank_bytes: int) -> None:
    """Pad both banks to the machine's flash size and record their digests.

    The machine presents two fixed-size flash devices, and refuses a backing
    file that does not fill one, so each image is zero-extended to that size.
    """
    output.mkdir(parents=True, exist_ok=True)
    lines = []
    for bank in banks:
        if bank.stat().st_size > bank_bytes:
            raise RuntimeError(f"{bank.name} is larger than one flash bank")
        destination = output / bank.name
        shutil.copyfile(bank, destination)
        with destination.open("r+b") as image:
            image.truncate(bank_bytes)
        destination.chmod(0o644)
        os.utime(destination, (EPOCH, EPOCH))
        lines.append(f"{sha256(destination)}  {destination.name}")
        print(f"  {destination.name}: {bank.stat().st_size} bytes padded to {bank_bytes}", flush=True)
    manifest = output / MANIFEST_NAME
    manifest.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
    manifest.chmod(0o644)
    os.utime(manifest, (EPOCH, EPOCH))


def verify(output: Path, bank_bytes: int) -> None:
    """Recompute every published digest and reject anything unrecorded."""
    manifest = output / MANIFEST_NAME
    if not manifest.is_file():
        raise RuntimeError(f"no firmware manifest at {manifest}")
    recorded = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if len(digest) != 64 or not name:
            raise RuntimeError(f"malformed manifest entry: {line}")
        recorded[name] = digest
    if set(recorded) != set(FLASH_BANKS):
        raise RuntimeError(f"the manifest must record exactly {list(FLASH_BANKS)}")
    for name, digest in sorted(recorded.items()):
        path = output / name
        if not path.is_file():
            raise RuntimeError(f"recorded bank is missing: {path}")
        if path.stat().st_size != bank_bytes:
            raise RuntimeError(f"{name} is not one flash bank in size")
        actual = sha256(path)
        if actual != digest:
            raise RuntimeError(f"digest mismatch for {name}: recorded {digest}, got {actual}")
        print(f"  {name}: {digest}", flush=True)


def build(args: argparse.Namespace, bank_bytes: int, repositories: list[Repository]) -> None:
    tools = host_tools(args)
    args.work.mkdir(parents=True, exist_ok=True)
    print(f"host toolchain: clang in {tools.llvm_bin}", flush=True)
    print(f"                ld.lld in {tools.lld_bin}", flush=True)
    print(f"                {tools.make}, OpenSSL in {tools.openssl_dir}", flush=True)
    print(f"                {tools.acpi_compiler}", flush=True)
    print("pinned sources:", flush=True)
    for repository in repositories:
        checkout(repository, args.work, tools, args.offline)
        print(f"  {repository.name} {repository.release or repository.commit[:12]}", flush=True)
    print("building the secure-world firmware", flush=True)
    first_stage, package = build_trusted_firmware(args.work, tools, args.jobs)
    stage = args.work / TRUSTED_FIRMWARE_STAGE
    stage.mkdir(parents=True, exist_ok=True)
    for artifact in (first_stage, package):
        shutil.copyfile(artifact, stage / artifact.name)
    print("building the UEFI firmware", flush=True)
    banks = build_uefi(args.work, tools, args.jobs)
    print("publishing both flash banks", flush=True)
    publish(banks, args.output, bank_bytes)


def main() -> int:
    args = parse_args()
    bank_bytes, repositories = sources()
    try:
        if not args.verify_only:
            if platform.system() not in ("Darwin", "Linux"):
                raise RuntimeError(f"unsupported build host: {platform.system()}")
            build(args, bank_bytes, repositories)
        print(f"verifying {args.output}", flush=True)
        verify(args.output, bank_bytes)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"SBSA firmware build failed: {error}", file=sys.stderr, flush=True)
        return 1
    print(f"SBSA reference firmware ready: {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
