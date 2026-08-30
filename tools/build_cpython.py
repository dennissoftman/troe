#!/usr/bin/env python3
"""Build authenticated, reproducible static CPython KEX runtime trees."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from tools import mkshared
except ImportError:  # Direct execution from tools/.
    import mkshared  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "apps" / "python"
SOURCE_LOCK = APP_ROOT / "sources.lock.json"
STDLIB_POLICY = APP_ROOT / "stdlib-policy.json"
PATCH = APP_ROOT / "patches" / "troe.patch"
SETUP_LOCAL = APP_ROOT / "config" / "Setup.local"
SETUP_LOCAL_OLDER = APP_ROOT / "config" / "Setup.local.3.12-3.13"
CONFIG_SITE = APP_ROOT / "config" / "config.site"
CONFIGURE_STUBS = APP_ROOT / "config" / "configure-stubs.c"
EPOCH = "946684800"
MANIFEST_NAME = "MANIFEST.sha256"
# Optional runtimes share one architecture-split layout on the medium:
# executables in bin/<architecture>, libraries in lib/<architecture>.
MEDIA_DIRECTORIES = (PurePosixPath("bin"), PurePosixPath("lib"))
DIAGNOSTICS_DIRECTORY = PurePosixPath("cpython-diagnostics") / "v1"
NEGATIVE_VARIANTS = ("python-no-random", "python-no-mutate", "python-no-clock")
ARCHITECTURES = {
    "x86_64": "x86_64-unknown-linux-musl",
    "aarch64": "aarch64-unknown-linux-musl",
}
DEFAULT_VERSION = "3.14.7"
# Bundled dependency archives that the reviewed static modules link.
VENDORED_ARCHIVES = (
    "Modules/_decimal/libmpdec/libmpdec.a",
    "Modules/expat/libexpat.a",
)
HACL_ARCHIVES = (
    "Modules/_hacl/libHacl_Hash_MD5.a",
    "Modules/_hacl/libHacl_Hash_SHA1.a",
    "Modules/_hacl/libHacl_Hash_SHA2.a",
    "Modules/_hacl/libHacl_Hash_SHA3.a",
    "Modules/_hacl/libHacl_Hash_BLAKE2.a",
    "Modules/_hacl/libHacl_HMAC.a",
)


@dataclass(frozen=True)
class Release:
    version: str
    series: str
    url: str
    sha256: str
    sigstore_url: str
    certificate_identity: str
    certificate_oidc_issuer: str

    @property
    def archive_name(self) -> str:
        return f"Python-{self.version}.tar.xz"


def absolute_path(value: str) -> Path:
    """Anchor one command-line path to the caller's working directory.

    Build steps run with their own working directories, so a relative path
    would silently resolve against the wrong one; ``configure`` in particular
    is invoked from the per-architecture build directory.
    """
    return Path(value).expanduser().absolute()


def parse_args() -> argparse.Namespace:
    lock = load_json(SOURCE_LOCK)
    versions = tuple(item["version"] for item in lock["releases"])
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    verify = subparsers.add_parser("verify", help="verify one built package tree")
    verify.add_argument("tree", type=absolute_path)
    install_image_parser = subparsers.add_parser(
        "install-image", help="install one package below /cpython on shared media"
    )
    install_image_parser.add_argument("tree", type=absolute_path)
    install_image_parser.add_argument("--image", type=absolute_path, required=True)
    verify_image_parser = subparsers.add_parser(
        "verify-image", help="verify one installed package on shared media"
    )
    verify_image_parser.add_argument("tree", type=absolute_path)
    verify_image_parser.add_argument("--image", type=absolute_path, required=True)
    install_diagnostics_parser = subparsers.add_parser(
        "install-diagnostics", help="install capability-negative interpreters"
    )
    install_diagnostics_parser.add_argument("tree", type=absolute_path)
    install_diagnostics_parser.add_argument("--image", type=absolute_path, required=True)
    install_packages_parser = subparsers.add_parser(
        "install-packages", help="install pure-Python packages onto shared media"
    )
    install_packages_parser.add_argument("source", type=absolute_path)
    install_packages_parser.add_argument("--image", type=absolute_path, required=True)
    variants = subparsers.add_parser(
        "variants", help="link capability-negative interpreters for acceptance"
    )
    variants.add_argument(
        "output", type=absolute_path, help="empty diagnostics output directory"
    )
    variants.add_argument("--work-directory", type=absolute_path, required=True)
    variants.add_argument("--architecture", choices=("all", *ARCHITECTURES), default="all")
    variants.add_argument("--cc", help="LLVM clang executable")
    build = subparsers.add_parser("build", help="build one authenticated package")
    build.add_argument("output", type=absolute_path, help="empty package output directory")
    build.add_argument(
        "--source-cache",
        type=absolute_path,
        required=True,
        help="cache for pinned archives and Sigstore bundles",
    )
    build.add_argument(
        "--version",
        choices=("all", *versions),
        default="all",
        help="release to build; all preserves lock-file order",
    )
    build.add_argument(
        "--architecture",
        choices=("all", *ARCHITECTURES),
        default="all",
    )
    build.add_argument("--cc", help="LLVM clang executable")
    build.add_argument("--ar", help="LLVM archiver executable")
    build.add_argument("--sigstore", help="Sigstore CLI executable")
    build.add_argument(
        "--build-python",
        action="append",
        default=[],
        metavar="SERIES=PATH",
        help="exact-series build Python override; repeat for multiple series",
    )
    build.add_argument(
        "--offline",
        action="store_true",
        help="reject missing cached source or signature files",
    )
    build.add_argument(
        "--work-directory",
        type=absolute_path,
        help="empty persistent work directory (retained for inspection)",
    )
    build.add_argument(
        "--check",
        action="store_true",
        help="build twice in independent directories and compare every output byte",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    normalize_file(path)


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


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def normalize_file(path: Path, executable: bool = False) -> None:
    path.chmod(0o755 if executable else 0o644)
    os.utime(path, (int(EPOCH), int(EPOCH)))


def releases() -> list[Release]:
    document = load_json(SOURCE_LOCK)
    if document.get("schema") != 1:
        raise RuntimeError("unsupported CPython source lock schema")
    result = [Release(**item) for item in document["releases"]]
    if [item.version for item in result][:1] != [DEFAULT_VERSION]:
        raise RuntimeError("the first pinned release must be the default CPython")
    return result


def find_tool(explicit: str | None, names: tuple[str, ...], candidates: tuple[str, ...]) -> str:
    if explicit:
        resolved = shutil.which(explicit) if "/" not in explicit else explicit
        if resolved and Path(resolved).is_file():
            return str(Path(resolved).resolve())
        raise RuntimeError(f"required tool not found: {explicit}")
    for candidate in candidates:
        if Path(candidate).is_file():
            return str(Path(candidate).resolve())
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return str(Path(resolved).resolve())
    raise RuntimeError(f"required tool not found: {names[0]}")


def find_rust_lld() -> str:
    rustc = shutil.which("rustc")
    if rustc is None:
        raise RuntimeError("required tool not found: rustc")
    details = run([rustc, "-vV"], capture=True)
    host = next(
        (line.split(":", 1)[1].strip() for line in details.splitlines() if line.startswith("host:")),
        None,
    )
    if host is None:
        raise RuntimeError("rustc did not report its host target")
    sysroot = Path(run([rustc, "--print", "sysroot"], capture=True))
    lld = sysroot / "lib" / "rustlib" / host / "bin" / "rust-lld"
    if not lld.is_file():
        raise RuntimeError(f"Rust LLD is missing: {lld}")
    return str(lld.resolve())


def parse_build_python(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise RuntimeError(f"invalid --build-python value: {value}")
        series, path = value.split("=", 1)
        if series in result:
            raise RuntimeError(f"duplicate build Python override: {series}")
        result[series] = str(Path(path).resolve())
    return result


def find_build_python(series: str, overrides: dict[str, str]) -> str:
    candidates: list[str] = []
    if series in overrides:
        candidates.append(overrides[series])
    resolved = shutil.which(f"python{series}")
    if resolved:
        candidates.append(resolved)
    candidates.extend(
        [
            f"/Library/Frameworks/Python.framework/Versions/{series}/bin/python{series}",
            f"/opt/homebrew/bin/python{series}",
            f"/usr/local/bin/python{series}",
        ]
    )
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file():
            continue
        actual = run(
            [str(path), "-c", "import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')"],
            capture=True,
        )
        if actual == series:
            return str(path.resolve())
    raise RuntimeError(
        f"CPython {series} is required to cross-build that release; "
        f"pass --build-python {series}=PATH"
    )


def download(url: str, destination: Path, offline: bool) -> None:
    if destination.is_file():
        return
    if offline:
        raise RuntimeError(f"offline source cache entry is missing: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".partial")
    request = urllib.request.Request(url, headers={"User-Agent": "TROE reproducible builder"})
    with urllib.request.urlopen(request) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output)
    temporary.replace(destination)
    normalize_file(destination)


def authenticate_source(release: Release, cache: Path, sigstore: str, offline: bool) -> Path:
    archive = cache / release.archive_name
    bundle = cache / f"{release.archive_name}.sigstore"
    download(release.url, archive, offline)
    actual = sha256(archive)
    if actual != release.sha256:
        raise RuntimeError(
            f"digest mismatch for {archive.name}: expected {release.sha256}, got {actual}"
        )
    download(release.sigstore_url, bundle, offline)
    run(
        [
            sigstore,
            "verify",
            "identity",
            "--offline",
            "--bundle",
            str(bundle),
            "--cert-identity",
            release.certificate_identity,
            "--cert-oidc-issuer",
            release.certificate_oidc_issuer,
            str(archive),
        ]
    )
    return archive


def extract_source(archive: Path, destination: Path, release: Release) -> Path:
    destination.mkdir(parents=True)
    expected_root = f"Python-{release.version}"
    with tarfile.open(archive, "r:xz") as bundle:
        names = {Path(member.name).parts[0] for member in bundle.getmembers() if member.name}
        if names != {expected_root}:
            raise RuntimeError(f"unexpected archive roots in {archive}: {sorted(names)}")
        bundle.extractall(destination, filter="data")
    source = destination / expected_root
    run(["patch", "--batch", "--forward", "-p1", "-i", str(PATCH)], cwd=source)
    return source


def compiler_flags(source: Path, build: Path, architecture: str) -> list[str]:
    flags = [
        "-O2",
        "-g0",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fPIC",
        "-ffunction-sections",
        "-fdata-sections",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-fvisibility=hidden",
        f"-ffile-prefix-map={source}=/usr/src/cpython",
        f"-fdebug-prefix-map={source}=/usr/src/cpython",
        f"-ffile-prefix-map={build}=/usr/src/cpython-build",
        f"-fdebug-prefix-map={build}=/usr/src/cpython-build",
    ]
    if architecture == "x86_64":
        flags.extend(
            [
                "-mno-red-zone",
                "-msse2",
                "-mfpmath=sse",
                "-mno-avx",
                "-mno-avx2",
                "-mno-avx512f",
            ]
        )
    else:
        flags.append("-march=armv8-a+simd")
    return flags


def make_compiler_wrapper(
    path: Path,
    cc: str,
    lld: str,
    sysroot: Path,
    architecture: str,
) -> None:
    resource = run([cc, "-print-resource-dir"], capture=True)
    arguments = [
        cc,
        f"--target={ARCHITECTURES[architecture]}",
        "-U__linux__",
        "-U__linux",
        "-Ulinux",
        "-D__TROE__=1",
        f"--ld-path={lld}",
        "-nostdlibinc",
        "-isystem",
        str(Path(resource) / "include"),
        "-I",
        str(APP_ROOT / "include"),
        "-I",
        str(sysroot / architecture / "include"),
    ]
    path.write_text(
        "#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in arguments) + ' "$@"\n',
        encoding="utf-8",
    )
    normalize_file(path, executable=True)


def build_configure_stub(
    wrapper: Path, output: Path, source: Path, build: Path, architecture: str
) -> None:
    run(
        [
            str(wrapper),
            *compiler_flags(source, build, architecture),
            "-std=c11",
            "-c",
            str(CONFIGURE_STUBS),
            "-o",
            str(output),
        ]
    )


def configure_options(release: Release, architecture: str, build_python: str) -> list[str]:
    options = [
        f"--host={architecture}-unknown-none",
        f"--with-build-python={build_python}",
        f"--prefix=/vol/shared/lib/{architecture}/python{release.version}",
        "--disable-shared",
        "--without-ensurepip",
        "--without-pkg-config",
        "--disable-ipv6",
        "--disable-test-modules",
        "--without-readline",
        "--with-tzpath=",
        # CPython probes computed gotos by running a test program, so a cross
        # build cannot answer it and configure falls back to "no" unless the
        # option is explicit. Requesting it keeps the threaded interpreter
        # dispatch that the hosted builds select for themselves.
        "--with-computed-gotos",
    ]
    if release.series in {"3.14", "3.13"}:
        options.append("--without-mimalloc")
    if release.series == "3.14":
        options.append("--with-remote-debug=no")
    return options


def build_library(
    release: Release,
    source: Path,
    workspace: Path,
    sysroot: Path,
    architecture: str,
    cc: str,
    archiver: str,
    lld: str,
    build_python: str,
) -> Path:
    build = workspace / "build" / release.version / architecture
    build.mkdir(parents=True)
    wrapper = workspace / "tools" / f"cc-{release.version}-{architecture}"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    make_compiler_wrapper(wrapper, cc, lld, sysroot, architecture)
    stub = workspace / "tools" / f"configure-stubs-{release.version}-{architecture}.o"
    build_configure_stub(wrapper, stub, source, build, architecture)
    flags = compiler_flags(source, build, architecture)
    build_triple = run([str(source / "config.guess")], capture=True)
    options = configure_options(release, architecture, build_python)
    options.insert(0, f"--build={build_triple}")
    environment = dict(os.environ)
    environment.update(
        {
            "AR": archiver,
            "ARFLAGS": "rcsD",
            "CC": str(wrapper),
            "CFLAGS": " ".join(flags),
            "CONFIG_SITE": str(CONFIG_SITE),
            "LDFLAGS": "-static -nostdlib -Wl,-e,main",
            "LIBS": f"{stub} {sysroot / architecture / 'lib/libtroe_c.a'}",
            "MACHDEP": "troe",
            "SOURCE_DATE_EPOCH": EPOCH,
            "TZ": "UTC",
            "LC_ALL": "C",
        }
    )
    run([str(source / "configure"), *options], cwd=build, env=environment)
    shutil.copyfile(setup_local(release), build / "Modules" / "Setup.local")
    run(
        ["make", "-W", "Modules/Setup.local", "Makefile"],
        cwd=build,
        env=environment,
    )
    jobs = str(max(1, os.cpu_count() or 1))
    run(
        [
            "make",
            f"-j{jobs}",
            f"libpython{release.series}.a",
            *hacl_archives(release),
            *VENDORED_ARCHIVES,
        ],
        cwd=build,
        env=environment,
    )
    archive = build / f"libpython{release.series}.a"
    if not archive.is_file():
        raise RuntimeError(f"CPython static archive was not produced: {archive}")
    return build


def build_kex(
    release: Release,
    source: Path,
    build: Path,
    sysroot: Path,
    workspace: Path,
    architecture: str,
    cc: str,
) -> Path:
    destination = workspace / "kex" / release.version / architecture
    cargo_target = workspace / "cargo" / release.version / architecture
    environment = dict(os.environ)
    environment.update(
        {
            "CC": cc,
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(cargo_target),
            "SOURCE_DATE_EPOCH": EPOCH,
            "TROE_CPYTHON_BUILD": str(build),
            "TROE_CPYTHON_SOURCE": str(source),
            "TROE_CPYTHON_SYSROOT": str(sysroot),
            "TROE_CPYTHON_VERSION": release.version,
            "TROE_CPYTHON_SERIES": release.series,
            "TROE_CPYTHON_ARCHITECTURE": architecture,
        }
    )
    run(
        [
            "cargo",
            "kex",
            "build",
            "apps/python",
            "--target",
            architecture,
            "--output",
            str(destination),
        ],
        cwd=REPO_ROOT,
        env=environment,
    )
    artifact = destination / architecture / "python.kex"
    if not artifact.is_file():
        raise RuntimeError(f"CPython KEX was not produced: {artifact}")
    return artifact


def module_name(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def exclusion_for(relative: Path, policy: dict[str, Any]) -> str | None:
    text = relative.as_posix()
    for rule in policy["exclude"]:
        for prefix in rule["paths"]:
            if text == prefix or text.startswith(prefix.rstrip("/") + "/"):
                return rule["reason"]
    return None


def setup_local(release: Release) -> Path:
    return SETUP_LOCAL if release.series == "3.14" else SETUP_LOCAL_OLDER


def hacl_archives(release: Release) -> tuple[str, ...]:
    if release.series == "3.14":
        return HACL_ARCHIVES
    return ("Modules/_hacl/libHacl_Hash_SHA2.a",)


def builtin_modules(build: Path) -> list[str]:
    config = (build / "Modules" / "config.c").read_text(encoding="utf-8")
    table = config.split("struct _inittab _PyImport_Inittab[] = {", 1)[1]
    table = table.split("/* Sentinel */", 1)[0]
    return sorted(set(re.findall(r'^\s*\{"([^\"]+)"\s*,', table, re.MULTILINE)))


def install_stdlib(
    release: Release,
    source: Path,
    build: Path,
    destination: Path,
    policy: dict[str, Any],
) -> dict[str, Any]:
    included: dict[str, dict[str, str]] = {}
    excluded: dict[str, dict[str, str]] = {}
    lib = source / "Lib"
    for source_file in sorted(path for path in lib.rglob("*.py") if path.is_file()):
        relative = source_file.relative_to(lib)
        name = module_name(relative)
        reason = exclusion_for(relative, policy)
        if reason is not None:
            excluded[name] = {"name": name, "kind": "source", "reason": reason}
            continue
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, output)
        normalize_file(output)
        included[name] = {
            "name": name,
            "kind": "source",
            "reason": policy["default"]["reason"],
        }
    for name in builtin_modules(build):
        included[name] = {
            "name": name,
            "kind": "built-in",
            "reason": "explicit static built-in-module allowlist",
        }
    for rule in policy["excluded_builtins"]:
        for name in rule["modules"]:
            excluded[name] = {"name": name, "kind": "native", "reason": rule["reason"]}
    included_document = {
        "schema": 1,
        "version": release.version,
        "series": release.series,
        "modules": sorted(included.values(), key=lambda item: item["name"]),
    }
    excluded_document = {
        "schema": 1,
        "version": release.version,
        "series": release.series,
        "modules": sorted(excluded.values(), key=lambda item: item["name"]),
    }
    write_json(destination / "TROE-MODULES-INCLUDED.json", included_document)
    write_json(destination / "TROE-MODULES-EXCLUDED.json", excluded_document)
    return {
        "included_modules": len(included),
        "excluded_modules": len(excluded),
        "stdlib_bytes": sum(path.stat().st_size for path in destination.rglob("*") if path.is_file()),
    }


def copy_artifact(source: Path, destination: Path, executable: bool = False) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    normalize_file(destination, executable=executable)


def kex_image_pages(path: Path) -> int:
    """Return the exact sum of mapped KEX image-record pages."""
    artifact = path.read_bytes()
    if len(artifact) < 48 or artifact[:8] != b"KEXPKG\0\0":
        raise RuntimeError(f"CPython artifact is not a KEX package: {path}")
    executable_offset = struct.unpack_from("<I", artifact, 24)[0]
    executable_bytes = struct.unpack_from("<Q", artifact, 32)[0]
    executable_end = executable_offset + executable_bytes
    if (
        executable_offset < 48
        or executable_end > len(artifact)
        or executable_bytes < 88
    ):
        raise RuntimeError(f"CPython KEX package geometry is invalid: {path}")
    executable = artifact[executable_offset:executable_end]
    if executable[:8] != b"KEX\0FMT\0":
        raise RuntimeError(f"CPython package has no canonical KEX executable: {path}")
    header_bytes, record_bytes = struct.unpack_from("<HH", executable, 14)
    record_count = struct.unpack_from("<H", executable, 32)[0]
    if (
        header_bytes != 88
        or record_bytes != 40
        or record_count == 0
        or header_bytes + record_count * record_bytes > len(executable)
    ):
        raise RuntimeError(f"CPython KEX record table is invalid: {path}")
    pages = 0
    for index in range(record_count):
        offset = header_bytes + index * record_bytes
        memory_bytes = struct.unpack_from("<Q", executable, offset + 24)[0]
        if memory_bytes == 0 or memory_bytes % 4096:
            raise RuntimeError(f"CPython KEX record is not page aligned: {path}")
        pages += memory_bytes // 4096
    return pages


def install_release(
    package_root: Path,
    release: Release,
    source: Path,
    build: Path,
    architecture: str,
    artifact: Path,
    policy: dict[str, Any],
) -> None:
    bin_root = package_root / "bin" / architecture
    architecture_root = package_root / "lib" / architecture
    names = [f"python{release.version}.kex", f"python{release.series}.kex"]
    if release.version == DEFAULT_VERSION:
        names.extend(["python3.kex", "python.kex"])
    for name in names:
        copy_artifact(artifact, bin_root / name, executable=True)
    inspect = json.loads(run(["cargo", "kex", "inspect", str(artifact), "--json"], capture=True))
    if inspect.get("target") != architecture or inspect.get("format") != "KEX package v1":
        raise RuntimeError(f"CPython KEX inspection did not match {architecture}: {artifact}")
    write_json(bin_root / f"python{release.version}.inspect.json", inspect)
    stdlib = architecture_root / f"python{release.version}" / f"python{release.series}"
    metrics = install_stdlib(release, source, build, stdlib, policy)
    measured = {
        "kex_bytes": artifact.stat().st_size,
        "image_mapped_pages": kex_image_pages(artifact),
        "stdlib_bytes": metrics["stdlib_bytes"],
    }
    for name, ceiling in policy["limits"].items():
        if measured[name] > ceiling:
            raise RuntimeError(
                f"CPython {release.version} {architecture} {name} is "
                f"{measured[name]}, above the accepted ceiling {ceiling}"
            )
    write_json(
        architecture_root / f"python{release.version}" / "TROE-BUILD.json",
        {
            "schema": 1,
            "architecture": architecture,
            "version": release.version,
            "series": release.series,
            "source_sha256": release.sha256,
            "patch_sha256": sha256(PATCH),
            "kex_sha256": sha256(artifact),
            "stack_pages": inspect["stack_pages"],
            "heap_limit_pages": inspect["heap_pages"],
            "limits": policy["limits"],
            **measured,
            **metrics,
        },
    )


def write_package_manifest(root: Path) -> None:
    manifest = root / MANIFEST_NAME
    lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item != manifest):
        lines.append(f"{sha256(path)}  {path.relative_to(root).as_posix()}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    normalize_file(manifest)


def read_package_manifest(root: Path) -> list[tuple[PurePosixPath, str]]:
    entries: list[tuple[PurePosixPath, str]] = []
    for line in (root / MANIFEST_NAME).read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or not name:
            raise RuntimeError(f"package manifest entry is malformed: {line}")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError(f"package manifest entry is not repository-relative: {name}")
        entries.append((relative, digest))
    return entries


def verify_package(root: Path) -> list[tuple[PurePosixPath, str]]:
    """Reject any package tree that differs from its own recorded manifest."""
    manifest = root / MANIFEST_NAME
    if not manifest.is_file():
        raise RuntimeError(f"package manifest is missing: {manifest}")
    entries = read_package_manifest(root)
    listed = {relative for relative, _digest in entries}
    present = {
        PurePosixPath(item.relative_to(root).as_posix())
        for item in root.rglob("*")
        if item.is_file() and item != manifest
    }
    if listed != present:
        raise RuntimeError(f"package tree does not match its manifest: {root}")
    for relative, digest in entries:
        if sha256(root / Path(*relative.parts)) != digest:
            raise RuntimeError(f"package file digest mismatch: {relative}")
    return entries


def mtools(
    command: str, image: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    executable = shutil.which(command)
    if executable is None:
        raise RuntimeError(f"{command} is required to populate shared media")
    offset = mkshared.PARTITION_START * mkshared.SECTOR_BYTES
    return subprocess.run(
        [executable, "-i", f"{image.resolve(strict=True)}@@{offset}", *arguments],
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def install_single_root_image(
    root: Path, image: Path, directory: PurePosixPath
) -> None:
    """Install one self-contained tree below its own directory on the medium.

    Acceptance-only diagnostics keep a private root instead of sharing the
    optional-runtime ``bin`` and ``lib`` directories.
    """
    entries = verify_package(root)
    mkshared.verify_image(image)
    if mtools("mdir", image, f"::/{directory.as_posix()}", check=False).returncode == 0:
        raise RuntimeError(f"shared media already contains /{directory.as_posix()}")
    mtools("mmd", image, f"::/{directory.parts[0]}", check=False)
    mtools("mcopy", image, "-s", str(root), f"::/{directory.parts[0]}/")
    with tempfile.TemporaryDirectory(prefix="troe-cpython-single-") as temporary:
        extraction = Path(temporary) / "extracted"
        extraction.mkdir()
        mtools("mcopy", image, "-s", f"::/{directory.as_posix()}", str(extraction))
        installed = extraction / directory.name
        for relative, digest in entries:
            path = installed / Path(*relative.parts)
            if not path.is_file() or sha256(path) != digest:
                raise RuntimeError(f"shared media entry differs: {relative}")


def install_package_image(root: Path, image: Path) -> None:
    """Install one verified package onto a detached shared image.

    The medium receives exactly the runtime layout: ``bin`` and ``lib`` are
    shared with other optional runtimes, so only the entries this package owns
    are refused when they already exist.
    """
    entries = verify_package(root)
    mkshared.verify_image(image)
    for relative, _digest in entries:
        if mtools("mdir", image, f"::/{relative.as_posix()}", check=False).returncode == 0:
            raise RuntimeError(f"shared media already contains /{relative.as_posix()}")
    for directory in MEDIA_DIRECTORIES:
        source = root / directory.as_posix()
        if not source.is_dir():
            continue
        mtools("mmd", image, f"::/{directory.as_posix()}", check=False)
        for child in sorted(item for item in source.iterdir() if item.is_dir()):
            mtools("mcopy", image, "-s", str(child), f"::/{directory.as_posix()}/")
        for child in sorted(item for item in source.iterdir() if item.is_file()):
            mtools("mcopy", image, str(child), f"::/{directory.as_posix()}/{child.name}")
    verify_package_image(root, image)


def verify_package_image(root: Path, image: Path) -> None:
    """Extract every installed entry and compare it against the source tree."""
    entries = verify_package(root)
    mkshared.verify_image(image)
    with tempfile.TemporaryDirectory(prefix="troe-cpython-image-") as temporary:
        extraction = Path(temporary) / "extracted"
        extraction.mkdir()
        for directory in MEDIA_DIRECTORIES:
            if (root / directory.as_posix()).is_dir():
                mtools("mcopy", image, "-s", f"::/{directory.as_posix()}", str(extraction))
        for relative, digest in entries:
            path = extraction / Path(*relative.parts)
            if not path.is_file() or sha256(path) != digest:
                raise RuntimeError(f"shared media package entry differs: {relative}")


def collect_pure_python(source: Path) -> list[PurePosixPath]:
    """Return the deterministic pure-Python file set below one source tree."""
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError(f"package source directory is unavailable: {source}")
    entries: list[PurePosixPath] = []
    for item in sorted(source.rglob("*")):
        relative = PurePosixPath(item.relative_to(source).as_posix())
        # Host bytecode caches are never part of a portable package payload.
        if "__pycache__" in relative.parts:
            continue
        if item.is_symlink():
            raise RuntimeError(f"package source entry is a symbolic link: {relative}")
        if item.is_dir():
            continue
        if not item.is_file() or item.suffix != ".py":
            raise RuntimeError(f"package source entry is not pure Python: {relative}")
        entries.append(relative)
    if not entries:
        raise RuntimeError(f"package source directory has no modules: {source}")
    return entries


def install_packages_image(source: Path, image: Path) -> None:
    """Install administrator-supplied pure-Python packages onto shared media."""
    entries = collect_pure_python(source)
    mkshared.verify_image(image)
    architectures = [
        name
        for name in ARCHITECTURES
        if mtools("mdir", image, f"::/lib/{name}", check=False).returncode == 0
    ]
    if not architectures:
        raise RuntimeError(f"shared media has no installed interpreter library: {image}")
    for architecture in architectures:
        packages = PurePosixPath("lib") / architecture / "packages"
        directories = sorted(
            {packages}
            | {
                packages / relative.parent
                for relative in entries
                if relative.parent != PurePosixPath(".")
            },
            key=lambda item: (len(item.parts), item.as_posix()),
        )
        for directory in directories:
            mtools("mmd", image, f"::/{directory.as_posix()}", check=False)
        for relative in entries:
            mtools(
                "mcopy",
                image,
                "-o",
                str(source / Path(*relative.parts)),
                f"::/{(packages / relative).as_posix()}",
            )
    with tempfile.TemporaryDirectory(prefix="troe-cpython-packages-") as temporary:
        extraction = Path(temporary) / "extracted"
        extraction.mkdir()
        for architecture in architectures:
            packages = PurePosixPath("lib") / architecture / "packages"
            for relative in entries:
                mtools(
                    "mcopy",
                    image,
                    "-o",
                    f"::/{(packages / relative).as_posix()}",
                    str(extraction / relative.name),
                )
                installed = extraction / relative.name
                if sha256(installed) != sha256(source / Path(*relative.parts)):
                    raise RuntimeError(
                        f"shared media package entry differs: {architecture} {relative}"
                    )
                installed.unlink()


def build_variant_kex(
    variant: str,
    release: Release,
    workspace: Path,
    architecture: str,
    cc: str,
) -> Path:
    """Link one capability-reduced interpreter from a retained work directory."""
    source = workspace / "source" / release.version / f"Python-{release.version}"
    build = workspace / "build" / release.version / architecture
    sysroot = workspace / "sysroot"
    for required in (source, build, sysroot):
        if not required.is_dir():
            raise RuntimeError(f"retained work directory is incomplete: {required}")
    destination = workspace / "variants" / variant / release.version / architecture
    environment = dict(os.environ)
    environment.update(
        {
            "CC": cc,
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(workspace / "cargo-variants" / variant / architecture),
            "SOURCE_DATE_EPOCH": EPOCH,
            "TROE_CPYTHON_APP_ROOT": str(APP_ROOT),
            "TROE_CPYTHON_BUILD": str(build),
            "TROE_CPYTHON_SOURCE": str(source),
            "TROE_CPYTHON_SYSROOT": str(sysroot),
            "TROE_CPYTHON_VERSION": release.version,
            "TROE_CPYTHON_SERIES": release.series,
            "TROE_CPYTHON_ARCHITECTURE": architecture,
        }
    )
    run(
        [
            "cargo",
            "kex",
            "build",
            f"tests/{variant}",
            "--target",
            architecture,
            "--output",
            str(destination),
        ],
        cwd=REPO_ROOT,
        env=environment,
    )
    artifact = destination / architecture / f"{variant}.kex"
    if not artifact.is_file():
        raise RuntimeError(f"variant KEX was not produced: {artifact}")
    return artifact


def build_variants(output: Path, workspace: Path, architectures: tuple[str, ...], cc: str) -> None:
    """Emit the capability-negative interpreters used by acceptance only."""
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory is not empty: {output}")
    release = releases()[0]
    root = output / DIAGNOSTICS_DIRECTORY
    for architecture in architectures:
        for variant in NEGATIVE_VARIANTS:
            artifact = build_variant_kex(variant, release, workspace, architecture, cc)
            copy_artifact(
                artifact, root / architecture / "bin" / f"{variant}.kex", executable=True
            )
    write_package_manifest(root)


def build_package(
    output: Path,
    workspace: Path,
    selected: list[Release],
    architectures: tuple[str, ...],
    cache: Path,
    offline: bool,
    cc: str,
    archiver: str,
    sigstore: str,
    lld: str,
    python_overrides: dict[str, str],
) -> None:
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"output directory is not empty: {output}")
    if workspace.exists() and any(workspace.iterdir()):
        raise RuntimeError(f"work directory is not empty: {workspace}")
    output.mkdir(parents=True, exist_ok=True)
    workspace.mkdir(parents=True, exist_ok=True)
    lld_driver = workspace / "tools" / "ld.lld"
    lld_driver.parent.mkdir(parents=True, exist_ok=True)
    lld_driver.symlink_to(lld)
    sysroot = workspace / "sysroot"
    sysroot_command = [sys.executable, str(REPO_ROOT / "tools" / "build_c_sysroot.py"), str(sysroot)]
    if len(architectures) == 1:
        sysroot_command.extend(["--architecture", architectures[0]])
    sysroot_command.extend(["--cc", cc, "--ar", archiver])
    run(sysroot_command)
    policy = load_json(STDLIB_POLICY)
    package_root = output
    authenticated: list[dict[str, str]] = []
    for release in selected:
        archive = authenticate_source(release, cache, sigstore, offline)
        source = extract_source(archive, workspace / "source" / release.version, release)
        build_python = find_build_python(release.series, python_overrides)
        authenticated.append(
            {
                "version": release.version,
                "sha256": release.sha256,
                "certificate_identity": release.certificate_identity,
                "certificate_oidc_issuer": release.certificate_oidc_issuer,
            }
        )
        for architecture in architectures:
            build = build_library(
                release,
                source,
                workspace,
                sysroot,
                architecture,
                cc,
                archiver,
                str(lld_driver),
                build_python,
            )
            artifact = build_kex(
                release, source, build, sysroot, workspace, architecture, cc
            )
            install_release(
                package_root,
                release,
                source,
                build,
                architecture,
                artifact,
                policy,
            )
    write_json(package_root / "lib" / "TROE-SOURCES.json", {"schema": 1, "releases": authenticated})
    write_json(
        package_root / "lib" / "TROE-PACKAGES.json",
        {
            "schema": 1,
            "search_paths": [
                "/vol/shared/lib/<architecture>/packages",
                "/vol/shared/lib/<architecture>/packages/python<major.minor>",
            ],
            "content": "administrator-supplied pure-Python source packages only",
        },
    )
    write_package_manifest(package_root)


def main() -> int:
    args = parse_args()
    try:
        if args.action == "verify":
            verify_package(args.tree)
            print(f"TROE CPython package verified: {args.tree}")
            return 0
        if args.action == "install-image":
            install_package_image(args.tree, args.image)
            print(f"TROE CPython package installed: {args.image}")
            return 0
        if args.action == "verify-image":
            verify_package_image(args.tree, args.image)
            print(f"TROE CPython shared media verified: {args.image}")
            return 0
        if args.action == "install-diagnostics":
            install_single_root_image(args.tree, args.image, DIAGNOSTICS_DIRECTORY)
            print(f"TROE CPython diagnostics installed: {args.image}")
            return 0
        if args.action == "variants":
            build_variants(
                args.output,
                args.work_directory,
                tuple(ARCHITECTURES)
                if args.architecture == "all"
                else (args.architecture,),
                find_tool(
                    args.cc,
                    ("clang",),
                    ("/opt/homebrew/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang"),
                ),
            )
            print(f"TROE CPython diagnostics ready: {args.output}")
            return 0
        if args.action == "install-packages":
            install_packages_image(args.source, args.image)
            print(f"TROE CPython packages installed: {args.image}")
            return 0
        selected = releases()
        if args.version != "all":
            selected = [item for item in selected if item.version == args.version]
        architectures = (
            tuple(ARCHITECTURES) if args.architecture == "all" else (args.architecture,)
        )
        cc = find_tool(
            args.cc,
            ("clang",),
            ("/opt/homebrew/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang"),
        )
        archiver = find_tool(
            args.ar,
            ("llvm-ar",),
            ("/opt/homebrew/opt/llvm/bin/llvm-ar", "/usr/local/opt/llvm/bin/llvm-ar"),
        )
        sigstore = find_tool(args.sigstore, ("sigstore",), ())
        lld = find_rust_lld()
        python_overrides = parse_build_python(args.build_python)
        if args.output.exists() and any(args.output.iterdir()):
            raise RuntimeError(f"output directory is not empty: {args.output}")
        if args.work_directory and args.check:
            raise RuntimeError("--work-directory and --check cannot be combined")
        if args.work_directory:
            build_package(
                args.output,
                args.work_directory,
                selected,
                architectures,
                args.source_cache,
                args.offline,
                cc,
                archiver,
                sigstore,
                lld,
                python_overrides,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="troe-cpython-build-") as temporary:
                build_package(
                    args.output,
                    Path(temporary) / "work",
                    selected,
                    architectures,
                    args.source_cache,
                    args.offline,
                    cc,
                    archiver,
                    sigstore,
                    lld,
                    python_overrides,
                )
        if args.check:
            with tempfile.TemporaryDirectory(prefix="troe-cpython-check-") as temporary:
                second_output = Path(temporary) / "output"
                build_package(
                    second_output,
                    Path(temporary) / "work",
                    selected,
                    architectures,
                    args.source_cache,
                    True,
                    cc,
                    archiver,
                    sigstore,
                    lld,
                    python_overrides,
                )
                if tree_digest(args.output) != tree_digest(second_output):
                    raise RuntimeError("CPython package output is not reproducible")
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print(f"CPython build failed: {error}", file=sys.stderr)
        return 1
    print(f"TROE CPython package ready: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
