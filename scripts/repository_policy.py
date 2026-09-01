#!/usr/bin/env python3
"""Shared repository-tool and dependency-audit policy checks."""

from __future__ import annotations

import datetime
import json
import re
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_EXCEPTIONS_FILE = REPO_ROOT / "tools" / "rustsec-exceptions.json"
PYTHON_TOOLING_FILE = REPO_ROOT / "pyproject.toml"
MINIMUM_PYTHON = (3, 13)
_ADVISORY_PATTERN = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
_EXCEPTION_FIELDS = {"advisory", "owner", "rationale", "expires"}


# One tool formats and lints every repository-owned Python file. It is resolved
# from `PATH` by name, exactly like the host image utilities: absence skips the
# Python format and lint gates with a notice unless the caller demands them.
RUFF_EXECUTABLE = "ruff"

# The gates walk the repository root and let the committed configuration decide
# what is in scope, so a new Python file anywhere is covered without edits here.
PYTHON_LINT_ROOT = "."

# Vendored and generated trees, the only paths `ruff` may skip. `apps/lua/vendor`
# and `apps/python/patches` carry upstream sources; `build` and `**/target` are
# generated. Everything else is repository-owned and gated.
RUFF_EXCLUDED_PATHS = (
    "apps/lua/vendor",
    "apps/python/patches",
    "build",
    "**/target",
)


SHARED_VOLUME_APPLICATIONS = frozenset({"lua", "python"})

# The two bare-metal targets every command and service is compiled for.
KEX_TARGETS = ("x86_64-unknown-none", "aarch64-unknown-none")

# `python` is the one member the lint and test gates cannot reach from a clean
# checkout: its build script consumes the CPython tree that
# `tools/build_cpython.py` generates outside the repository, so linting it would
# make an out-of-tree build a prerequisite of `cargo clippy`. Its Rust bridge is
# covered by `test_cpython_integration.py` instead.
UNLINTABLE_APPLICATIONS = frozenset({"python"})


def application_directories(root: Path = REPO_ROOT) -> tuple[Path, ...]:
    """Return every application directory in deterministic order."""
    return tuple(
        sorted(
            path
            for path in (root / "apps").iterdir()
            if path.is_dir() and (path / "Cargo.toml").is_file()
        )
    )


def service_directories(root: Path = REPO_ROOT) -> tuple[Path, ...]:
    """Return every isolated user-service directory in deterministic order."""
    return tuple(
        sorted(
            path
            for path in (root / "services").iterdir()
            if path.is_dir() and (path / "Cargo.toml").is_file()
        )
    )


def lintable_application_directories(root: Path = REPO_ROOT) -> tuple[Path, ...]:
    """Return the applications the format, lint, and test gates can compile."""
    return tuple(
        path
        for path in application_directories(root)
        if path.name not in UNLINTABLE_APPLICATIONS
    )


def package_name(directory: Path) -> str:
    """Return the Cargo package name one member manifest declares."""
    manifest = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))
    return str(manifest["package"]["name"])


def unlintable_application_exclusions(root: Path = REPO_ROOT) -> tuple[str, ...]:
    """Return the ``--exclude`` arguments that drop unlintable members."""
    return tuple(
        argument
        for directory in application_directories(root)
        if directory.name in UNLINTABLE_APPLICATIONS
        for argument in ("--exclude", package_name(directory))
    )


def rootfs_application_directories(root: Path = REPO_ROOT) -> tuple[Path, ...]:
    """Return only applications installed into the read-only rootfs image.

    Shared-volume deliverables exceed the rootfs and EFI budgets and ship below
    ``/vol/shared`` from their own versioned package tree instead.
    """
    return tuple(
        path
        for path in application_directories(root)
        if path.name not in SHARED_VOLUME_APPLICATIONS
    )


def buildable_shared_volume_directories(root: Path = REPO_ROOT) -> tuple[Path, ...]:
    """Return the shared-volume applications ``cargo kex build`` can build here.

    A shared-volume deliverable ships no committed ``.kex``, so there is no
    byte-for-byte ``--check`` to run for it and nothing outside a QEMU
    acceptance run builds one. Building it is therefore the only thing that
    proves the builder still reaches it. ``python`` is excluded for the same
    reason it is unlintable: its build script consumes the CPython tree
    ``tools/build_cpython.py`` generates outside the repository.
    """
    return tuple(
        path
        for path in application_directories(root)
        if path.name in SHARED_VOLUME_APPLICATIONS
        and path.name not in UNLINTABLE_APPLICATIONS
    )


def load_python_tooling_policy(
    path: Path = PYTHON_TOOLING_FILE,
) -> dict[str, object]:
    """Return the committed ``[tool.ruff]`` table that governs Python tooling."""
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(
            f"cannot read Python tooling policy {path}: {error}"
        ) from error
    tools = document.get("tool")
    if not isinstance(tools, dict) or not isinstance(tools.get("ruff"), dict):
        raise RuntimeError(f"{path} must configure [tool.ruff]")
    return tools["ruff"]


def python_lint_commands(
    *, executable: str = RUFF_EXECUTABLE, paths: Sequence[str] = (PYTHON_LINT_ROOT,)
) -> tuple[tuple[str, ...], ...]:
    """Return the Python format and lint argument vectors, in gate order."""
    return (
        (executable, "format", "--check", *paths),
        (executable, "check", *paths),
    )


def require_supported_python(version: Sequence[int] = sys.version_info) -> None:
    """Reject repository-tool execution on an unsupported Python runtime."""
    actual = tuple(version[:2])
    if actual < MINIMUM_PYTHON:
        required = ".".join(str(part) for part in MINIMUM_PYTHON)
        current = ".".join(str(part) for part in actual)
        raise RuntimeError(
            f"repository tools require Python {required} or newer; got {current}"
        )


def load_audit_exceptions(
    path: Path = AUDIT_EXCEPTIONS_FILE,
    *,
    today: datetime.date | None = None,
) -> tuple[str, ...]:
    """Return validated, unexpired RustSec advisory exceptions."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"cannot read RustSec exception policy {path}: {error}"
        ) from error

    if not isinstance(document, dict) or set(document) != {"schema", "exceptions"}:
        raise RuntimeError(
            "RustSec exception policy must contain schema and exceptions"
        )
    if document["schema"] != 1 or not isinstance(document["exceptions"], list):
        raise RuntimeError("unsupported RustSec exception policy schema")

    current_date = (
        datetime.datetime.now(tz=datetime.UTC).date() if today is None else today
    )
    advisories: list[str] = []
    for index, entry in enumerate(document["exceptions"]):
        label = f"RustSec exception {index}"
        if not isinstance(entry, dict) or set(entry) != _EXCEPTION_FIELDS:
            raise RuntimeError(
                f"{label} must contain exactly {sorted(_EXCEPTION_FIELDS)}"
            )

        advisory = entry["advisory"]
        owner = entry["owner"]
        rationale = entry["rationale"]
        expires = entry["expires"]
        if (
            not isinstance(advisory, str)
            or _ADVISORY_PATTERN.fullmatch(advisory) is None
        ):
            raise RuntimeError(f"{label} has an invalid advisory identifier")
        if advisory in advisories:
            raise RuntimeError(f"duplicate RustSec exception for {advisory}")
        if not isinstance(owner, str) or not owner.strip():
            raise RuntimeError(f"{label} must name a non-empty owner")
        if not isinstance(rationale, str) or not rationale.strip():
            raise RuntimeError(f"{label} must include a non-empty rationale")
        if not isinstance(expires, str):
            raise RuntimeError(f"{label} must use an ISO-8601 expiry date")
        try:
            expiry_date = datetime.date.fromisoformat(expires)
        except ValueError as error:
            raise RuntimeError(f"{label} must use an ISO-8601 expiry date") from error
        if expiry_date <= current_date:
            raise RuntimeError(f"RustSec exception for {advisory} expired on {expires}")
        advisories.append(advisory)

    return tuple(advisories)


_CFG_PREFIX = re.compile(r"#\[cfg\(")
_RAW_STRING = re.compile(r"b?r(?P<hashes>#*)\"")
_CHARACTER = re.compile(r"'(?:\\[^']*|[^'\\])'")


def _literal_or_comment_end(source: str, index: int) -> int | None:
    """Return the index just past a comment or literal starting at ``index``.

    Returns ``None`` when ``index`` is ordinary code. Recognizing these spans is
    what keeps a brace inside `"}"` or a doc comment from mis-scoping an item.
    """
    if source.startswith("//", index):
        end = source.find("\n", index)
        return len(source) if end < 0 else end
    if source.startswith("/*", index):
        depth = 0
        end = index
        while end < len(source):
            if source.startswith("/*", end):
                depth += 1
                end += 2
            elif source.startswith("*/", end):
                depth -= 1
                end += 2
                if depth == 0:
                    return end
            else:
                end += 1
        return len(source)
    raw = _RAW_STRING.match(source, index)
    if raw is not None:
        terminator = '"' + raw.group("hashes")
        end = source.find(terminator, raw.end())
        return len(source) if end < 0 else end + len(terminator)
    if source[index] == '"':
        end = index + 1
        while end < len(source):
            if source[end] == "\\":
                end += 2
                continue
            if source[end] == '"':
                return end + 1
            end += 1
        return len(source)
    # A leading quote is a lifetime unless it closes as a character literal.
    if source[index] == "'":
        character = _CHARACTER.match(source, index)
        return None if character is None else character.end()
    return None


def _cfg_attribute_at(source: str, index: int) -> tuple[str, int] | None:
    """Return the ``#[cfg(..)]`` predicate and end index at ``index``.

    Returns ``None`` when ``index`` does not begin such an attribute. The
    predicate's parentheses are balanced by scanning rather than by pattern, so
    nesting depth is not a limit.
    """
    prefix = _CFG_PREFIX.match(source, index)
    if prefix is None:
        return None
    depth = 1
    cursor = prefix.end()
    while cursor < len(source):
        skip = _literal_or_comment_end(source, cursor)
        if skip is not None:
            cursor = skip
            continue
        character = source[cursor]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                if not source.startswith("]", cursor + 1):
                    return None
                return source[prefix.end() : cursor], cursor + 2
        cursor += 1
    return None


def _predicate_terms(predicate: str) -> list[str]:
    """Split a ``cfg`` predicate list on its top-level commas."""
    terms: list[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(predicate):
        skip = _literal_or_comment_end(predicate, index)
        if skip is not None:
            index = skip
            continue
        character = predicate[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            terms.append(predicate[start:index])
            start = index + 1
        index += 1
    terms.append(predicate[start:])
    return terms


def _predicate_holds_only_under_test(predicate: str) -> bool:
    """Report whether ``predicate`` can hold only when ``test`` is set.

    Exactly two shapes qualify: a bare ``test``, and an ``all(..)`` naming a
    bare ``test`` among its terms. A ``not(..)`` or an ``any(..)`` is satisfied
    by a non-test build, so its item ships and must be retained; every other
    shape is unrecognized and retained for the same reason.
    """
    predicate = predicate.strip()
    if predicate == "test":
        return True
    if predicate.startswith("all(") and predicate.endswith(")"):
        return any(
            _predicate_holds_only_under_test(term)
            for term in _predicate_terms(predicate[len("all(") : -1])
        )
    return False


def _annotated_item_end(source: str, index: int) -> int:
    """Return the index just past the item that begins at ``index``.

    The item ends at the brace that closes its body, or at the semicolon that
    terminates a declaration such as a ``use``. Bracket and parenthesis depth is
    tracked so the semicolon in `[u8; 4]` does not end the item early.

    An item shape this scan does not recognize -- an annotated statement, or a
    struct field or enum variant, whose extent ends at neither -- reaches a
    comma or a closing delimiter belonging to its enclosing block instead.
    Every such boundary returns ``index``, which retains the remainder rather
    than consuming it, so an unrecognized shape understates the removal instead
    of deleting shipped code. A generic parameter list costs the same
    understatement, since its comma is not nested in a tracked delimiter.
    """
    braces = 0
    brackets = 0
    while index < len(source):
        skip = _literal_or_comment_end(source, index)
        if skip is not None:
            index = skip
            continue
        character = source[index]
        if character == "{":
            braces += 1
        elif character == "}":
            braces -= 1
            if braces < 0:
                return index
            if braces == 0:
                return index + 1
        elif character in "([":
            brackets += 1
        elif character in ")]":
            brackets -= 1
            if brackets < 0:
                return index
        elif character == ";" and braces == 0 and brackets == 0:
            return index + 1
        elif character == "," and braces == 0 and brackets == 0:
            return index
        index += 1
    return len(source)


def rust_source_outside_test_configuration(source: str) -> str:
    """Return ``source`` with every item annotated ``#[cfg(test)]`` removed.

    What remains is the text a non-test build of the crate compiles, so a name
    that survives here is named by shipped code. Only an item whose predicate
    cannot hold outside a test build is removed: ``test`` itself and an
    ``all(..)`` containing it. Every other predicate, and every item shape this
    scan cannot delimit, is retained, so the result understates the removal
    rather than overstating it and can never drop code a shipped build compiles.
    """
    kept: list[str] = []
    index = 0
    while index < len(source):
        skip = _literal_or_comment_end(source, index)
        if skip is not None:
            kept.append(source[index:skip])
            index = skip
            continue
        attribute = _cfg_attribute_at(source, index)
        if attribute is None:
            kept.append(source[index])
            index += 1
            continue
        predicate, end = attribute
        if not _predicate_holds_only_under_test(predicate):
            kept.append(source[index:end])
            index = end
            continue
        index = _annotated_item_end(source, end)
    return "".join(kept)


def rust_code_without_comments_or_literals(source: str) -> str:
    """Return ``source`` with every comment and literal blanked out.

    Each such span becomes spaces, with its newlines kept, so token boundaries
    and line numbering survive. A textual search over the result therefore sees
    code only: a doc-comment example or a string that merely mentions a
    construct is not mistaken for the construct itself.
    """
    kept: list[str] = []
    index = 0
    while index < len(source):
        skip = _literal_or_comment_end(source, index)
        if skip is None:
            kept.append(source[index])
            index += 1
            continue
        kept.append(
            "".join(
                "\n" if character == "\n" else " " for character in source[index:skip]
            )
        )
        index = skip
    return "".join(kept)


def shipped_troe_dependencies(manifest: dict) -> set[str]:
    """Return the ``troe-`` dependencies of ``manifest`` that reach an image.

    Normal, build, and per-target dependencies all link into something a build
    produces. Dev-dependencies deliberately do not count: a test must stay free
    to compose a real subsystem out of the crates a shipped build must not name.
    """
    names: set[str] = set()
    for section in ("dependencies", "build-dependencies"):
        names.update(
            name for name in manifest.get(section, {}) if name.startswith("troe-")
        )
    for target in manifest.get("target", {}).values():
        names.update(
            name for name in target.get("dependencies", {}) if name.startswith("troe-")
        )
    return names
