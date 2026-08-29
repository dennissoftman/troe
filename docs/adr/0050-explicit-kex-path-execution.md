# ADR 0050: Explicit KEX path execution

Status: accepted and implemented, 2026-08-28.

The whole-artifact staging detail in this decision was superseded by the
coherent bounded streaming loader in [ADR 0052](0052-streamed-kex-and-static-c-runtime.md).
Path selection and authority semantics are unchanged.

## Context

The immutable `/bin` catalog gives recovery commands a deterministic trusted
distribution path, but an application copied to a writable mounted volume
cannot be launched from that location. Adding writable directories to an
ambient command search path would make command selection depend on mutable
namespace contents and would weaken the existing non-shadowing rule.

TROE also has no Unix mode-bit contract on FAT volumes. Execution intent must
therefore be explicit without pretending that every readable file is a valid
application or that a new file-mode ABI exists.

## Decision

Command resolution classifies `argv[0]` by syntax. A nonempty bare lowercase
ASCII name containing only digits, `_`, or `-` resolves exactly to
`/bin/<name>.kex`. A token containing `/` is an explicit path and resolves
exactly through the caller's VFS namespace against its canonical invocation
cwd. Relative forms such as `./tool` and `../tools/tool`, and absolute forms
such as `/vol/shared/tool`, are supported. The resolver does not infer a
`.kex` suffix, search `PATH`, or search the current directory for a bare name.

The resolved final node must be a regular file; a final symbolic link may be
followed by the owning provider to such a file. The kernel streams the selected
bytes through bounded coherent validation before admission and applies the same canonical package envelope, KCAP
manifest, target, inner KEX, W^X, relocation, mapping, and resource validation
used for `/bin` applications. A malformed file, directory, missing path,
symlink failure, or unsupported package fails without starting a process.

Explicit selection changes code provenance, not authority. Interactive launch
still constructs only the package's declared typed services. Owner-scoped
process launch still requires a launch capability, and every child manifest is
an attenuation of its launcher's grants. A copied application cannot acquire
capabilities merely because it resides on a writable mount.

The shell completes path-shaped command words from the VFS while retaining the
bounded `/bin` catalog for bare words. Shell intrinsics remain non-shadowable:
the bare token `cd` is intrinsic, while an explicit `./cd` is an ordinary KEX
path and receives no shell-session authority.

As an interim provenance signal, the interactive shell asks before directly
executing an explicit path whose canonical location is outside `/bin`. Only an
exact case-insensitive `y` proceeds; Enter and every other response cancel the
whole command line. This prompt is deliberately not a kernel permission check.
An already-running application using its typed process-launch capability does
not gain a controlling-terminal prompt, and scripts are code whose launch is
already an explicit user decision.

## Consequences

Users can copy a canonical KEX package to `/vol/shared`, rename it without a
suffix, and run it explicitly with `./name`. Nested consumers such as Lua
`os.execute` and `io.popen` use the same rule because the existing process
launch record already carries canonical cwd and unrestricted bounded UTF-8
arguments; no ABI version change is required.

This decision does not add Unix permission bits, shebang interpretation,
arbitrary native formats, a dynamic linker, a `PATH` implementation, or an
ambient execute right on mounted filesystems. The explicit slash is the user
or launcher intent, while package validation and capability attenuation remain
the security boundary.

When ownership, ACLs, and mode bits are implemented, permission-aware providers
such as ext4 should reject a regular file without execute permission before KEX
staging. Filesystems without that metadata, including FAT32, remain explicitly
launchable and retain the provenance warning by default. Typed configuration
may later select stricter mount execution policy without changing KEX parsing.
