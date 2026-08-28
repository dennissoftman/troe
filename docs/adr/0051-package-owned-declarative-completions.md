# ADR 0051: Package-owned declarative completions

Status: accepted and implemented, 2026-08-29. Portable descriptors, embedded
CMPL artifacts, recovery activation registry, and current app migration are
complete. Hosted PMAN/PLOCK publication binding remains a follow-up.

## Context

The shell already owns cursor-aware completion, its revision-aware command
catalog, namespace access, candidate budgets, insertion, and display. Argument
knowledge is nevertheless compiled as application-specific Rust branches in
`troe-shell`. Adding or replacing an application therefore requires changing a
privileged session component even when the new completion behavior is only a
list of modes or a declaration that one operand is a path.

Tab is received while the shell owns the editor and before an ordinary
application has been launched. Starting that application on every Tab would
grant its normal capabilities, admit side effects, make editor latency depend
on arbitrary application code, and complicate cancellation and teardown.

A finite value list also cannot describe every useful domain. Files, commands,
jobs, services, integers, and network endpoints are open sets whose candidates
come from current trusted state.

## Decision

`troe-completion` is a portable `no_std` policy crate. A bounded validated
descriptor contains ordered rules over one-based argument position, the current
prefix, and bounded predicates over already parsed arguments. The first matching
rule selects one semantic resolver:

- a finite descriptor-owned value set;
- a filesystem path constrained to files, directories, or either;
- the authoritative command catalog;
- an address family and optional or required port;
- an integer radix and optional inclusive bounds;
- session-owned jobs; or
- supervisor-visible services; or
- configured mount-policy volumes.

Resolver kinds form a closed, versioned vocabulary, but their candidate domains
are not closed. `Path(File)` means that the shell's trusted namespace resolver
enumerates current matching files. It does not place every filename in the
descriptor. Address, job, and service resolvers similarly
require an explicitly selected trusted state source. A resolver declaration is
metadata and grants no application authority.

The shell remains authoritative for parsing, replacement offsets, quoting and
escaping policy, sorting and deduplication, candidate count and byte budgets,
display, and insertion. Descriptors never return terminal control bytes and do
not authorize command execution. Redirection and command-position completion
remain generic shell behavior.

Integers are modeled directly rather than as regular expressions because radix
and numeric bounds are typed, inspectable, and useful to both candidate
generation and validation. Arbitrary regular expressions are not part of the
first descriptor vocabulary. A regex can filter strings but cannot identify the
trusted source from which candidates should be obtained; it also introduces an
engine/version and worst-case execution contract. A future measured need may
add a small bounded lexical-pattern format as a new resolver or constraint, but
must not accept an implementation-defined host regex dialect.

CMPL v1 is canonical bounded text owned as `completion.cmpl` by each app. The
KEX builder validates it, requires its command identity to match the installed
command, and embeds it in the single-file KEX package. The shell activation
registry reads only the fixed package header and the at-most-16-KiB CMPL range,
revalidates command identity, and refreshes on the namespace command revision.
An invalid or mismatched descriptor is omitted rather than granting fallback
behavior. Shell intrinsics retain a separate immutable descriptor table because
they are owned by the shell rather than packages.

The hosted package-model follow-up will bind the embedded CMPL digest through a
new PMAN/PLOCK version. This implementation does not silently reinterpret the
existing v1 hosted formats.

Completion metadata is not KCAP. KCAP continues to declare only required typed
startup authority. No loose `/bin/*.complete` sidecar is introduced because a
mutable or independently replaced sidecar could disagree with the executable
selected for the command.

An executable completion provider is also deferred. If a declarative resolver
cannot meet a measured application need, a later design may add a separate
typed request/reply mode with a short lease and completion-specific attenuated
authority. It must not execute the ordinary application with its normal grants.

## Consequences

Application-specific argument knowledge now lives with every app rather than in
the shell's control flow. New semantic domains require an explicit portable enum addition and a
trusted composition-root resolver, making their state and authority visible in
review. Most applications use deterministic allocation-free descriptor
evaluation; open-domain enumeration remains bounded by the shell's existing
candidate policy.

Descriptor validation rejects excessive rules, predicates, literal counts and
bytes, invalid positions, control text, and inverted integer ranges. Request
validation bounds referenced arguments and text. Unknown commands and unmatched
rules produce no argument candidates, preserving the shell prompt.

Integer and address resolvers validate a complete typed prefix before offering
shell insertion; they do not pretend an infinite domain is enumerable. File
resolvers retain directories as traversal candidates even when the final value
must be a file. The native completion environment enumerates session jobs,
configured services, and mount-policy volumes without launching ordinary apps.
