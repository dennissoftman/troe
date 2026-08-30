# ADR 0057: Bounded shell pathname expansion and paged command operands

Status: accepted and implemented, 2026-08-30. Amends the deliberate
no-expansion premise of ADR 0036 and raises command interface 1 from 1.1 to 1.2.

## Context

The shell parses one logical command list into words and passes those words to
a KEX application unchanged. ADR 0036 recorded that the first grammar has no
expansion of any kind, and `docs/architecture.md` states that no globbing
occurs. That premise is no longer serving the system: every filesystem tool now
accepts paths, and a session cannot name a set of them. `rm *.txt` is a literal
request to remove one file named `*.txt`.

Expansion is filesystem authority. The correct owner is the shell, which
already holds the session `Namespace` and already enumerates directories for
declarative completion (ADR 0051). Placing pattern matching inside `rm.kex`
would require granting every tool a directory-listing capability it does not
otherwise need, and would make each tool's matching rules independently
divergent. The shell expands; an application only ever receives concrete paths.

Two bounds make the naive design wrong. First, the parser discards quoting:
once a word is a `String`, `rm "*.txt"` and `rm *.txt` are the same value, so
quoting cannot suppress matching unless the parser retains it. Second, the
canonical invocation record is one IPC message. Command interface 1.1 admits
128 arguments and 1,024 aggregate argument bytes inside a 4 KiB message, which
is roughly eighty ordinary filenames. A directory holding a thousand matches
exceeds that by an order of magnitude, and silently delivering a prefix of an
expansion to a removal tool is the one outcome the design must exclude.

## Decision

### Expansion is shell-owned, quoted-aware, and never crosses a component

`parse_line` retains, per word, which bytes originated inside single or double
quotes. A word is a pattern only when it holds at least one unquoted `*`, `?`,
or `[`; quoted metacharacters match literally, so `"*"` is one literal
character while `"a"*` still matches. `Stage.words` becomes a `Word` sequence
carrying text plus that literal mask rather than a bare `String` sequence.

The matcher accepts `*`, `?`, `[abc]`, `[a-z]`, and negated `[!abc]`/`[^abc]`.
An unterminated `[` is literal. Matching is iterative rather than recursive
because it runs on a kernel stack. `*` never matches `/`, so a pattern is
expanded component by component against the namespace. A leading `*` or `?` in
a component does not match a name beginning with `.`, so `rm *` cannot remove
dotfiles.

Expansion applies to a stage's argument words. The command word is left
literal, preserving exact KEX path resolution (ADR 0050) and the interactive
confirmation for applications outside `/bin`. Redirection targets are not
expanded and remain outside argv. A pattern matching nothing is passed through
unchanged, so a failed match surfaces as the tool's own `not found` diagnostic
rather than as a silently empty command.

### Expansion is bounded, and exceeding a bound runs nothing

One expansion admits at most 4,096 resulting words and 64 KiB of aggregate
argument bytes, and visits at most 4,096 directory entries while expanding one
whole word. Storage is heap-backed and reserved fallibly; the shell holds the
result as owned words rather than in any fixed stack buffer.

Once a component has matched, every path the word produces must exist, and a
non-final component must additionally be a directory. Without that check
`*/missing` would name one nonexistent path per matched directory instead of
matching nothing.

Exceeding any bound fails the whole stage before it is dispatched. The
diagnostic names the pattern, the count reached, and the limit. No command
runs, so no partial removal, copy, or move is possible. The shell does not
split an over-budget expansion across repeated invocations: batching would make
one written command line into several independent exit statuses, and would
silently change `cp SOURCE... DIRECTORY` from one validated operation into
several unvalidated ones.

### Command interface 1.2 adds paged operands

`GET_INVOCATION` keeps its exact 1.1 encoding and bounds, so every application
that reads a stack-resident invocation record is unchanged. When the real
argument vector exceeds those bounds the operation fails closed with a distinct
service error; it never returns a truncated prefix.

`GET_ARGUMENT_PAGE` returns one bounded page of arguments from a caller-supplied
index, together with the total argument count and the next index. The reply
respects the existing 4 KiB message bound. Paged records admit up to 4,096
arguments and 64 KiB of aggregate argument bytes, matching the shell's
expansion budget.

The SDK exposes this as a borrowing cursor over one page-sized buffer, not as a
materialized argument list. Tools that treat operands independently -- `rm`,
`cat`, `ls`, `wc`, `grep` -- consume one page at a time and require no heap. A
tool needing a specific position, such as `cp` reading its destination,
requests that index directly. The immutable record may be re-read from index
zero, so a flag pre-pass followed by an operand pass is well defined.

### Tools accept operand lists

`rm [-r|-R] PATH...` parses leading flags, then removes every remaining
operand, continuing past a failed operand and reporting failure if any operand
failed. `rmdir DIRECTORY...` behaves likewise. `rmdir` is retained rather than
folded into `rm -r`: it refuses a nonempty directory, and that refusal is a
safety property that `rm -r` deliberately does not have.

`cp` and `mv` accept either `SOURCE DEST` or `SOURCE... DIRECTORY`. Destination
metadata is resolved once, before any mutation. With more than two operands the
final operand must already be an existing directory; otherwise the command
fails without copying or moving anything, which is what prevents several
sources from collapsing into one file. With exactly two operands an existing
directory destination receives the source under its own base name, and any
other destination is a file target. A source whose base name is empty, `.`, or
`..`, and a source that is the destination directory itself, are rejected.
Sources sharing a base name resolve last-writer-wins, as POSIX specifies.

## Consequences

The shell gains directory enumeration on the execution path, not only the
completion path. It gains no new capability: the authority is the session
namespace it already holds. Applications gain no listing authority and never
observe a pattern.

Per-process argument retention grows from at most 1,544 bytes to at most
64 KiB for launches that use paged operands. That storage is charged to the
launching session's accounting, and the shell's expansion bound is what caps it.

The interface minor rises, and the kernel requires an exact major and minor
match, so every committed KEX artifact under `rootfs/bin/`, the service corpus
under `tests/kex-corpus/`, and both `assets/root-*.kefs` images are rebuilt in
the same change. A stale artifact does not degrade: it fails startup.

`docs/architecture.md` and `rootfs/man/sh` stated that no expansion or globbing
occurs; both are corrected here, together with `rootfs/man/rm`,
`rootfs/man/rmdir`, `rootfs/man/cp`, `rootfs/man/mv`, and the operand positions
in the affected `completion.cmpl` descriptors. ADR 0036's language paragraph is
amended to except pathname expansion.

Still deliberately absent: variables, tilde and brace expansion, command
substitution, `nullglob`/`failglob` options, `**`, collating classes such as
`[[:alpha:]]`, case-insensitive matching, and expansion of redirection targets.
Each remains a later grammar decision with its own bounds.

Closure gates are quoting suppression including partially quoted words, the
leading-dot and no-`/`-crossing rules, multi-component patterns with literal
components verified after a match, atomic refusal of an over-budget expansion,
and a thousand-argument record round-tripping through the paged protocol at
both the encoding and service layers.
