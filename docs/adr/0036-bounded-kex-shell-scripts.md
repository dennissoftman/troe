# ADR 0036: Bounded KEX shell scripts without nested execution

Status: accepted and implemented, 2026-08-27; nested-launch premise superseded
by ADR 0046 while the current `sh.kex` sidecar behavior remains implemented;
the no-expansion premise amended by ADR 0057, which adds bounded pathname
expansion.

## Context

The interactive shell executes one parsed logical command list at a time and
every ordinary command is an isolated KEX application. A conventional `sh.kex` cannot launch a
second KEX while it is running: native application entry deliberately rejects a
nested launch, and granting an interpreter ambient kernel or shell authority
would violate the typed least-authority boundary.

The first required workload is an architecture-independent command transcript
using physical command lines, blank lines, leading comments, literal quoting,
pipelines, `&&`/`||` short-circuit lists, and `<`/`>` redirection. It does not
require variables, control-flow blocks, loops, substitution, multiline shell
grammar, jobs, or direct executable files.

## Decision

Interface 16, `shell-script` 1.0, is an optional KEX startup authority. Its only
operation submits one one-based physical line number plus one nonempty UTF-8
command line. A line is at most 512 bytes. The kernel sidecar validates the exact
wire encoding and the existing TROE parser before retaining an owned copy.

One interpreter launch may submit at most 1,024 lines and 64 KiB of aggregate
command bytes. The complete source accepted by `sh.kex` is also at most 64 KiB.
Blank lines and lines whose first non-whitespace byte is `#` are discarded by
the interpreter. CRLF is normalized only by removing the terminal `\r`; embedded
NUL, CR, LF, invalid UTF-8, malformed syntax, excess, allocation failure, or an
unsupported service request fails closed.

Submission never executes a command. The sidecar batch remains private to the
one `sh.kex` launch. Only a normal zero-status application exit publishes the
batch to the shell; rejection, nonzero exit, fault, cancellation, lease expiry,
or partial setup discards every submitted line. This makes source validation
transactional even though later command side effects are not rolled back.

After `sh.kex` exits and all its handles and address-space resources are
revoked, the owning shell executes the published lines synchronously through
the same parser, KEX resolver, streams, and redirection paths used by interactive
input. This avoids nested native execution and lets `cd` update the owning
session. Runtime command failures do not stop later physical lines. The batch
returns the last executed command status. Script nesting is limited to four,
and all nested batches share one 1,024-pipeline execution budget; every entry
in a logical list consumes that budget even when short-circuited.

The runtime command is `/bin/sh.kex` and is invoked as `sh [FILE | -]`. A file
is streamed through the existing read-only filesystem capability; `-` or no
operand reads standard input. TROE does not search executable paths or honor a
shebang, so a script is run explicitly with `sh FILE`.

## Consequences

`sh.kex` is an ordinary immutable application with exactly `filesystem-read`
and `shell-script` optional capabilities. It has no command-spawn operation,
filesystem mutation authority, process table, environment, or machine control.
Child commands receive only their own manifests' capabilities after the
interpreter has been reclaimed.

The first language deliberately has no variables, control-flow blocks, loops,
functions, command substitution, multiline constructs, traps, jobs, descriptor
syntax, stderr redirection, or POSIX compatibility claim. It had no expansion of
any kind until ADR 0057 added bounded pathname expansion; every other form of
expansion remains absent.
`&&` and `||` provide only same-line status-based short circuiting. Each broader
feature requires a later grammar/version decision and dedicated bounds. The
accepted example under `/share/sh/bench.sh` plus transactional rejection,
standard-input loading, cwd persistence, both-target KEX artifacts, and native
QEMU execution are the closure gates.
