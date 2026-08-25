# ADR 0030: KEX-only ordinary commands

Status: accepted and implemented for the completed Stage 9 command migration,
2026-08-25. This supersedes only the absent-artifact recovery-fallback clauses
of ADR 0024 and related command-service ADRs.

## Decision

The shell implements exactly three non-shadowable intrinsics: `cd`, `poweroff`,
and `reboot`. Every other command name is resolved as `/bin/<name>.kex` and has
no statically linked shell implementation. A registered name with no artifact
returns not-found as `application unavailable`; an unregistered name returns
not-found as `unknown command`. A present malformed, incompatible, denied,
faulting, or over-budget application continues to fail closed.

The shell retains only bounded parsing, sequential pipeline transport, logical
working-directory state, command metadata/completion, and authorized terminal
machine transitions. It owns no command filesystem, mutation, timer,
diagnostics, or network capability. The kernel command runner validates KCAP,
constructs only the declared typed services, executes the isolated task, and
revokes all owner state before the shell resumes.

The immutable target-selected KEFS root is the recovery command distribution:
both supported images contain behavior-equivalent KEX apps for `arp`, `cat`,
`clear`, `dhcp`, `echo`, `grep`, `hexdump`, `ls`, `man`, `mem`, `net`, `ping`,
`printf`, `pwd`, `rm`, `sleep`, `tcp`, `udp`, and `write`. Losing one artifact does not
silently substitute privileged code with different authority or semantics.
`cd` cannot be external because it mutates the shell session; poweroff and
reboot remain intrinsic because ABI 1.0 intentionally exposes no
machine-control service.

## Consequences

The hosted executable is a parser, pipeline, completion, and intrinsic model;
it does not emulate target-native KEX execution. Unit tests use an explicit
external-runner fixture for pipeline invariants, while booted-image QEMU tests
are the behavior and isolation gate for real command apps on both architectures.

There is now one application path for small utilities and later larger programs
such as Lua: the same startup ABI, typed least-authority services, memory limits,
cancellation, fault containment, and teardown apply. Recovery depends on the
immutable KEX root and loader rather than privileged utility duplication.
Package signing, generation publication, jobs, and interpreter-specific
resource policies remain separate decisions. ADR 0031 defines the bounded TCP
authority used only by `tcp.kex`.
