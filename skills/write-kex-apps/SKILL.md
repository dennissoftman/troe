---
name: write-kex-apps
description: Write, review, build, or debug secure TROE KEX command applications using the repo-local Rust SDK and canonical Rust builder. Use for work under apps/, SDK-facing ABI questions, KEX command replacement, or generated rootfs/bin artifacts.
---

# Write TROE KEX apps

Work from the repository root. Read `apps/echo` (streams), `apps/udp`
(datagrams), `sdk/rust/troe-kex/src/lib.rs`, and `crates/troe-abi/src/lib.rs`
only as needed. Do not infer POSIX behavior.

## App contract

- Use Rust `#![no_std]`, `#![no_main]`, and `troe_kex_sdk::entry!`.
- Implement `fn main(&mut CommandContext) -> u32`; return a constant from
  `troe_kex_sdk::exit`.
- Get `cwd`/`argv` with `CommandContext::invocation`; use only granted
  `stdin`, `stdout`, `stderr`, optional datagram/filesystem/mutation/timer/
  diagnostics clients, and cooperative `yield_now`.
- Declare every optional authority in `[package.metadata.troe-kex]`
  `capabilities`; use `[]` or omit the table when none is needed.
- No undeclared filesystem, environment, clock, raw sockets/device access,
  threads, process spawning, dynamic linking, TLS, signals, or allocator is
  granted.
- Never hand-code call gates, startup parsing, handle values, ELF layout, or
  KEX bytes. Do not add `unsafe` unless a reviewed SDK change strictly needs it.
- Treat every argument/input byte and every service result as untrusted. Check
  errors, avoid panics, and fail closed with `exit::FAILURE` or `exit::USAGE`.

Hard ABI ceilings: 32 arguments including argv[0], 256-byte cwd, 512 aggregate
argument bytes, 4,094-byte service payload, 4 KiB message, and 64 KiB total per
standard stream. Stream reads may be partial; zero bytes is EOF. `write_all`
either accepts the complete slice in bounded calls or returns an error.
Datagrams are IPv4/UDP only, at most 1,472 payload bytes. Explicit ports are
nonzero and exclusively owned until app teardown; `receive` is cancellable and
reports Ctrl-C as `Error::Cancelled`. Treat `command.datagram()` as optional.
Read-only filesystem paths are at most 256 bytes; opens are generation-checked
and limited to eight. Reads may be partial. Close every open file. Directory
pages are lexical and opaque-cursor based, with at most 64 entries, 64-byte
names, and 3,072 aggregate name bytes. Request `filesystem-read` only when used.
Mutation permits one 64 KiB complete-file staging transaction: append
sequentially, then commit or abort; teardown aborts unfinished work. Remove is
atomic. Request `filesystem-mutate` only for create/replace/remove operations.
Timer values are boot-relative monotonic milliseconds only. Request `timer`,
form deadlines with saturation, and treat `sleep_until` as cancellable.
Diagnostics is one immutable typed launch snapshot. Request `diagnostics` only
for bounded reporting; it grants no mutable memory, input, or device access.

## Minimal crate

Create a standalone crate under `apps/<command>` (include an empty `[workspace]`
table), commit its `Cargo.lock` (`cargo kex` is locked), and depend on:

```toml
[dependencies]
troe-kex-sdk = { path = "../../sdk/rust/troe-kex" }

[profile.release]
codegen-units = 1
lto = false
opt-level = "z"
panic = "abort"
strip = "none"

[workspace]
```

Use the adapter shape:

```rust
#![no_std]
#![no_main]

use troe_kex_sdk::{CommandContext, entry, exit};

fn main(command: &mut CommandContext) -> u32 {
    let mut output = command.stdout();
    if output.write_all(b"ready\n").is_err() {
        return exit::FAILURE;
    }
    exit::SUCCESS
}

entry!(main);
```

Keep computation in a separate `no_std` library module when host unit tests are
useful. Prefer fixed-size stack storage and streaming over buffering. Keep stack
usage within the four-page default; declare `stack-pages` or `heap-pages` in
package metadata only with a measured, reviewed reason.

## Build and verify

The installed name must match `[a-z0-9][a-z0-9_-]*`:

```sh
cargo kex build apps/<command> --target all
cargo kex build apps/<command> --target all --check
cargo kex inspect rootfs/bin/x86_64/<command>.kex
cargo kex inspect rootfs/bin/aarch64/<command>.kex
```

The builder pins the freestanding targets and linker policy, validates the ELF,
converts through strict KEX v1, and installs architecture-specific `.kex` plus
least-authority `.kcap` artifacts.
Never copy one architecture's artifact to the other. KEFS assembly projects the
selected source directory into flat runtime `/bin`; verify both target roots.

Before handing off, run formatting, app/library tests, both KEX byte checks, and
the narrowest relevant kernel/QEMU gate. For a new command name, acceptance must
execute that unknown-to-the-shell name; for replacement, also test fallback
when the artifact is absent and confirm intrinsics remain non-shadowable.

If a required capability is absent, stop and propose a versioned interface in
`troe-abi` plus a bounded kernel service. Do not smuggle authority through raw
pointers, magic opcodes, writable executable paths, or ad-hoc syscalls.
