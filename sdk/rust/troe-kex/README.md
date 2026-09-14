# TROE Rust application SDK

The default `entry!` macro and `Startup::parse` implement the ordinary ABI 1.3
command profile. Typed services use capability handles from immutable startup.
`CommandContext` owns its command streams and heap context.

## Explicit native thread profile

The optional `native-threads` feature and `threaded_entry!(main)` macro implement
ABI 1.4 initial/worker entry for the explicit resident threaded loader. The main
function accepts `threading::Initial` and returns a process exit status. Returning
from main or panicking terminates the process. Returning from a worker completes
that thread with its scalar result.

`Initial::handle` copies one exact interface/version grant; `image_base` supports
encoding an image-relative worker entry. Consuming `into_command` constructs one
typed command/heap context. This profile exposes no second mutable IPC-page owner.

Each thread binds a compiler-managed local-exec TLS object to its own validated
descriptor and TX/RX pages. Workers read the shared process header without
dereferencing the initial descriptor, whose backing can already be retired.
Service calls copy requests and validated replies while holding a thread-local
reentry guard. They preserve the full-width syscall frame and use the current RX
address even for zero-capacity replies. No page borrow escapes the call.

`threading::call` accepts the allocation-free `threading::wire` scheduler codecs.
It is unsafe: worker entries must have signature `unsafe extern "C" fn(u64) -> u64`,
and their argument/storage must remain valid until completion. Calling Exit must
perform required runtime cleanup first and must not abandon references or shared
state that depends on the retiring stack. Kernel capability and executable-entry
checks cannot establish these language-level obligations. Low-level
`service_call` likewise requires the selected interface's ownership contract.

Bare-target feature builds need freestanding Clang and an LLVM archiver (`CC`
and `AR`). The C helper only returns the current TLS object's address; it does
not assign runtime data to undocumented TCB padding. It is a minimal unprotected
bootstrap helper, not a production C stack-protection qualification. Host builds
test metadata and ownership; native operations return `UnsupportedTarget`.

The feature, native entry macro and explicit threaded conversion/loader form one
profile. Enabling the feature alone does not enable ordinary package admission
or qualify the production C allocator, libc, pthreads or CPython for threading.
The runnable consumer and pinned reproduction recipe are described in
[testing](../../../docs/testing.md); the exact startup and scheduler ABI is in
the [thread contract](../../../docs/formats/thread-v1.md).
