# TROE KEX C runtime bridge

This `no_std` crate binds the freestanding C runtime to one KEX
`CommandContext`. `Runtime::new` takes ownership of the application heap,
enables the private-mapping allocator path when that capability is present,
and snapshots only the typed filesystem, mutation, timer, wall-clock, and
random services granted to the executable. `Runtime::host` returns the exact C
callback table declared in `troe/runtime.h`.

The bridge retains at most 32 read-only file tokens and one sequential
replacement transaction. It translates typed KEX errors to the shared errno
contract, returns `EACCES` for absent capabilities, and provides no ambient
filesystem or kernel access. Allocation statistics expose exact live bytes and
private mappings so an executable can prove complete reclamation after
`troe_runtime_finalize`.

Callbacks borrow immutable service handles and copy them into local owners before
I/O. File and replacement tables use short, separate atomic exclusions. An
operation moves its resource out of the table while retaining a busy slot, so no
table lock or mutable reference to the complete runtime crosses a service call.
Competing calls on the same token return `EBUSY`; unrelated resources remain
available. Close and replacement finish retain their slot until the service
returns. Tokens contain a slot and nonzero generation; stale tokens return
`EINVAL`, and generation exhaustion permanently excludes the slot from reuse.
Replacement writes retain the SDK's exact progress after a partial failure;
retrying with a superseded offset is rejected before sending more bytes.

The allocator has its own atomic exclusion, including statistics and bounded
backing calls. Those calls require no sibling progress and invoke no user
callbacks. Code under an exclusion cannot voluntarily exit or invoke user code.
The C ABI-1 profile remains single-threaded: these ownership rules do not enable
pthread creation, supply thread-local C state, or qualify a threaded allocator.
`Runtime` and its host table must remain live and unmoved until all C callbacks
have returned and finalization is complete.
