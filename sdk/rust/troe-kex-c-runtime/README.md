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
