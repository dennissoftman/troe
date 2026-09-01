# TROE freestanding C sysroot

This sysroot defines the shared LP64 C target used by statically linked KEX
language runtimes on `x86_64-unknown-none` and `aarch64-unknown-none`. Builds use
`-nostdlibinc` and this `include/` directory, so no host libc declaration or
layout enters a runtime artifact.

The standard headers own C types, constants, errno values, UTF-8 conversion,
UTC/C-locale behavior, descriptor and stream layouts, setjmp state, single-
execution-thread pthread stubs, and the versioned `troe/runtime.h` host bridge.
The linked implementation owns the corresponding symbols. Thread creation,
signals beyond fail-closed `raise`, executable mappings, networking, dynamic
linking, additional locales, and timezone databases are unsupported. `struct
tm` carries `tm_gmtoff` and `tm_zone`, and `tzset`, `localtime`, `mktime`,
`timegm`, and `strftime` resolve the POSIX `TZ` string the launch supplies.

Build both architecture sysroots into an empty output directory and verify
byte-for-byte deterministic output with:

```console
python3 tools/build_c_sysroot.py build/c-sysroot --architecture all --check
```

Each architecture directory contains `include/`, `lib/libtroe_c.a`, and a
canonical `TARGET.json` ownership record. The archive is a build-time static
library; it is not installed in the guest filesystem. A KEX build links the
archive and supplies the versioned `troe_runtime_host` callbacks through the
Rust `troe-kex-c-runtime` bridge.
