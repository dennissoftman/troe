/* Audited unprotected bootstrap: compiler-managed local-exec storage, no
 * allocation, calls, buffer access, or dependency on libc-private TCB bytes.
 * Rust binds the validated descriptor before any threaded SDK operation. */
struct troe_native_local_v1 {
  const unsigned char *descriptor;
  unsigned long long tx;
  unsigned long long rx;
  unsigned long long control;
  unsigned long long sync;
  unsigned long long busy;
};

_Static_assert(sizeof(void *) == 8 && sizeof(unsigned long long) == 8,
               "native SDK TLS requires the 64-bit profile");

static _Thread_local struct troe_native_local_v1 local;

struct troe_native_local_v1 *__troe_native_local_v1(void) { return &local; }
