/* Native acceptance only: compiler TLS and canonical creation calls, no libc/SSP. */
typedef unsigned long long u64;
_Thread_local volatile u64 marker = 0x1122334455667788ULL;
_Thread_local volatile u64 counter;
_Thread_local volatile u64 *self;

static void trap(u64 number, u64 a, u64 b, u64 c, u64 *status, u64 *bytes) {
#if defined(__x86_64__)
    register u64 d __asm__("r10") = 0;
    register u64 e __asm__("r8") = 0;
    register u64 f __asm__("r9") = 0;
    __asm__ volatile("int $0x80" : "+a"(number), "+D"(a), "+S"(b), "+d"(c), "+r"(d), "+r"(e), "+r"(f) : : "memory", "cc");
    *status = number; *bytes = c;
#else
    register u64 n __asm__("x8") = number;
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = 0;
    register u64 x4 __asm__("x4") = 0;
    register u64 x5 __asm__("x5") = 0;
    __asm__ volatile("svc #0" : "+r"(n), "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5) : : "memory", "cc");
    *status = x0; *bytes = x1;
#endif
}
__attribute__((noreturn)) static void fail(void) {
    u64 status, bytes;
    trap(0, 1, 0, 0, &status, &bytes);
    __builtin_trap();
}
static volatile u64 *header(void) { return (volatile u64 *)self[3]; }
static volatile u64 *shared(void) { return (volatile u64 *)header()[13]; }
static u64 request(u64 opcode, u64 a, u64 b, u64 c, u64 outcome) {
    volatile u64 *tx = (volatile u64 *)self[10];
    volatile u64 *rx = (volatile u64 *)self[11];
    tx[0] = (30ULL << 32) | (opcode << 16) | 1;
    tx[1] = a; tx[2] = b; tx[3] = c;
    for (u64 i = 4; i < 8; ++i) tx[i] = 0;
    u64 status, bytes;
    trap(6, header()[15], 64, 32, &status, &bytes);
    if (status || bytes != 32 || rx[0] != ((opcode << 48) | (1ULL << 32) | 30) ||
        rx[1] != outcome || rx[3] || (outcome && rx[2])) fail();
    for (u64 i = 4; i < 512; ++i) if (rx[i]) fail();
    return rx[2];
}
static void check_tls(u64 increment) {
    if (marker != 0x1122334455667788ULL + increment || counter != 1 ||
        self[15] != (u64)self || header()[0] != 0x123456789abcdef0ULL) fail();
}
__attribute__((noreturn)) static void finish(u64 value) {
    request(9, value, 0, 0, 0);
    fail();
}
__attribute__((noinline)) u64 worker_body(u64 argument) {
    if (argument != 0x55 || shared()[2] != 0xfeedface ||
        marker != 0x1122334455667788ULL || counter) fail();
    marker += 0x22; counter++;
    if (request(8, 0, 0, 0, 0) != self[2]) fail();
    const u64 entry = (u64)worker_body - 0x400000000000ULL;
    u64 child = request(1, entry, 0x99, 1, 0);
    shared()[1] = child;
    u64 status, bytes;
    trap(1, 0, 0, 0, &status, &bytes);
    check_tls(0x22);
    if (request(3, child, 0, 0, 0)) fail();
    u64 fresh = request(1, entry, 0x99, 1, 0);
    if (fresh == child || (fresh & 0xffffff) != (child & 0xffffff)) fail();
    shared()[1] = fresh;
    shared()[3] = 0x55d00d;
    return 0x7788;
}
__attribute__((noreturn,section(".text.entry.initial"))) void initial_entry(volatile u64 *process, u64 bytes) {
    if (bytes != 4096 || process[11] != 128) fail();
    self = (volatile u64 *)process[10];
    if (self[14] != 1 || self[15] != (u64)self || marker != 0x1122334455667788ULL || counter) fail();
    const u64 entry = (u64)worker_body - 0x400000000000ULL;
    request(1, 0x100000, 0x55, 1, 13); /* Unmapped image entry. */
    request(1, entry, 0x55, 2, 10); /* Stack allowance. */
    request(1, entry, 0x55, 1, 10); /* Injected IPC exhaustion after reservation. */
    u64 worker = request(1, entry, 0x55, 1, 0);
    shared()[0] = worker;
    shared()[2] = 0xfeedface;
    marker += 0x11; counter++;
    if (request(2, worker, 0, 0, 0)) fail();
    check_tls(0x11);
    if (!shared()[1]) fail(); /* Worker ran before Start's successful return. */
    request(1, entry, 0x55, 1, 10); /* Initial, worker and prepared child fill quota. */
    request(2, shared()[1], 0, 0, 11); /* Another creator's preparation. */
    request(3, shared()[1], 0, 0, 11);
    if (request(8, 0, 0, 0, 0) != self[2]) fail();
    if (request(4, worker, 1, 0, 0) != 0x7788) fail();
    check_tls(0x11);
    if (shared()[3] != 0x55d00d) fail();
    finish(~0ULL);
}
__attribute__((noreturn,section(".text.entry.worker"))) void worker_entry(volatile u64 *descriptor, u64 bytes) {
    if (bytes != 128 || descriptor[14] || descriptor[15] != (u64)descriptor) fail();
    self = descriptor;
    u64 (*entry)(u64) = (u64 (*)(u64))descriptor[12];
    finish(entry(descriptor[13]));
}
