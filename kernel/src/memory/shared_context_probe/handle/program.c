/* Native mechanism acceptance: per-thread IPC and copied ordinary calls; no libc/SSP. */
typedef unsigned long long u64;

static u64 tls_read(u64 offset) {
#if defined(__x86_64__)
    u64 value;
    __asm__ volatile("movq %%fs:(%1), %0" : "=r"(value) : "r"(offset) : "memory");
    return value;
#else
    u64 base;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(base));
    return *(volatile u64 *)(base + offset);
#endif
}
static void tls_write(u64 offset, u64 value) {
#if defined(__x86_64__)
    __asm__ volatile("movq %0, %%fs:(%1)" : : "r"(value), "r"(offset) : "memory");
#else
    u64 base;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(base));
    *(volatile u64 *)(base + offset) = value;
#endif
}
static void trap(u64 number, u64 a, u64 b, u64 c, u64 d, u64 e, u64 *status, u64 *bytes) {
#if defined(__x86_64__)
    register u64 x3 __asm__("r10") = d;
    register u64 x4 __asm__("r8") = e;
    register u64 x5 __asm__("r9") = 0;
    __asm__ volatile("int $0x80" : "+a"(number), "+D"(a), "+S"(b), "+d"(c), "+r"(x3), "+r"(x4), "+r"(x5) : : "memory", "cc");
    *status = number; *bytes = c;
#else
    register u64 n __asm__("x8") = number;
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = d;
    register u64 x4 __asm__("x4") = e;
    register u64 x5 __asm__("x5") = 0;
    __asm__ volatile("svc #0" : "+r"(n), "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5) : : "memory", "cc");
    *status = x0; *bytes = x1;
#endif
}
__attribute__((noreturn)) static void fail(void) {
    u64 status, bytes;
    trap(0, 1, 0, 0, 0, 0, &status, &bytes);
    __builtin_trap();
}
__attribute__((noreturn,section(".text.entry"))) void entry(volatile u64 *startup, u64 bytes) {
    const u64 marker = *startup;
    if (bytes != 8 || marker != tls_read(0)) fail();
    volatile u64 *tx = (volatile u64 *)tls_read(24);
    volatile u64 *rx = tx + 512;
    volatile u64 *peer = (volatile u64 *)tls_read(32);
    for (u64 round = 0; round < 2; ++round) {
        const u64 mode = tls_read(48);
        if (mode == 1) __builtin_trap();
        tx[0] = 5;
        tx[1] = marker;
        tx[2] = round;
        if (mode == 4) for (u64 i = 3; i < 512; ++i) tx[i] = marker + round + i;
        if (marker == 22) { peer[1] = 0xbadbad; peer[511] = 0xbadbad; }
        u64 status, count;
        trap(2, 0x123456, (u64)tx + (mode == 2 ? 8 : 0), mode == 4 ? 4096 : 24,
             (u64)rx + (mode == 3 ? 8 : 0), mode == 4 ? 4096 : mode == 5 ? 0 : 8,
             &status, &count);
        const u64 wanted = mode == 5 || mode == 6 ? 0 : 8;
        if (status != (mode == 6 ? 20 : 0) || count != wanted ||
            (wanted && rx[0] != marker + round)) fail();
        for (u64 i = wanted / 8; i < 512; ++i) if (rx[i]) fail();
        tls_write(16, round + 1);
        trap(1, 0, 0, 0, 0, 0, &status, &count);
    }
    for (;;) {
        u64 status, count;
        trap(1, 0, 0, 0, 0, 0, &status, &count);
    }
}
