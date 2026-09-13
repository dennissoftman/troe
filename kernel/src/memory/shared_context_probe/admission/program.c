/* Native acceptance only; compiler local-exec TLS, no libc or stack protector. */
typedef unsigned long long u64;
_Thread_local volatile u64 marker = 0x1122334455667788ULL;
_Thread_local volatile u64 counter;

static void call(u64 number, u64 a, u64 b, u64 c) {
#if defined(__x86_64__)
    register u64 d __asm__("r10") = 0;
    register u64 e __asm__("r8") = 0;
    register u64 f __asm__("r9") = 0;
    __asm__ volatile("int $0x80" : "+a"(number), "+D"(a), "+S"(b), "+d"(c), "+r"(d), "+r"(e), "+r"(f) : : "memory", "cc");
#else
    register u64 n __asm__("x8") = number;
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = 0;
    register u64 x4 __asm__("x4") = 0;
    register u64 x5 __asm__("x5") = 0;
    __asm__ volatile("svc #0" : "+r"(n), "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5) : : "memory", "cc");
#endif
}
__attribute__((noreturn)) static void fail(void) {
    call(0, 1, 0, 0);
    __builtin_trap();
}
__attribute__((noreturn,noinline)) static void run(volatile u64 *descriptor, u64 initial) {
    volatile u64 *header = (volatile u64 *)descriptor[3];
    if (descriptor[0] != 0x317652485454ULL || descriptor[14] != initial ||
        descriptor[15] != (u64)descriptor || descriptor[4] != 4096 ||
        header[0] != 0x123456789abcdef0ULL || marker != 0x1122334455667788ULL || counter)
        fail();
    if (initial ? (descriptor[12] || descriptor[13]) : (!descriptor[12] || descriptor[13] != 0x55))
        fail();
    for (u64 i = 16; i < 512; ++i) if (descriptor[i]) fail();
    const u64 increment = initial ? 0x11 : 0x22;
    for (u64 i = 0; i < 2; ++i) {
        if (marker != 0x1122334455667788ULL + i * increment || counter != i) fail();
        marker += increment;
        counter++;
        call(1, 0, 0, 0);
    }
    if (marker != 0x1122334455667788ULL + 2 * increment || counter != 2 ||
        header[0] != 0x123456789abcdef0ULL) fail();
    if (!initial) {
        if (header[14] == 1) { volatile u64 value = *(volatile u64 *)header[10]; (void)value; fail(); }
        if (header[14] == 2) { descriptor[0] = 0; fail(); }
        if (header[14] == 3) { volatile u64 value = *(volatile u64 *)(descriptor[5] - 4096); (void)value; fail(); }
    }
    volatile u64 *tx = (volatile u64 *)descriptor[10];
    for (u64 i = 0; i < 8; ++i) tx[i] = header[32 + i];
    call(6, header[15], 64, 32);
    fail();
}
__attribute__((noreturn,section(".text.entry.initial"))) void initial_entry(volatile u64 *header, u64 bytes) {
    if (bytes != 4096 || header[11] != 128) fail();
    run((volatile u64 *)header[10], 1);
}
__attribute__((noreturn,section(".text.entry.worker"))) void worker_entry(volatile u64 *descriptor, u64 bytes) {
    if (bytes != 128) fail();
    run(descriptor, 0);
}
