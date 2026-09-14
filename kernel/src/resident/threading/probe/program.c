/* Acceptance-only freestanding TLS consumer; the production libc is separate. */
typedef unsigned long long u64;
_Thread_local volatile u64 marker = 0x1122334455667788ULL;
_Thread_local volatile u64 counter;
_Thread_local volatile u64 *self;
static u64 shared;
static u64 pipe_token;

static void trap_full(u64 number, u64 a, u64 b, u64 c, u64 reply, u64 capacity, u64 *status, u64 *bytes) {
#if defined(__x86_64__)
    register u64 d __asm__("r10") = reply;
    register u64 e __asm__("r8") = capacity;
    register u64 f __asm__("r9") = 0;
    __asm__ volatile("int $0x80" : "+a"(number), "+D"(a), "+S"(b), "+d"(c), "+r"(d), "+r"(e), "+r"(f) : : "memory", "cc");
    *status = number; *bytes = c;
#else
    register u64 n __asm__("x8") = number;
    register u64 x0 __asm__("x0") = a;
    register u64 x1 __asm__("x1") = b;
    register u64 x2 __asm__("x2") = c;
    register u64 x3 __asm__("x3") = reply;
    register u64 x4 __asm__("x4") = capacity;
    register u64 x5 __asm__("x5") = 0;
    __asm__ volatile("svc #0" : "+r"(n), "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5) : : "memory", "cc");
    *status = x0; *bytes = x1;
#endif
}
static void trap(u64 number, u64 a, u64 b, u64 c, u64 *status, u64 *bytes) {
    trap_full(number, a, b, c, 0, 0, status, bytes);
}
__attribute__((noreturn)) static void exit_process(u64 value) {
    u64 status, bytes;
    trap(0, value, 0, 0, &status, &bytes);
    __builtin_trap();
}
#define CHECK(condition) do { if (!(condition)) exit_process(__LINE__); } while (0)
static volatile u64 *header(void) { return (volatile u64 *)self[3]; }
static u64 handle(u64 interface) {
    volatile u64 *process = header();
    const u64 count = process[1] >> 48;
    for (u64 i = 0; i < count; ++i) {
        if (process[13 + 3 * i] >> 32 == interface) return process[12 + 3 * i];
    }
    exit_process(__LINE__);
}
static u64 service(u64 interface, u64 opcode, u64 a, u64 b, u64 payload, u64 expected) {
    volatile unsigned char *tx = (volatile unsigned char *)self[10];
    volatile u64 *rx = (volatile u64 *)self[11];
    tx[0] = opcode; tx[1] = opcode >> 8;
    for (u64 i = 0; i < 8; ++i) { tx[2+i] = a >> (8*i); tx[10+i] = b >> (8*i); }
    u64 status, bytes;
    trap_full(2, handle(interface), (u64)tx, payload + 2, (u64)rx, 4096, &status, &bytes);
    CHECK(!status && bytes == expected);
    for (u64 i = expected; i < 4096; ++i) CHECK(!((volatile unsigned char *)rx)[i]);
    return rx[0];
}
static void sleep_for(u64 milliseconds) {
    const u64 deadline = service(8, 1, 0, 0, 0, 8) + milliseconds;
    service(8, 2, deadline, 0, 8, 0);
    CHECK(service(8, 1, 0, 0, 0, 8) >= deadline);
}
static u64 request(u64 interface, u64 opcode, u64 a, u64 b, u64 c, u64 outcome) {
    volatile u64 *tx = (volatile u64 *)self[10];
    volatile u64 *rx = (volatile u64 *)self[11];
    tx[0] = (interface << 32) | (opcode << 16) | 1;
    tx[1] = a; tx[2] = b; tx[3] = c;
    for (u64 i = 4; i < 8; ++i) tx[i] = 0;
    u64 status, bytes;
    trap(6, handle(interface), 64, 32, &status, &bytes);
    CHECK(!status && bytes == 32);
    CHECK(rx[0] == ((opcode << 48) | (1ULL << 32) | interface));
    CHECK(rx[1] == outcome && !rx[3] && (!outcome || !rx[2]));
    for (u64 i = 4; i < 512; ++i) CHECK(!rx[i]);
    return rx[2];
}
__attribute__((noinline)) static u64 worker(u64 argument) {
    CHECK((argument == 0x55 || argument == 0x56) && marker == 0x1122334455667788ULL && !counter);
    CHECK(request(30, 8, 0, 0, 0, 0) == self[2]);
    marker += 0x22; counter++;
    u64 status, bytes;
    trap(1, 0, 0, 0, &status, &bytes);
    CHECK(marker == 0x11223344556677aaULL && counter == 1);
    sleep_for(5);
    const u64 value = service(21, 3, pipe_token, 1, 16, 1);
    CHECK(value == 0xa1 || value == 0xa2);
    const u64 bit = 1ULL << (value - 0xa1);
    CHECK(!(__atomic_fetch_or(&shared, bit, __ATOMIC_ACQ_REL) & bit));
    return 0x7788 + argument - 0x55;
}
__attribute__((noreturn)) void __troe_thread_start_v1(volatile u64 *descriptor, u64 bytes) {
    CHECK(bytes == 128 && !descriptor[14] && descriptor[15] == (u64)descriptor);
    self = descriptor;
    u64 (*entry)(u64) = (u64 (*)(u64))descriptor[12];
    request(30, 9, entry(descriptor[13]), 0, 0, 0);
    exit_process(1);
}
__attribute__((noreturn)) void _start(volatile u64 *process, u64 bytes) {
    CHECK(bytes == 4096 && process[11] == 128);
    self = (volatile u64 *)process[10];
    CHECK(self[14] == 1 && self[15] == (u64)self);
    CHECK(marker == 0x1122334455667788ULL && !counter && !process[4]);
    CHECK(request(30, 8, 0, 0, 0, 0) == self[2]);
    const u64 entry = (u64)worker - process[2];
    request(30, 1, 0x3fffffff, 0, 4, 13);
    request(30, 1, entry, 0, 257, 10);
    u64 aborted = request(30, 1, entry, 0x55, 4, 0);
    request(30, 3, aborted, 0, 0, 0);
    u64 child = request(30, 1, entry, 0x55, 4, 0);
    CHECK(child != aborted);
    u64 sibling = request(30, 1, entry, 0x56, 4, 0);
    pipe_token = service(21, 1, 4096, 0, 4, 8);
    marker += 0x11; counter++;
    request(30, 2, child, 0, 0, 0);
    request(30, 2, sibling, 0, 0, 0);
    sleep_for(50);
    CHECK(!__atomic_load_n(&shared, __ATOMIC_ACQUIRE));
    service(21, 2, pipe_token, 0xa1, 9, 0);
    sleep_for(50);
    CHECK(__atomic_load_n(&shared, __ATOMIC_ACQUIRE) == 1);
    service(21, 2, pipe_token, 0xa2, 9, 0);
    CHECK(request(30, 4, child, 1, 0, 0) == 0x7788);
    CHECK(request(30, 4, sibling, 1, 0, 0) == 0x7789);
    service(21, 4, pipe_token, 0, 8, 0);
    service(21, 5, pipe_token, 0, 8, 0);
    CHECK(marker == 0x1122334455667799ULL && counter == 1);
    CHECK(__atomic_load_n(&shared, __ATOMIC_ACQUIRE) == 3);
    u64 mutex = request(31, 1, 0, 0, 0, 0);
    request(31, 4, mutex, 1, 0, 0);
    request(31, 5, mutex, 0, 0, 0);
    request(31, 10, mutex, 0, 0, 0);
    u64 status, mapped;
    trap(3, 1, 0, 0, &status, &mapped);
    CHECK(!status && mapped == 4096);
    volatile u64 *heap = (volatile u64 *)process[3];
    for (u64 i = 0; i < 512; ++i) CHECK(!heap[i]);
    heap[511] = 0xfeed;
    trap(3, 1, 0, 0, &status, &mapped);
    CHECK(!status && mapped == 8192 && heap[511] == 0xfeed);
    for (u64 i = 512; i < 1024; ++i) CHECK(!heap[i]);
    exit_process(0);
}
