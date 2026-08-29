#ifndef TROE_SETJMP_H
#define TROE_SETJMP_H

#include <stdint.h>

#if defined(__aarch64__)
typedef struct {
  uint64_t general[12];
  uint64_t stack;
  uint64_t floating_point[8];
} jmp_buf[1];
#elif defined(__x86_64__)
typedef struct {
  uint64_t rbx, rbp, r12, r13, r14, r15, stack, instruction;
} jmp_buf[1];
#else
#error "TROE C sysroot supports only x86_64 and aarch64"
#endif

int troe_setjmp(jmp_buf buffer) __attribute__((returns_twice));
void troe_longjmp(jmp_buf buffer, int value) __attribute__((noreturn));
#define setjmp(buffer) troe_setjmp(buffer)
#define longjmp(buffer, value) troe_longjmp((buffer), (value))

#endif
