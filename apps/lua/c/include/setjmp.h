#ifndef TROE_SETJMP_H
#define TROE_SETJMP_H

#if defined(__aarch64__)

#include <stdint.h>

typedef struct TroeJumpState {
  uint64_t general[12];
  uint64_t stack;
  uint64_t floating_point[8];
} jmp_buf[1];

int troe_setjmp(jmp_buf buffer) __attribute__((returns_twice));
void troe_longjmp(jmp_buf buffer, int value) __attribute__((noreturn));

#define setjmp(buffer) troe_setjmp(buffer)
#define longjmp(buffer, value) troe_longjmp((buffer), (value))

#else

/* Clang's x86_64 freestanding builtins require five pointer-sized slots. */
typedef void *jmp_buf[5];

#define setjmp(buffer) __builtin_setjmp((void **)(buffer))
#define longjmp(buffer, value) \
  ((void)(value), __builtin_longjmp((void **)(buffer), 1))

#endif

#endif
