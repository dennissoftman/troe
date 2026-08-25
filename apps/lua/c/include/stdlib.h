#ifndef TROE_STDLIB_H
#define TROE_STDLIB_H

#include <stddef.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

void abort(void) __attribute__((noreturn));
int abs(int value);
void exit(int status) __attribute__((noreturn));
void free(void *pointer);
void *malloc(size_t size);
void *realloc(void *pointer, size_t size);
double strtod(const char *text, char **end);

#endif
