#ifndef TROE_STRING_H
#define TROE_STRING_H

#include <stddef.h>

void *memcpy(void *destination, const void *source, size_t size);
void *memmove(void *destination, const void *source, size_t size);
void *memset(void *destination, int value, size_t size);
int memcmp(const void *left, const void *right, size_t size);
void *memchr(const void *bytes, int value, size_t size);
char *strchr(const char *text, int value);
int strcmp(const char *left, const char *right);
int strcoll(const char *left, const char *right);
char *strcpy(char *destination, const char *source);
char *strerror(int error);
size_t strlen(const char *text);
int strncmp(const char *left, const char *right, size_t size);
char *strpbrk(const char *text, const char *accepted);
size_t strspn(const char *text, const char *accepted);
char *strstr(const char *text, const char *needle);

#endif
