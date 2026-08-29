#ifndef TROE_STRING_H
#define TROE_STRING_H

#include <stddef.h>

void *memcpy(void *destination, const void *source, size_t size);
void *memmove(void *destination, const void *source, size_t size);
void *memset(void *destination, int value, size_t size);
int memcmp(const void *left, const void *right, size_t size);
void *memchr(const void *bytes, int value, size_t size);
size_t strlen(const char *text);
size_t strnlen(const char *text, size_t maximum);
int strcmp(const char *left, const char *right);
int strncmp(const char *left, const char *right, size_t size);
int strcoll(const char *left, const char *right);
size_t strxfrm(char *destination, const char *source, size_t capacity);
char *strcpy(char *destination, const char *source);
char *strncpy(char *destination, const char *source, size_t size);
char *strcat(char *destination, const char *source);
char *strncat(char *destination, const char *source, size_t size);
char *strchr(const char *text, int value);
char *strrchr(const char *text, int value);
char *strpbrk(const char *text, const char *accepted);
size_t strspn(const char *text, const char *accepted);
size_t strcspn(const char *text, const char *rejected);
char *strstr(const char *text, const char *needle);
char *strtok(char *text, const char *separators);
char *strtok_r(char *text, const char *separators, char **state);
char *strerror(int error);
int strerror_r(int error, char *destination, size_t capacity);
char *strdup(const char *text);
char *strndup(const char *text, size_t maximum);

#endif
