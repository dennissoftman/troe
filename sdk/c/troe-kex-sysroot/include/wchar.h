#ifndef TROE_WCHAR_H
#define TROE_WCHAR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define WEOF ((wint_t)0xffffffffU)

typedef struct {
  uint32_t codepoint;
  uint8_t expected;
  uint8_t seen;
  uint8_t reserved[2];
} mbstate_t;

size_t mbrtowc(wchar_t *destination, const char *source, size_t length,
               mbstate_t *state);
size_t wcrtomb(char *destination, wchar_t character, mbstate_t *state);
int mbsinit(const mbstate_t *state);
size_t mbsrtowcs(wchar_t *destination, const char **source, size_t capacity,
                 mbstate_t *state);
size_t wcsrtombs(char *destination, const wchar_t **source, size_t capacity,
                 mbstate_t *state);
size_t wcslen(const wchar_t *text);
int wcscmp(const wchar_t *left, const wchar_t *right);
int wcsncmp(const wchar_t *left, const wchar_t *right, size_t size);
wchar_t *wcscpy(wchar_t *destination, const wchar_t *source);
wchar_t *wmemcpy(wchar_t *destination, const wchar_t *source, size_t size);
int wmemcmp(const wchar_t *left, const wchar_t *right, size_t size);
wchar_t *wmemchr(const wchar_t *text, wchar_t value, size_t size);

#endif
