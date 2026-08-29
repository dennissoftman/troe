#ifndef TROE_CPYTHON_WCHAR_OVERLAY_H
#define TROE_CPYTHON_WCHAR_OVERLAY_H
#include_next <wchar.h>
wchar_t *wcschr(const wchar_t *text, wchar_t value);
wchar_t *wcsrchr(const wchar_t *text, wchar_t value);
wchar_t *wcsncpy(wchar_t *destination, const wchar_t *source, size_t size);
long wcstol(const wchar_t *text, wchar_t **end, int base);
wchar_t *wcstok(wchar_t *text, const wchar_t *delimiters, wchar_t **context);
#endif
