#ifndef TROE_STDDEF_H
#define TROE_STDDEF_H

typedef __SIZE_TYPE__ size_t;
typedef __PTRDIFF_TYPE__ ptrdiff_t;
typedef __WCHAR_TYPE__ wchar_t;
typedef __WINT_TYPE__ wint_t;
typedef struct { long long __value; long double __align; } max_align_t;

#define NULL ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)

#endif
