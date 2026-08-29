#ifndef TROE_WCTYPE_H
#define TROE_WCTYPE_H

#include <wchar.h>

typedef unsigned long wctype_t;
int iswalnum(wint_t character);
int iswalpha(wint_t character);
int iswspace(wint_t character);
int iswdigit(wint_t character);
int iswlower(wint_t character);
int iswupper(wint_t character);
wint_t towlower(wint_t character);
wint_t towupper(wint_t character);

#endif
