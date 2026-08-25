#ifndef TROE_LOCALE_H
#define TROE_LOCALE_H

struct lconv {
  char *decimal_point;
};

struct lconv *localeconv(void);

#endif
