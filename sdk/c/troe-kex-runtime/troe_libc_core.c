/* Minimal freestanding C compatibility core shared by KEX language runtimes. */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct TroeDecimalResult {
  int status;
  size_t consumed;
  double value;
} TroeDecimalResult;

extern TroeDecimalResult troe_parse_decimal(const uint8_t *bytes,
                                            size_t length);

int errno;

void *memcpy(void *destination, const void *source, size_t size) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (size_t index = 0; index < size; ++index)
    out[index] = in[index];
  return destination;
}

void *memmove(void *destination, const void *source, size_t size) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  if (out < in) {
    for (size_t index = 0; index < size; ++index)
      out[index] = in[index];
  } else if (out > in) {
    while (size != 0) {
      --size;
      out[size] = in[size];
    }
  }
  return destination;
}

void *memset(void *destination, int value, size_t size) {
  uint8_t *out = (uint8_t *)destination;
  for (size_t index = 0; index < size; ++index)
    out[index] = (uint8_t)value;
  return destination;
}

int memcmp(const void *left, const void *right, size_t size) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (size_t index = 0; index < size; ++index) {
    if (a[index] != b[index])
      return a[index] < b[index] ? -1 : 1;
  }
  return 0;
}

void *memchr(const void *bytes, int value, size_t size) {
  const uint8_t *cursor = (const uint8_t *)bytes;
  for (size_t index = 0; index < size; ++index) {
    if (cursor[index] == (uint8_t)value)
      return (void *)&cursor[index];
  }
  return NULL;
}

size_t strlen(const char *text) {
  size_t length = 0;
  while (text[length] != '\0')
    ++length;
  return length;
}

int strcmp(const char *left, const char *right) {
  while (*left != '\0' && *left == *right) {
    ++left;
    ++right;
  }
  return (uint8_t)*left < (uint8_t)*right
             ? -1
             : ((uint8_t)*left != (uint8_t)*right);
}

int strncmp(const char *left, const char *right, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    uint8_t a = (uint8_t)left[index];
    uint8_t b = (uint8_t)right[index];
    if (a != b)
      return a < b ? -1 : 1;
    if (a == 0)
      return 0;
  }
  return 0;
}

int strcoll(const char *left, const char *right) { return strcmp(left, right); }

char *strcpy(char *destination, const char *source) {
  char *result = destination;
  do {
    *destination++ = *source;
  } while (*source++ != '\0');
  return result;
}

char *strchr(const char *text, int value) {
  char wanted = (char)value;
  do {
    if (*text == wanted)
      return (char *)text;
  } while (*text++ != '\0');
  return NULL;
}

char *strpbrk(const char *text, const char *accepted) {
  for (; *text != '\0'; ++text) {
    if (strchr(accepted, *text) != NULL)
      return (char *)text;
  }
  return NULL;
}

size_t strspn(const char *text, const char *accepted) {
  size_t length = 0;
  while (text[length] != '\0' && strchr(accepted, text[length]) != NULL)
    ++length;
  return length;
}

char *strstr(const char *text, const char *needle) {
  size_t needle_length = strlen(needle);
  if (needle_length == 0)
    return (char *)text;
  for (; *text != '\0'; ++text) {
    if (strncmp(text, needle, needle_length) == 0)
      return (char *)text;
  }
  return NULL;
}

char *strerror(int error) {
  switch (error) {
  case EPERM: return "operation not permitted";
  case EIO: return "input/output error";
  case E2BIG: return "argument list too long";
  case ENOMEM: return "out of memory";
  case EBUSY: return "resource busy";
  case ENOTDIR: return "not a directory";
  case EFBIG: return "file too large";
  case ENOSYS: return "function not implemented";
  case EOVERFLOW: return "value too large";
  case ETIMEDOUT: return "operation timed out";
  case ECANCELED: return "operation canceled";
  case EDOM: return "numeric argument out of domain";
  case ERANGE: return "result out of range";
  case ENOENT: return "no such file or directory";
  case EACCES: return "permission denied";
  case EEXIST: return "file exists";
  case EXDEV: return "cross-device operation";
  case EISDIR: return "is a directory";
  case ENOSPC: return "no space left on device";
  case EROFS: return "read-only filesystem";
  case ENOTEMPTY: return "directory not empty";
  case ENOTSUP: return "operation not supported";
  case EINVAL: return "invalid argument";
  default: return "KEX service operation failed";
  }
}

struct lconv *localeconv(void) {
  static char point[] = ".";
  static char empty[] = "";
  static struct lconv locale = {
      .decimal_point = point,
      .thousands_sep = empty,
      .grouping = empty,
      .int_curr_symbol = empty,
      .currency_symbol = empty,
      .mon_decimal_point = empty,
      .mon_thousands_sep = empty,
      .mon_grouping = empty,
      .positive_sign = empty,
      .negative_sign = empty,
      .int_frac_digits = CHAR_MAX,
      .frac_digits = CHAR_MAX,
      .p_cs_precedes = CHAR_MAX,
      .p_sep_by_space = CHAR_MAX,
      .n_cs_precedes = CHAR_MAX,
      .n_sep_by_space = CHAR_MAX,
      .p_sign_posn = CHAR_MAX,
      .n_sign_posn = CHAR_MAX,
  };
  return &locale;
}

double strtod(const char *text, char **end) {
  TroeDecimalResult result =
      troe_parse_decimal((const uint8_t *)text, strlen(text));
  if (result.status != 0) {
    if (end != NULL)
      *end = (char *)text;
    return 0.0;
  }
  if (end != NULL)
    *end = (char *)text + result.consumed;
  return result.value;
}

typedef union TroeDoubleBits {
  double value;
  uint64_t bits;
} TroeDoubleBits;

#define TROE_UNARY_MATH(name)                                                \
  extern uint64_t troe_math_##name##_bits(uint64_t value);                  \
  double name(double value) {                                               \
    TroeDoubleBits input = {.value = value};                                \
    TroeDoubleBits output = {.bits = troe_math_##name##_bits(input.bits)};   \
    return output.value;                                                     \
  }

TROE_UNARY_MATH(acos)
TROE_UNARY_MATH(asin)
TROE_UNARY_MATH(atan)
TROE_UNARY_MATH(ceil)
TROE_UNARY_MATH(cos)
TROE_UNARY_MATH(exp)
TROE_UNARY_MATH(fabs)
TROE_UNARY_MATH(floor)
TROE_UNARY_MATH(log)
TROE_UNARY_MATH(log10)
TROE_UNARY_MATH(sin)
TROE_UNARY_MATH(sqrt)
TROE_UNARY_MATH(tan)

#define TROE_BINARY_MATH(name)                                               \
  extern uint64_t troe_math_##name##_bits(uint64_t left, uint64_t right);   \
  double name(double left, double right) {                                  \
    TroeDoubleBits left_bits = {.value = left};                             \
    TroeDoubleBits right_bits = {.value = right};                           \
    TroeDoubleBits output = {                                                \
        .bits = troe_math_##name##_bits(left_bits.bits, right_bits.bits)};   \
    return output.value;                                                     \
  }

TROE_BINARY_MATH(atan2)
TROE_BINARY_MATH(fmod)
TROE_BINARY_MATH(pow)

typedef struct TroeFrexpResult {
  uint64_t fraction_bits;
  int exponent;
} TroeFrexpResult;

extern TroeFrexpResult troe_math_frexp_bits(uint64_t value);
double frexp(double value, int *exponent) {
  TroeDoubleBits input = {.value = value};
  TroeFrexpResult result = troe_math_frexp_bits(input.bits);
  TroeDoubleBits output = {.bits = result.fraction_bits};
  if (exponent != NULL)
    *exponent = result.exponent;
  return output.value;
}

extern uint64_t troe_math_ldexp_bits(uint64_t value, int exponent);
double ldexp(double value, int exponent) {
  TroeDoubleBits input = {.value = value};
  TroeDoubleBits output = {
      .bits = troe_math_ldexp_bits(input.bits, exponent)};
  return output.value;
}

#include "troe_printf_double.h"

#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_SMALL_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_ALT_FORM_FLAG 1
#define NANOPRINTF_USE_FLOAT_SINGLE_PRECISION 0
#define NANOPRINTF_USE_FLOAT_HEX_FORMAT_SPECIFIER 0
#define NANOPRINTF_IMPLEMENTATION
#include "nanoprintf.h"

int vsnprintf(char *buffer, size_t size, const char *format,
              va_list arguments) {
  va_list copy;
  int handled;
  int result;
  va_copy(copy, arguments);
  result = troe_vsnprintf_double(buffer, size, format, copy, &handled);
  va_end(copy);
  if (handled)
    return result;
  return npf_vsnprintf(buffer, size, format, arguments);
}

int snprintf(char *buffer, size_t size, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = vsnprintf(buffer, size, format, arguments);
  va_end(arguments);
  return result;
}

int sprintf(char *buffer, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = vsnprintf(buffer, (size_t)-1, format, arguments);
  va_end(arguments);
  return result;
}
