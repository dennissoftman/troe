#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "troe_printf_double.h"

/* Whether the host's own `%#g` result dropped the trailing zeros that `#`
   requires it to keep.

   C says a `g` conversion removes trailing zeros "unless the `#` flag is
   used". For 999999.5 at precision 6 the rounded exponent is 6, so `P > X` is
   false and the style is `e` with precision 5: `1.00000e+06`. glibc renders
   `1.e+06`, keeping the decimal point that `#` demands while removing the
   digits that `#` equally demands. A decimal point with nothing between it and
   the exponent is exactly that shape.

   Where the host is non-conforming it stops being the oracle, and the standard
   takes over: the rule is checked directly rather than the case being skipped,
   so glibc keeps the coverage instead of losing it. */
static int host_dropped_alternate_zeros(const char *text) {
  const char *point = strchr(text, '.');
  if (point == NULL)
    return 0;
  return point[1] == '\0' || point[1] == 'e' || point[1] == 'E';
}

/* Significant digits in one formatted mantissa, or -1 if it is not a number.
   Leading zeros are not significant, so `0.00100000` and `1.00000e+06` both
   carry six. The exponent is not part of the mantissa. */
static int significant_digits(const char *text) {
  const char *cursor = text;
  int count = 0;
  int started = 0;
  /* A width can pad either side, so the mantissa need not start or end the
     text. */
  while (*cursor == ' ')
    cursor++;
  if (*cursor == '-' || *cursor == '+')
    cursor++;
  for (; *cursor != '\0' && *cursor != 'e' && *cursor != 'E' && *cursor != ' ';
       cursor++) {
    if (*cursor == '.')
      continue;
    if (*cursor < '0' || *cursor > '9')
      return -1;
    if (!started && *cursor == '0')
      continue;
    started = 1;
    count++;
  }
  return count;
}

/* Whether `format`'s single conversion asks for the alternate form of `g`, and
   what precision it names. Both scan from the last `%` so literal text in a
   template cannot be mistaken for part of the specifier. An unrecognised shape
   reports no precision, which leaves the disagreement to be reported plainly
   rather than reinterpreted. */
static int format_requests_alternate_g(const char *format) {
  const char *percent = strrchr(format, '%');
  size_t length = strlen(format);
  if (percent == NULL || strchr(percent, '#') == NULL || length == 0)
    return 0;
  return format[length - 1] == 'g' || format[length - 1] == 'G';
}

static int format_precision(const char *format) {
  const char *percent = strrchr(format, '%');
  const char *point;
  int precision = 0;
  if (percent == NULL)
    return -1;
  point = strchr(percent, '.');
  if (point == NULL)
    return -1;
  for (point++; *point >= '0' && *point <= '9'; point++)
    precision = precision * 10 + (*point - '0');
  return precision;
}

static int compare(double value, char conversion, int precision,
                   int alternate) {
  char expected[TROE_DOUBLE_TEXT_BYTES];
  char actual[TROE_DOUBLE_TEXT_BYTES];
  char format[16];
  int expected_length;
  int actual_length;
  (void)snprintf(format, sizeof(format), alternate ? "%%#.%d%c" : "%%.%d%c",
                 precision, conversion);
  expected_length = snprintf(expected, sizeof(expected), format, value);
  actual_length = troe_format_double_payload(actual, value, conversion,
                                             precision, alternate);
  if (actual_length >= 0 && (size_t)actual_length < sizeof(actual))
    actual[actual_length] = '\0';
  if (expected_length != actual_length || actual_length < 0 ||
      memcmp(expected, actual, (size_t)expected_length + 1) != 0) {
    /* Only a disagreement raises the question of which side is right, and only
       then is the host's conformance worth testing. While the two agree the
       host stays the oracle, which keeps `%#.0g` of zero -- legitimately `0.`
       on both -- out of this branch entirely. */
    if (alternate && (conversion == 'g' || conversion == 'G') &&
        host_dropped_alternate_zeros(expected)) {
      /* `#` keeps the trailing zeros, so a `g` result carries exactly
         `precision` significant digits, and a precision of zero means one. */
      int wanted = precision == 0 ? 1 : precision;
      int digits = actual_length < 0 ? -1 : significant_digits(actual);
      if (digits == wanted && strchr(actual, '.') != NULL)
        return 0;
      fprintf(stderr,
              "alternate-form mismatch value=%a conversion=%c precision=%d "
              "expected %d significant digits and a decimal point, got %s "
              "with %d (host is non-conforming here and rendered %s)\n",
              value, conversion, precision, wanted,
              actual_length < 0 ? "(failure)" : actual, digits, expected);
      return 1;
    }
    fprintf(stderr,
            "format mismatch value=%a conversion=%c precision=%d alternate=%d "
            "expected=%s actual=%s\n",
            value, conversion, precision, alternate, expected,
            actual_length < 0 ? "(failure)" : actual);
    return 1;
  }
  return 0;
}

static int troe_test_snprintf(char *destination, size_t capacity,
                              const char *format, ...) {
  va_list arguments;
  int handled;
  int result;
  va_start(arguments, format);
  result = troe_vsnprintf_double(destination, capacity, format, arguments,
                                &handled);
  va_end(arguments);
  return handled ? result : -1;
}

static int compare_complete(double value, const char *format) {
  char expected[TROE_DOUBLE_TEXT_BYTES];
  char actual[TROE_DOUBLE_TEXT_BYTES];
  int expected_length = snprintf(expected, sizeof(expected), format, value);
  int actual_length =
      troe_test_snprintf(actual, sizeof(actual), format, value);
  if (expected_length != actual_length || actual_length < 0 ||
      memcmp(expected, actual, (size_t)expected_length + 1) != 0) {
    /* Same alternate-form divergence as in `compare`, reached through a whole
       format rather than one conversion: `%-#18.4g` of 9999.5 is `1.000e+04`
       and glibc renders `1.e+04`. Only a disagreement asks the question, and
       only a host that dropped the zeros `#` requires forfeits it. */
    int precision = format_precision(format);
    if (format_requests_alternate_g(format) && precision >= 0 &&
        host_dropped_alternate_zeros(expected)) {
      int wanted = precision == 0 ? 1 : precision;
      int digits = actual_length < 0 ? -1 : significant_digits(actual);
      if (digits == wanted && strchr(actual, '.') != NULL)
        return 0;
      fprintf(stderr,
              "complete alternate-form mismatch value=%a format=%s expected %d "
              "significant digits and a decimal point, got %s with %d (host is "
              "non-conforming here and rendered %s)\n",
              value, format, wanted,
              actual_length < 0 ? "(failure)" : actual, digits, expected);
      return 1;
    }
    fprintf(stderr,
            "complete format mismatch value=%a format=%s expected=%s actual=%s\n",
            value, format, expected, actual_length < 0 ? "(failure)" : actual);
    return 1;
  }
  return 0;
}

int main(void) {
  static const double values[] = {
      0.0,
      0x1p-1074,
      DBL_MIN,
      0.00009999999999999999,
      0.0001,
      0.1,
      0.5,
      1.0,
      1.2345678901234567,
      9.9995,
      999999.5,
      1e20,
      DBL_MAX,
      INFINITY,
      NAN,
  };
  static const int precisions[] = {0, 1, 2, 6, 15, 17, 99};
  static const char conversions[] = {'f', 'e', 'g', 'E', 'G'};
  uint64_t random_bits = UINT64_C(0x6a09e667f3bcc909);
  for (size_t value = 0; value < sizeof(values) / sizeof(values[0]); ++value) {
    for (size_t conversion = 0;
         conversion < sizeof(conversions) / sizeof(conversions[0]);
         ++conversion) {
      for (size_t precision = 0;
           precision < sizeof(precisions) / sizeof(precisions[0]); ++precision) {
        if (compare(values[value], conversions[conversion],
                    precisions[precision], 0) != 0 ||
            compare(values[value], conversions[conversion],
                    precisions[precision], 1) != 0)
          return 1;
      }
    }
  }
  for (size_t sample = 0; sample < 512; ++sample) {
    random_bits ^= random_bits << 13;
    random_bits ^= random_bits >> 7;
    random_bits ^= random_bits << 17;
    TroePrintfDoubleBits generated = {
        .bits = random_bits & UINT64_C(0x7fffffffffffffff)};
    if (((generated.bits >> 52) & 0x7ffu) == 0x7ffu)
      generated.bits ^= UINT64_C(1) << 52;
    for (size_t conversion = 0;
         conversion < sizeof(conversions) / sizeof(conversions[0]);
         ++conversion) {
      for (size_t precision = 0; precision < 5; ++precision) {
        if (compare(generated.value, conversions[conversion],
                    precisions[precision], 0) != 0 ||
            compare(generated.value, conversions[conversion],
                    precisions[precision], 1) != 0)
          return 1;
      }
    }
  }
  if (compare_complete(-1.2345678901234567, "%+020.10e") != 0 ||
      compare_complete(9999.5, "%-#18.4g") != 0 ||
      compare_complete(0.0, "%.15gx0p+0") != 0 ||
      compare_complete(DBL_MAX, "value=%.17g") != 0 ||
      compare_complete(2.675, "%.2f") != 0 ||
      compare_complete(INFINITY, "%010f") != 0 ||
      compare_complete(-0.0, "%+08.2f") != 0)
    return 1;
  puts("troe-printf-double ok");
  return 0;
}
