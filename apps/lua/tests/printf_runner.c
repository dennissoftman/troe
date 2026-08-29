#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "troe_printf_double.h"

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
