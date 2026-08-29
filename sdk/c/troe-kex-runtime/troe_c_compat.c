/* Locale-independent freestanding C compatibility used by KEX runtimes. */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <troe/runtime.h>

size_t strnlen(const char *text, size_t maximum) {
  size_t length = 0;
  while (length < maximum && text[length] != '\0')
    ++length;
  return length;
}

size_t strxfrm(char *destination, const char *source, size_t capacity) {
  size_t length = strlen(source);
  if (capacity != 0) {
    size_t copied = length < capacity - 1 ? length : capacity - 1;
    memcpy(destination, source, copied);
    destination[copied] = '\0';
  }
  return length;
}

char *strncpy(char *destination, const char *source, size_t size) {
  size_t index = 0;
  while (index < size && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  while (index < size)
    destination[index++] = '\0';
  return destination;
}

char *strcat(char *destination, const char *source) {
  strcpy(destination + strlen(destination), source);
  return destination;
}

char *strncat(char *destination, const char *source, size_t size) {
  size_t offset = strlen(destination);
  size_t copied = strnlen(source, size);
  memcpy(destination + offset, source, copied);
  destination[offset + copied] = '\0';
  return destination;
}

char *strrchr(const char *text, int value) {
  const char *result = NULL;
  char wanted = (char)value;
  do {
    if (*text == wanted)
      result = text;
  } while (*text++ != '\0');
  return (char *)result;
}

size_t strcspn(const char *text, const char *rejected) {
  size_t length = 0;
  while (text[length] != '\0' && strchr(rejected, text[length]) == NULL)
    ++length;
  return length;
}

char *strtok_r(char *text, const char *separators, char **state) {
  char *start = text != NULL ? text : *state;
  if (start == NULL)
    return NULL;
  start += strspn(start, separators);
  if (*start == '\0') {
    *state = start;
    return NULL;
  }
  char *end = start + strcspn(start, separators);
  if (*end != '\0')
    *end++ = '\0';
  *state = end;
  return start;
}

char *strtok(char *text, const char *separators) {
  static char *state;
  return strtok_r(text, separators, &state);
}

int strerror_r(int error, char *destination, size_t capacity) {
  const char *message = strerror(error);
  size_t length = strlen(message);
  if (capacity == 0 || length >= capacity)
    return ERANGE;
  memcpy(destination, message, length + 1);
  return 0;
}

char *strdup(const char *text) {
  size_t length = strlen(text) + 1;
  char *copy = malloc(length);
  if (copy != NULL)
    memcpy(copy, text, length);
  return copy;
}

char *strndup(const char *text, size_t maximum) {
  size_t length = strnlen(text, maximum);
  char *copy = malloc(length + 1);
  if (copy != NULL) {
    memcpy(copy, text, length);
    copy[length] = '\0';
  }
  return copy;
}

int isblank(int character) { return character == ' ' || character == '\t'; }

char *setlocale(int category, const char *locale) {
  static char c_locale[] = "C";
  if (category < LC_ALL || category > LC_TIME) {
    errno = EINVAL;
    return NULL;
  }
  if (locale == NULL || locale[0] == '\0' || strcmp(locale, "C") == 0 ||
      strcmp(locale, "POSIX") == 0)
    return c_locale;
  errno = ENOENT;
  return NULL;
}

static int troe_digit_value(unsigned char character) {
  if (character >= '0' && character <= '9')
    return (int)(character - '0');
  if (character >= 'a' && character <= 'z')
    return (int)(character - 'a') + 10;
  if (character >= 'A' && character <= 'Z')
    return (int)(character - 'A') + 10;
  return -1;
}

static unsigned long long troe_strtoull(const char *text, char **end, int base,
                                        int *negative) {
  const char *cursor = text;
  unsigned long long value = 0;
  int any = 0;
  while (isspace((unsigned char)*cursor))
    ++cursor;
  *negative = 0;
  if (*cursor == '+' || *cursor == '-') {
    *negative = *cursor == '-';
    ++cursor;
  }
  if (base == 0) {
    if (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X')) {
      base = 16;
      cursor += 2;
    } else if (cursor[0] == '0') {
      base = 8;
    } else {
      base = 10;
    }
  } else if (base == 16 && cursor[0] == '0' &&
             (cursor[1] == 'x' || cursor[1] == 'X')) {
    cursor += 2;
  }
  if (base < 2 || base > 36) {
    errno = EINVAL;
    if (end != NULL)
      *end = (char *)text;
    return 0;
  }
  for (;;) {
    int digit = troe_digit_value((unsigned char)*cursor);
    if (digit < 0 || digit >= base)
      break;
    any = 1;
    if (value > (ULLONG_MAX - (unsigned int)digit) / (unsigned int)base) {
      value = ULLONG_MAX;
      errno = ERANGE;
      do {
        ++cursor;
        digit = troe_digit_value((unsigned char)*cursor);
      } while (digit >= 0 && digit < base);
      break;
    }
    value = value * (unsigned int)base + (unsigned int)digit;
    ++cursor;
  }
  if (end != NULL)
    *end = (char *)(any ? cursor : text);
  return value;
}

unsigned long long strtoull(const char *text, char **end, int base) {
  int negative;
  unsigned long long value = troe_strtoull(text, end, base, &negative);
  return negative ? 0ULL - value : value;
}

long long strtoll(const char *text, char **end, int base) {
  int negative;
  unsigned long long value = troe_strtoull(text, end, base, &negative);
  unsigned long long limit = negative ? (unsigned long long)LLONG_MAX + 1ULL
                                      : (unsigned long long)LLONG_MAX;
  if (value > limit) {
    errno = ERANGE;
    return negative ? LLONG_MIN : LLONG_MAX;
  }
  if (negative && value == (unsigned long long)LLONG_MAX + 1ULL)
    return LLONG_MIN;
  return negative ? -(long long)value : (long long)value;
}

unsigned long strtoul(const char *text, char **end, int base) {
  return (unsigned long)strtoull(text, end, base);
}

long strtol(const char *text, char **end, int base) {
  return (long)strtoll(text, end, base);
}

float strtof(const char *text, char **end) { return (float)strtod(text, end); }
int atoi(const char *text) { return (int)strtol(text, NULL, 10); }
long atol(const char *text) { return strtol(text, NULL, 10); }
long long atoll(const char *text) { return strtoll(text, NULL, 10); }
long labs(long value) { return value < 0 ? -value : value; }
long long llabs(long long value) { return value < 0 ? -value : value; }
div_t div(int numerator, int denominator) {
  div_t result = {numerator / denominator, numerator % denominator};
  return result;
}
ldiv_t ldiv(long numerator, long denominator) {
  ldiv_t result = {numerator / denominator, numerator % denominator};
  return result;
}
lldiv_t lldiv(long long numerator, long long denominator) {
  lldiv_t result = {numerator / denominator, numerator % denominator};
  return result;
}

void *bsearch(const void *key, const void *base, size_t count, size_t size,
              int (*compare)(const void *, const void *)) {
  size_t low = 0;
  size_t high = count;
  while (low < high) {
    size_t middle = low + (high - low) / 2;
    const unsigned char *item = (const unsigned char *)base + middle * size;
    int ordering = compare(key, item);
    if (ordering < 0)
      high = middle;
    else if (ordering > 0)
      low = middle + 1;
    else
      return (void *)item;
  }
  return NULL;
}

static void troe_swap(unsigned char *left, unsigned char *right, size_t size) {
  while (size-- != 0) {
    unsigned char byte = *left;
    *left++ = *right;
    *right++ = byte;
  }
}

void qsort(void *base, size_t count, size_t size,
           int (*compare)(const void *, const void *)) {
  unsigned char *bytes = base;
  if (size == 0)
    return;
  /* Insertion sort has constant auxiliary storage and deterministic bounds. */
  for (size_t index = 1; index < count; ++index) {
    size_t current = index;
    while (current != 0 &&
           compare(bytes + (current - 1) * size, bytes + current * size) > 0) {
      troe_swap(bytes + (current - 1) * size, bytes + current * size, size);
      --current;
    }
  }
}

enum TroeScanLength {
  TROE_SCAN_DEFAULT,
  TROE_SCAN_CHAR,
  TROE_SCAN_SHORT,
  TROE_SCAN_LONG,
  TROE_SCAN_LONG_LONG,
  TROE_SCAN_SIZE,
  TROE_SCAN_LONG_DOUBLE
};

#define TROE_SCAN_STORE_SIGNED(arguments, length, value)                       \
  do {                                                                         \
    if ((length) == TROE_SCAN_CHAR)                                            \
      *va_arg((arguments), signed char *) = (signed char)(value);              \
    else if ((length) == TROE_SCAN_SHORT)                                      \
      *va_arg((arguments), short *) = (short)(value);                          \
    else if ((length) == TROE_SCAN_LONG)                                       \
      *va_arg((arguments), long *) = (long)(value);                            \
    else if ((length) == TROE_SCAN_LONG_LONG)                                  \
      *va_arg((arguments), long long *) = (long long)(value);                  \
    else if ((length) == TROE_SCAN_SIZE)                                       \
      *va_arg((arguments), ssize_t *) = (ssize_t)(value);                      \
    else                                                                        \
      *va_arg((arguments), int *) = (int)(value);                              \
  } while (0)

#define TROE_SCAN_STORE_UNSIGNED(arguments, length, value)                     \
  do {                                                                         \
    if ((length) == TROE_SCAN_CHAR)                                            \
      *va_arg((arguments), unsigned char *) = (unsigned char)(value);          \
    else if ((length) == TROE_SCAN_SHORT)                                      \
      *va_arg((arguments), unsigned short *) = (unsigned short)(value);        \
    else if ((length) == TROE_SCAN_LONG)                                       \
      *va_arg((arguments), unsigned long *) = (unsigned long)(value);          \
    else if ((length) == TROE_SCAN_LONG_LONG)                                  \
      *va_arg((arguments), unsigned long long *) =                             \
          (unsigned long long)(value);                                         \
    else if ((length) == TROE_SCAN_SIZE)                                       \
      *va_arg((arguments), size_t *) = (size_t)(value);                        \
    else                                                                        \
      *va_arg((arguments), unsigned int *) = (unsigned int)(value);            \
  } while (0)

static const char *troe_scan_token(const char *source, size_t width,
                                   char token[128], char **end,
                                   int base, int is_signed,
                                   unsigned long long *unsigned_value,
                                   long long *signed_value) {
  if (width == 0 || width >= 128) {
    if (is_signed)
      *signed_value = strtoll(source, end, base);
    else
      *unsigned_value = strtoull(source, end, base);
    return source;
  }
  size_t copied = strnlen(source, width);
  memcpy(token, source, copied);
  token[copied] = '\0';
  char *token_end;
  if (is_signed)
    *signed_value = strtoll(token, &token_end, base);
  else
    *unsigned_value = strtoull(token, &token_end, base);
  *end = (char *)source + (token_end - token);
  return token;
}

int vsscanf(const char *source, const char *format, va_list arguments) {
  if (source == NULL || format == NULL) {
    errno = EINVAL;
    return EOF;
  }
  const char *cursor = source;
  const char *origin = source;
  int assigned = 0;
  while (*format != '\0') {
    if (isspace((unsigned char)*format)) {
      while (isspace((unsigned char)*format))
        ++format;
      while (isspace((unsigned char)*cursor))
        ++cursor;
      continue;
    }
    if (*format != '%') {
      if (*cursor != *format)
        break;
      ++cursor;
      ++format;
      continue;
    }
    ++format;
    if (*format == '%') {
      if (*cursor != '%')
        break;
      ++cursor;
      ++format;
      continue;
    }
    int suppress = 0;
    if (*format == '*') {
      suppress = 1;
      ++format;
    }
    size_t width = 0;
    while (isdigit((unsigned char)*format)) {
      if (width < 1000000U)
        width = width * 10U + (size_t)(*format - '0');
      ++format;
    }
    enum TroeScanLength length = TROE_SCAN_DEFAULT;
    if (*format == 'h') {
      ++format;
      length = *format == 'h' ? (++format, TROE_SCAN_CHAR) : TROE_SCAN_SHORT;
    } else if (*format == 'l') {
      ++format;
      length = *format == 'l' ? (++format, TROE_SCAN_LONG_LONG) : TROE_SCAN_LONG;
    } else if (*format == 'z') {
      ++format;
      length = TROE_SCAN_SIZE;
    } else if (*format == 'L') {
      ++format;
      length = TROE_SCAN_LONG_DOUBLE;
    }
    char conversion = *format++;
    if (conversion == 'n') {
      if (!suppress)
        TROE_SCAN_STORE_SIGNED(arguments, length, (long long)(cursor - origin));
      continue;
    }
    if (conversion != 'c') {
      while (isspace((unsigned char)*cursor))
        ++cursor;
    }
    if (*cursor == '\0')
      return assigned == 0 ? EOF : assigned;
    if (conversion == 'c') {
      size_t count = width == 0 ? 1 : width;
      if (strnlen(cursor, count) != count)
        return assigned == 0 ? EOF : assigned;
      if (!suppress) {
        char *destination = va_arg(arguments, char *);
        memcpy(destination, cursor, count);
        ++assigned;
      }
      cursor += count;
      continue;
    }
    if (conversion == 's') {
      size_t count = 0;
      size_t maximum = width == 0 ? SIZE_MAX : width;
      while (count < maximum && cursor[count] != '\0' &&
             !isspace((unsigned char)cursor[count]))
        ++count;
      if (count == 0)
        break;
      if (!suppress) {
        char *destination = va_arg(arguments, char *);
        memcpy(destination, cursor, count);
        destination[count] = '\0';
        ++assigned;
      }
      cursor += count;
      continue;
    }
    int base = conversion == 'o' ? 8 :
               (conversion == 'x' || conversion == 'X' || conversion == 'p') ? 16 :
               conversion == 'i' ? 0 : 10;
    int signed_conversion = conversion == 'd' || conversion == 'i';
    if (signed_conversion || conversion == 'u' || conversion == 'o' ||
        conversion == 'x' || conversion == 'X' || conversion == 'p') {
      char token[128];
      char *end;
      unsigned long long unsigned_value = 0;
      long long signed_value = 0;
      const char *parsed = troe_scan_token(cursor, width, token, &end, base,
                                           signed_conversion, &unsigned_value,
                                           &signed_value);
      if (end == parsed)
        break;
      if (!suppress) {
        if (conversion == 'p')
          *va_arg(arguments, void **) = (void *)(uintptr_t)unsigned_value;
        else if (signed_conversion)
          TROE_SCAN_STORE_SIGNED(arguments, length, signed_value);
        else
          TROE_SCAN_STORE_UNSIGNED(arguments, length, unsigned_value);
        ++assigned;
      }
      cursor = end;
      continue;
    }
    if (conversion == 'a' || conversion == 'A' || conversion == 'e' ||
        conversion == 'E' || conversion == 'f' || conversion == 'F' ||
        conversion == 'g' || conversion == 'G') {
      char token[128];
      const char *parsed = cursor;
      if (width != 0 && width < sizeof(token)) {
        size_t copied = strnlen(cursor, width);
        memcpy(token, cursor, copied);
        token[copied] = '\0';
        parsed = token;
      }
      char *end;
      double value = strtod(parsed, &end);
      if (end == parsed)
        break;
      cursor += end - parsed;
      if (!suppress) {
        if (length == TROE_SCAN_LONG_DOUBLE)
          *va_arg(arguments, long double *) = (long double)value;
        else if (length == TROE_SCAN_LONG)
          *va_arg(arguments, double *) = value;
        else
          *va_arg(arguments, float *) = (float)value;
        ++assigned;
      }
      continue;
    }
    errno = ENOTSUP;
    return assigned == 0 ? EOF : assigned;
  }
  return assigned;
}

int sscanf(const char *source, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = vsscanf(source, format, arguments);
  va_end(arguments);
  return result;
}

size_t wcslen(const wchar_t *text) {
  size_t length = 0;
  while (text[length] != 0)
    ++length;
  return length;
}

int wcscmp(const wchar_t *left, const wchar_t *right) {
  while (*left != 0 && *left == *right) {
    ++left;
    ++right;
  }
  return *left < *right ? -1 : (*left != *right);
}

int wcsncmp(const wchar_t *left, const wchar_t *right, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (left[index] != right[index])
      return left[index] < right[index] ? -1 : 1;
    if (left[index] == 0)
      return 0;
  }
  return 0;
}

wchar_t *wcscpy(wchar_t *destination, const wchar_t *source) {
  wchar_t *result = destination;
  do {
    *destination++ = *source;
  } while (*source++ != 0);
  return result;
}

wchar_t *wmemcpy(wchar_t *destination, const wchar_t *source, size_t size) {
  for (size_t index = 0; index < size; ++index)
    destination[index] = source[index];
  return destination;
}

int wmemcmp(const wchar_t *left, const wchar_t *right, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (left[index] != right[index])
      return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

wchar_t *wmemchr(const wchar_t *text, wchar_t value, size_t size) {
  for (size_t index = 0; index < size; ++index) {
    if (text[index] == value)
      return (wchar_t *)&text[index];
  }
  return NULL;
}

int mbsinit(const mbstate_t *state) {
  return state == NULL || (state->expected == 0 && state->seen == 0);
}

size_t mbrtowc(wchar_t *destination, const char *source, size_t length,
               mbstate_t *state) {
  static mbstate_t internal;
  mbstate_t *active = state != NULL ? state : &internal;
  uint32_t codepoint = active->codepoint;
  unsigned int expected = active->expected;
  unsigned int seen = active->seen;
  if (source == NULL) {
    memset(active, 0, sizeof(*active));
    return 0;
  }
  if (length == 0)
    return (size_t)-2;
  size_t consumed = 0;
  if (expected == 0) {
    unsigned char first = (unsigned char)source[consumed++];
    if (first == 0) {
      if (destination != NULL)
        *destination = 0;
      return 0;
    }
    if (first < 0x80) {
      if (destination != NULL)
        *destination = (wchar_t)first;
      return 1;
    }
    if (first >= 0xc2 && first <= 0xdf) {
      codepoint = first & 0x1fU;
      expected = 2;
    } else if (first >= 0xe0 && first <= 0xef) {
      codepoint = first & 0x0fU;
      expected = 3;
    } else if (first >= 0xf0 && first <= 0xf4) {
      codepoint = first & 0x07U;
      expected = 4;
    } else {
      errno = EILSEQ;
      memset(active, 0, sizeof(*active));
      return (size_t)-1;
    }
    seen = 1;
  }
  while (seen < expected && consumed < length) {
    unsigned char continuation = (unsigned char)source[consumed];
    if ((continuation & 0xc0U) != 0x80U) {
      errno = EILSEQ;
      memset(active, 0, sizeof(*active));
      return (size_t)-1;
    }
    codepoint = (codepoint << 6) | (continuation & 0x3fU);
    ++seen;
    ++consumed;
  }
  if (seen < expected) {
    active->codepoint = codepoint;
    active->expected = (uint8_t)expected;
    active->seen = (uint8_t)seen;
    return (size_t)-2;
  }
  uint32_t minimum = expected == 2 ? 0x80U : expected == 3 ? 0x800U : 0x10000U;
  memset(active, 0, sizeof(*active));
  if (codepoint < minimum || codepoint > 0x10ffffU ||
      (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
    errno = EILSEQ;
    return (size_t)-1;
  }
  if (destination != NULL)
    *destination = (wchar_t)codepoint;
  return consumed;
}

size_t wcrtomb(char *destination, wchar_t character, mbstate_t *state) {
  uint32_t codepoint = (uint32_t)character;
  if (state != NULL)
    memset(state, 0, sizeof(*state));
  if (destination == NULL)
    return 1;
  if (codepoint <= 0x7fU) {
    destination[0] = (char)codepoint;
    return 1;
  }
  if (codepoint <= 0x7ffU) {
    destination[0] = (char)(0xc0U | (codepoint >> 6));
    destination[1] = (char)(0x80U | (codepoint & 0x3fU));
    return 2;
  }
  if (codepoint >= 0xd800U && codepoint <= 0xdfffU) {
    errno = EILSEQ;
    return (size_t)-1;
  }
  if (codepoint <= 0xffffU) {
    destination[0] = (char)(0xe0U | (codepoint >> 12));
    destination[1] = (char)(0x80U | ((codepoint >> 6) & 0x3fU));
    destination[2] = (char)(0x80U | (codepoint & 0x3fU));
    return 3;
  }
  if (codepoint <= 0x10ffffU) {
    destination[0] = (char)(0xf0U | (codepoint >> 18));
    destination[1] = (char)(0x80U | ((codepoint >> 12) & 0x3fU));
    destination[2] = (char)(0x80U | ((codepoint >> 6) & 0x3fU));
    destination[3] = (char)(0x80U | (codepoint & 0x3fU));
    return 4;
  }
  errno = EILSEQ;
  return (size_t)-1;
}

size_t mbsrtowcs(wchar_t *destination, const char **source, size_t capacity,
                 mbstate_t *state) {
  const char *cursor = *source;
  size_t output = 0;
  while (*cursor != '\0') {
    wchar_t character;
    size_t count = mbrtowc(&character, cursor, 4, state);
    if (count == (size_t)-1 || count == (size_t)-2)
      return (size_t)-1;
    if (destination != NULL) {
      if (output == capacity) {
        *source = cursor;
        return output;
      }
      destination[output] = character;
    }
    ++output;
    cursor += count;
  }
  if (destination != NULL && output < capacity)
    destination[output] = 0;
  *source = NULL;
  return output;
}

size_t wcsrtombs(char *destination, const wchar_t **source, size_t capacity,
                 mbstate_t *state) {
  const wchar_t *cursor = *source;
  size_t output = 0;
  while (*cursor != 0) {
    char encoded[4];
    size_t count = wcrtomb(encoded, *cursor, state);
    if (count == (size_t)-1)
      return (size_t)-1;
    if (destination != NULL) {
      if (count > capacity - output) {
        *source = cursor;
        return output;
      }
      memcpy(destination + output, encoded, count);
    }
    output += count;
    ++cursor;
  }
  if (destination != NULL && output < capacity)
    destination[output] = '\0';
  *source = NULL;
  return output;
}

size_t mbstowcs(wchar_t *destination, const char *source, size_t capacity) {
  mbstate_t state = {0};
  return mbsrtowcs(destination, &source, capacity, &state);
}

size_t wcstombs(char *destination, const wchar_t *source, size_t capacity) {
  mbstate_t state = {0};
  return wcsrtombs(destination, &source, capacity, &state);
}

int iswalnum(wint_t character) { return character >= 0 && character <= 0x7f && isalnum(character); }
int iswalpha(wint_t character) { return character >= 0 && character <= 0x7f && isalpha(character); }
int iswspace(wint_t character) { return character >= 0 && character <= 0x7f && isspace(character); }
int iswdigit(wint_t character) { return character >= 0 && character <= 0x7f && isdigit(character); }
int iswlower(wint_t character) { return character >= 0 && character <= 0x7f && islower(character); }
int iswupper(wint_t character) { return character >= 0 && character <= 0x7f && isupper(character); }
wint_t towlower(wint_t character) {
  return character >= 0 && character <= 0x7f ? (wint_t)tolower(character) : character;
}
wint_t towupper(wint_t character) {
  return character >= 0 && character <= 0x7f ? (wint_t)toupper(character) : character;
}

static void (*troe_signal_handlers[32])(int);

void (*signal(int signal_number, void (*handler)(int)))(int) {
  if (signal_number <= 0 || signal_number >= 32) {
    errno = EINVAL;
    return SIG_ERR;
  }
  void (*previous)(int) = troe_signal_handlers[signal_number];
  troe_signal_handlers[signal_number] = handler;
  return previous;
}

int raise(int signal_number) {
  if (signal_number <= 0 || signal_number >= 32) {
    errno = EINVAL;
    return -1;
  }
  void (*handler)(int) = troe_signal_handlers[signal_number];
  if (handler == SIG_IGN)
    return 0;
  if (handler != SIG_DFL && handler != NULL)
    handler(signal_number);
  errno = ENOTSUP;
  return -1;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                   void *(*entry)(void *), void *argument) {
  (void)thread;
  (void)attributes;
  (void)entry;
  (void)argument;
  return ENOTSUP;
}
int pthread_join(pthread_t thread, void **result) {
  (void)thread;
  (void)result;
  return ENOTSUP;
}
int pthread_detach(pthread_t thread) {
  (void)thread;
  return ENOTSUP;
}
pthread_t pthread_self(void) { return (pthread_t)1; }
int pthread_equal(pthread_t left, pthread_t right) { return left == right; }
int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *attributes) {
  (void)attributes;
  if (mutex == NULL)
    return EINVAL;
  mutex->state = 0;
  return 0;
}
int pthread_mutex_destroy(pthread_mutex_t *mutex) {
  if (mutex == NULL || mutex->state != 0)
    return EBUSY;
  return 0;
}
int pthread_mutex_lock(pthread_mutex_t *mutex) {
  if (mutex == NULL)
    return EINVAL;
  if (mutex->state != 0)
    return EDEADLK;
  mutex->state = 1;
  return 0;
}
int pthread_mutex_trylock(pthread_mutex_t *mutex) {
  if (mutex == NULL)
    return EINVAL;
  if (mutex->state != 0)
    return EBUSY;
  mutex->state = 1;
  return 0;
}
int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  if (mutex == NULL || mutex->state == 0)
    return EPERM;
  mutex->state = 0;
  return 0;
}
int pthread_cond_init(pthread_cond_t *condition, const void *attributes) {
  (void)attributes;
  if (condition == NULL)
    return EINVAL;
  condition->state = 0;
  return 0;
}
int pthread_cond_destroy(pthread_cond_t *condition) {
  return condition == NULL ? EINVAL : 0;
}
int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex) {
  (void)condition;
  (void)mutex;
  return ENOTSUP;
}
int pthread_cond_signal(pthread_cond_t *condition) {
  return condition == NULL ? EINVAL : 0;
}
int pthread_cond_broadcast(pthread_cond_t *condition) {
  return condition == NULL ? EINVAL : 0;
}
int pthread_once(pthread_once_t *once, void (*initializer)(void)) {
  if (once == NULL || initializer == NULL)
    return EINVAL;
  if (once->state == 0) {
    once->state = 1;
    initializer();
    once->state = 2;
  }
  return once->state == 2 ? 0 : EDEADLK;
}

struct TroeTssSlot {
  int allocated;
  void *value;
  void (*destructor)(void *);
};
static struct TroeTssSlot troe_tss[TROE_C_MAX_TSS_KEYS];

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
  if (key == NULL)
    return EINVAL;
  for (unsigned int index = 0; index < TROE_C_MAX_TSS_KEYS; ++index) {
    if (!troe_tss[index].allocated) {
      troe_tss[index].allocated = 1;
      troe_tss[index].value = NULL;
      troe_tss[index].destructor = destructor;
      *key = index;
      return 0;
    }
  }
  return EAGAIN;
}
int pthread_key_delete(pthread_key_t key) {
  if (key >= TROE_C_MAX_TSS_KEYS || !troe_tss[key].allocated)
    return EINVAL;
  memset(&troe_tss[key], 0, sizeof(troe_tss[key]));
  return 0;
}
int pthread_setspecific(pthread_key_t key, const void *value) {
  if (key >= TROE_C_MAX_TSS_KEYS || !troe_tss[key].allocated)
    return EINVAL;
  troe_tss[key].value = (void *)value;
  return 0;
}
void *pthread_getspecific(pthread_key_t key) {
  if (key >= TROE_C_MAX_TSS_KEYS || !troe_tss[key].allocated)
    return NULL;
  return troe_tss[key].value;
}

void troe_runtime_run_tss_destructors(void) {
  for (unsigned int pass = 0; pass < 4; ++pass) {
    int invoked = 0;
    for (unsigned int index = 0; index < TROE_C_MAX_TSS_KEYS; ++index) {
      if (troe_tss[index].allocated && troe_tss[index].value != NULL &&
          troe_tss[index].destructor != NULL) {
        void *value = troe_tss[index].value;
        troe_tss[index].value = NULL;
        troe_tss[index].destructor(value);
        invoked = 1;
      }
    }
    if (!invoked)
      break;
  }
  memset(troe_tss, 0, sizeof(troe_tss));
}
