#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <setjmp.h>
#include <ctype.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(TROE_LUA_HOST_TEST) && defined(__aarch64__)
__asm__(".text\n"
        ".global troe_setjmp\n"
        ".type troe_setjmp, %function\n"
        "troe_setjmp:\n"
        "stp x19, x20, [x0, #0]\n"
        "stp x21, x22, [x0, #16]\n"
        "stp x23, x24, [x0, #32]\n"
        "stp x25, x26, [x0, #48]\n"
        "stp x27, x28, [x0, #64]\n"
        "stp x29, x30, [x0, #80]\n"
        "mov x1, sp\n"
        "str x1, [x0, #96]\n"
        "stp d8, d9, [x0, #104]\n"
        "stp d10, d11, [x0, #120]\n"
        "stp d12, d13, [x0, #136]\n"
        "stp d14, d15, [x0, #152]\n"
        "mov w0, wzr\n"
        "ret\n"
        ".size troe_setjmp, .-troe_setjmp\n"
        ".global troe_longjmp\n"
        ".type troe_longjmp, %function\n"
        "troe_longjmp:\n"
        "ldp x19, x20, [x0, #0]\n"
        "ldp x21, x22, [x0, #16]\n"
        "ldp x23, x24, [x0, #32]\n"
        "ldp x25, x26, [x0, #48]\n"
        "ldp x27, x28, [x0, #64]\n"
        "ldr x2, [x0, #96]\n"
        "mov sp, x2\n"
        "ldp d8, d9, [x0, #104]\n"
        "ldp d10, d11, [x0, #120]\n"
        "ldp d12, d13, [x0, #136]\n"
        "ldp d14, d15, [x0, #152]\n"
        "cmp w1, #0\n"
        "csinc w1, w1, wzr, ne\n"
        "ldp x29, x30, [x0, #80]\n"
        "mov w0, w1\n"
        "ret\n"
        ".size troe_longjmp, .-troe_longjmp\n");
#endif

typedef struct TroeLuaHost TroeLuaHost;

typedef void *(*TroeAllocate)(void *context, void *pointer, size_t old_size,
                              size_t new_size);
typedef intptr_t (*TroeRead)(void *context, uint8_t *destination,
                             size_t capacity);
typedef int (*TroeWrite)(void *context, int stream, const uint8_t *bytes,
                         size_t length);
typedef int (*TroeProcessCpuTime)(void *context, uint64_t *ticks,
                                  uint64_t *frequency_hz);
typedef int (*TroeWallTime)(void *context, uint64_t *seconds);
typedef intptr_t (*TroeReadInput)(void *context, uint8_t *destination,
                                  size_t capacity);
typedef int (*TroeFileOpen)(void *context, const uint8_t *path,
                            size_t path_length, uint32_t *token,
                            uint64_t *length);
typedef intptr_t (*TroeFileRead)(void *context, uint32_t token,
                                 uint64_t length, uint64_t offset,
                                 uint8_t *destination, size_t capacity);
typedef int (*TroeFileClose)(void *context, uint32_t token, uint64_t length);
typedef int (*TroeFileReplace)(void *context, const uint8_t *path,
                               size_t path_length, const uint8_t *bytes,
                               size_t length);
typedef int (*TroeFilePathOperation)(void *context, const uint8_t *path,
                                     size_t path_length);
typedef int (*TroeFileRename)(void *context, const uint8_t *old_path,
                              size_t old_path_length, const uint8_t *new_path,
                              size_t new_path_length);

struct TroeLuaHost {
  void *context;
  TroeAllocate allocate;
  TroeRead read;
  TroeWrite write;
  TroeProcessCpuTime process_cpu_time;
  TroeWallTime wall_time;
  TroeReadInput read_input;
  TroeFileOpen file_open;
  TroeFileRead file_read;
  TroeFileClose file_close;
  TroeFileReplace file_replace;
  TroeFilePathOperation file_remove;
  TroeFileRename file_rename;
  int file_mutation_available;
};

typedef struct TroeLuaArgument {
  const uint8_t *bytes;
  size_t length;
} TroeLuaArgument;

typedef struct TroeLuaAction {
  int kind;
  const uint8_t *bytes;
  size_t length;
} TroeLuaAction;

typedef struct TroeLuaConfiguration {
  TroeLuaHost *host;
  const uint8_t *source_name;
  size_t source_name_length;
  const TroeLuaArgument *arguments;
  size_t argument_count;
  const TroeLuaAction *actions;
  size_t action_count;
  int has_source;
  int warnings_enabled;
  int ignore_environment;
  const uint8_t *current_directory;
  size_t current_directory_length;
  int requested_exit;
  uint32_t requested_exit_status;
  int requested_exit_close;
} TroeLuaConfiguration;

static TroeLuaHost *troe_active_host;
static TroeLuaConfiguration *troe_active_configuration;
static int troe_output_failed;
static jmp_buf troe_unclosed_exit_jump;
static int troe_exit_jump_active;

#if !defined(TROE_LUA_HOST_TEST)
extern int troe_parse_decimal(const uint8_t *bytes, size_t length,
                              double *result);

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
  case EDOM:
    return "numeric argument out of domain";
  case ERANGE:
    return "result out of range";
  case EINVAL:
    return "invalid argument or filesystem operation";
  default:
    return "KEX service operation failed";
  }
}

static int troe_ascii(unsigned value) { return value <= 0x7f ? (int)value : -1; }

int isdigit(int value) {
  value = troe_ascii((unsigned)value);
  return value >= '0' && value <= '9';
}
int islower(int value) {
  value = troe_ascii((unsigned)value);
  return value >= 'a' && value <= 'z';
}
int isupper(int value) {
  value = troe_ascii((unsigned)value);
  return value >= 'A' && value <= 'Z';
}
int isalpha(int value) { return islower(value) || isupper(value); }
int isalnum(int value) { return isalpha(value) || isdigit(value); }
int iscntrl(int value) {
  value = troe_ascii((unsigned)value);
  return value >= 0 && (value < 0x20 || value == 0x7f);
}
int isprint(int value) {
  value = troe_ascii((unsigned)value);
  return value >= 0x20 && value <= 0x7e;
}
int isgraph(int value) { return isprint(value) && value != ' '; }
int isspace(int value) {
  return value == ' ' || value == '\t' || value == '\n' || value == '\r' ||
         value == '\f' || value == '\v';
}
int isxdigit(int value) {
  return isdigit(value) || (value >= 'a' && value <= 'f') ||
         (value >= 'A' && value <= 'F');
}
int ispunct(int value) { return isgraph(value) && !isalnum(value); }
int tolower(int value) { return isupper(value) ? value + ('a' - 'A') : value; }
int toupper(int value) { return islower(value) ? value - ('a' - 'A') : value; }

int abs(int value) { return value < 0 ? -value : value; }

void abort(void) {
  __builtin_trap();
  __builtin_unreachable();
}

void exit(int status) {
  (void)status;
  abort();
}

void *malloc(size_t size) {
  (void)size;
  return NULL;
}
void *realloc(void *pointer, size_t size) {
  (void)pointer;
  (void)size;
  return NULL;
}
void free(void *pointer) { (void)pointer; }
char *getenv(const char *name) {
  (void)name;
  return NULL;
}

struct lconv *localeconv(void) {
  static char point[] = ".";
  static struct lconv locale = {point};
  return &locale;
}

time_t time(time_t *destination) {
  if (destination != NULL)
    *destination = 0;
  return 0;
}

double strtod(const char *text, char **end) {
  const char *start = text;
  const char *cursor;
  const char *exponent;
  int digits = 0;
  double result = 0.0;
  while (isspace(*start))
    ++start;
  cursor = start;
  if (*cursor == '+' || *cursor == '-')
    ++cursor;
  while (isdigit(*cursor)) {
    ++digits;
    ++cursor;
  }
  if (*cursor == '.') {
    ++cursor;
    while (isdigit(*cursor)) {
      ++digits;
      ++cursor;
    }
  }
  if (digits == 0) {
    if (end != NULL)
      *end = (char *)text;
    return 0.0;
  }
  exponent = cursor;
  if (*cursor == 'e' || *cursor == 'E') {
    const char *exponent_digits;
    ++cursor;
    if (*cursor == '+' || *cursor == '-')
      ++cursor;
    exponent_digits = cursor;
    while (isdigit(*cursor))
      ++cursor;
    if (cursor == exponent_digits)
      cursor = exponent;
  }
  if (troe_parse_decimal((const uint8_t *)start, (size_t)(cursor - start),
                         &result) != 0) {
    if (end != NULL)
      *end = (char *)text;
    return 0.0;
  }
  if (end != NULL)
    *end = (char *)cursor;
  return result;
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

extern uint64_t troe_math_frexp_bits(uint64_t value, int *exponent);
double frexp(double value, int *exponent) {
  TroeDoubleBits input = {.value = value};
  TroeDoubleBits output = {
      .bits = troe_math_frexp_bits(input.bits, exponent)};
  return output.value;
}

extern uint64_t troe_math_ldexp_bits(uint64_t value, int exponent);
double ldexp(double value, int exponent) {
  TroeDoubleBits input = {.value = value};
  TroeDoubleBits output = {
      .bits = troe_math_ldexp_bits(input.bits, exponent)};
  return output.value;
}

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
  return npf_vsnprintf(buffer, size, format, arguments);
}

int snprintf(char *buffer, size_t size, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = npf_vsnprintf(buffer, size, format, arguments);
  va_end(arguments);
  return result;
}

int sprintf(char *buffer, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = npf_vsnprintf(buffer, (size_t)-1, format, arguments);
  va_end(arguments);
  return result;
}

enum {
  TROE_FILE_REGULAR = 0,
  TROE_FILE_STDIN = 1,
  TROE_FILE_STDOUT = 2,
  TROE_FILE_STDERR = 3,
  TROE_FILE_MEMORY = 4
};

struct TroeFile {
  int kind;
  uint32_t token;
  uint64_t source_length;
  uint64_t position;
  uint8_t *buffer;
  size_t length;
  size_t capacity;
  char *path;
  size_t path_length;
  int readable;
  int writable;
  int append;
  int dirty;
  int eof;
  int error;
  int ungot;
};

static struct TroeFile troe_stdin_file = {
    .kind = TROE_FILE_STDIN, .readable = 1, .ungot = EOF};
static struct TroeFile troe_stdout_file = {
    .kind = TROE_FILE_STDOUT, .writable = 1, .ungot = EOF};
static struct TroeFile troe_stderr_file = {
    .kind = TROE_FILE_STDERR, .writable = 1, .ungot = EOF};
FILE *stdin = &troe_stdin_file;
FILE *stdout = &troe_stdout_file;
FILE *stderr = &troe_stderr_file;

static void *troe_file_resize(void *pointer, size_t old_size,
                              size_t new_size) {
  if (troe_active_host == NULL)
    return NULL;
  return troe_active_host->allocate(troe_active_host->context, pointer,
                                    old_size, new_size);
}

static FILE *troe_file_new(void) {
  FILE *file = (FILE *)troe_file_resize(NULL, 0, sizeof(FILE));
  if (file != NULL) {
    memset(file, 0, sizeof(*file));
    file->ungot = EOF;
  }
  return file;
}

static void troe_file_dispose(FILE *file) {
  if (file == NULL || file == stdin || file == stdout || file == stderr)
    return;
  if (file->buffer != NULL)
    troe_file_resize(file->buffer, file->capacity, 0);
  if (file->path != NULL)
    troe_file_resize(file->path, file->path_length + 1, 0);
  troe_file_resize(file, sizeof(*file), 0);
}

static int troe_file_reserve(FILE *file, size_t wanted) {
  size_t capacity;
  uint8_t *buffer;
  if (wanted <= file->capacity)
    return 0;
  capacity = file->capacity == 0 ? 256 : file->capacity;
  while (capacity < wanted) {
    if (capacity > (size_t)-1 / 2) {
      errno = ERANGE;
      return -1;
    }
    capacity *= 2;
  }
  buffer = (uint8_t *)troe_file_resize(file->buffer, file->capacity, capacity);
  if (buffer == NULL) {
    errno = ERANGE;
    return -1;
  }
  file->buffer = buffer;
  file->capacity = capacity;
  return 0;
}

static int troe_file_load(FILE *file) {
  size_t offset = 0;
  if (file->source_length > (uint64_t)(size_t)-1) {
    errno = ERANGE;
    return -1;
  }
  if (troe_file_reserve(file, (size_t)file->source_length) != 0)
    return -1;
  while (offset < (size_t)file->source_length) {
    intptr_t count = troe_active_host->file_read(
        troe_active_host->context, file->token, file->source_length,
        (uint64_t)offset, file->buffer + offset,
        (size_t)file->source_length - offset);
    if (count <= 0 || (size_t)count > (size_t)file->source_length - offset) {
      errno = EINVAL;
      return -1;
    }
    offset += (size_t)count;
  }
  file->length = offset;
  if (troe_active_host->file_close(troe_active_host->context, file->token,
                                   file->source_length) != 0) {
    errno = EINVAL;
    return -1;
  }
  file->token = 0;
  return 0;
}

static int troe_file_set_path(FILE *file, const char *path) {
  file->path_length = strlen(path);
  file->path = (char *)troe_file_resize(NULL, 0, file->path_length + 1);
  if (file->path == NULL) {
    errno = ERANGE;
    return -1;
  }
  memcpy(file->path, path, file->path_length + 1);
  return 0;
}

void clearerr(FILE *file) {
  if (file != NULL) {
    file->eof = 0;
    file->error = 0;
  }
}

int fclose(FILE *file) {
  int result = 0;
  if (file == NULL || file == stdin || file == stdout || file == stderr) {
    errno = EINVAL;
    return EOF;
  }
  if (fflush(file) != 0)
    result = EOF;
  if (file->token != 0 &&
      troe_active_host->file_close(troe_active_host->context, file->token,
                                   file->source_length) != 0)
    result = EOF;
  troe_file_dispose(file);
  return result;
}

int feof(FILE *file) { return file == NULL ? 0 : file->eof; }
int ferror(FILE *file) { return file == NULL ? 1 : file->error; }

int fflush(FILE *file) {
  if (file == NULL)
    return 0;
  if (!file->writable || !file->dirty || file->path == NULL)
    return file->error ? EOF : 0;
  if (troe_active_host == NULL || troe_active_host->file_replace(
          troe_active_host->context, (const uint8_t *)file->path,
          file->path_length, file->buffer, file->length) != 0) {
    file->error = 1;
    errno = EINVAL;
    return EOF;
  }
  file->dirty = 0;
  return 0;
}

char *fgets(char *buffer, int size, FILE *file) {
  int character;
  int offset = 0;
  if (buffer == NULL || file == NULL || size <= 0)
    return NULL;
  while (offset + 1 < size && (character = getc(file)) != EOF) {
    buffer[offset++] = (char)character;
    if (character == '\n')
      break;
  }
  if (offset == 0)
    return NULL;
  buffer[offset] = '\0';
  return buffer;
}

FILE *fopen(const char *path, const char *mode) {
  FILE *file;
  int initial;
  int plus;
  int existed = 0;
  uint32_t token = 0;
  uint64_t length = 0;
  if (path == NULL || mode == NULL || troe_active_host == NULL) {
    errno = EINVAL;
    return NULL;
  }
  initial = (unsigned char)mode[0];
  plus = strchr(mode, '+') != NULL;
  if (initial != 'r' && initial != 'w' && initial != 'a') {
    errno = EINVAL;
    return NULL;
  }
  file = troe_file_new();
  if (file == NULL)
    return NULL;
  file->kind = TROE_FILE_REGULAR;
  file->readable = initial == 'r' || plus;
  file->writable = initial != 'r' || plus;
  file->append = initial == 'a';
  if (file->writable && !troe_active_host->file_mutation_available) {
    troe_file_dispose(file);
    errno = EINVAL;
    return NULL;
  }
  if (troe_file_set_path(file, path) != 0) {
    troe_file_dispose(file);
    return NULL;
  }
  if (initial == 'r' || initial == 'a') {
    if (troe_active_host->file_open(troe_active_host->context,
                                    (const uint8_t *)path, strlen(path),
                                    &token, &length) == 0) {
      file->token = token;
      file->source_length = length;
      existed = 1;
    } else if (initial == 'r') {
      troe_file_dispose(file);
      errno = EINVAL;
      return NULL;
    }
  }
  if (file->writable) {
    if (file->token != 0 && troe_file_load(file) != 0) {
      troe_file_dispose(file);
      return NULL;
    }
    if (initial == 'w') {
      file->length = 0;
      file->dirty = 1;
      if (fflush(file) != 0) {
        troe_file_dispose(file);
        return NULL;
      }
    } else if (initial == 'a' && !existed) {
      file->dirty = 1;
      if (fflush(file) != 0) {
        troe_file_dispose(file);
        return NULL;
      }
    }
    file->position = initial == 'a' && !plus ? file->length : 0;
  }
  return file;
}

FILE *freopen(const char *path, const char *mode, FILE *file) {
  (void)file;
  return fopen(path, mode);
}

int getc(FILE *file) {
  unsigned char value;
  return fread(&value, 1, 1, file) == 1 ? (int)value : EOF;
}

size_t fread(void *destination, size_t size, size_t count, FILE *file) {
  size_t wanted;
  size_t copied = 0;
  uint8_t *output = (uint8_t *)destination;
  if (file == NULL || !file->readable || size == 0 || count == 0)
    return 0;
  if (count > (size_t)-1 / size) {
    file->error = 1;
    errno = ERANGE;
    return 0;
  }
  wanted = size * count;
  if (file->ungot != EOF && wanted != 0) {
    output[copied++] = (uint8_t)file->ungot;
    file->ungot = EOF;
    file->position++;
  }
  if (copied < wanted && file->kind == TROE_FILE_STDIN) {
    intptr_t got = troe_active_host->read_input(troe_active_host->context,
                                                output + copied,
                                                wanted - copied);
    if (got < 0 || (size_t)got > wanted - copied) {
      file->error = 1;
      return copied / size;
    }
    copied += (size_t)got;
    file->position += (uint64_t)got;
  } else if (copied < wanted && file->buffer != NULL) {
    size_t position = file->position > (uint64_t)(size_t)-1
                          ? file->length
                          : (size_t)file->position;
    size_t available = position < file->length ? file->length - position : 0;
    size_t take = available < wanted - copied ? available : wanted - copied;
    memcpy(output + copied, file->buffer + position, take);
    copied += take;
    file->position += (uint64_t)take;
  } else if (copied < wanted && file->token != 0) {
    intptr_t got = troe_active_host->file_read(
        troe_active_host->context, file->token, file->source_length,
        file->position, output + copied, wanted - copied);
    if (got < 0 || (size_t)got > wanted - copied) {
      file->error = 1;
      return copied / size;
    }
    copied += (size_t)got;
    file->position += (uint64_t)got;
  }
  if (copied < wanted)
    file->eof = 1;
  return copied / size;
}

size_t fwrite(const void *source, size_t size, size_t count, FILE *file) {
  size_t wanted;
  size_t position;
  if (file == NULL || !file->writable || size == 0 || count == 0)
    return 0;
  if (count > (size_t)-1 / size) {
    file->error = 1;
    errno = ERANGE;
    return 0;
  }
  wanted = size * count;
  if (file->kind == TROE_FILE_STDOUT || file->kind == TROE_FILE_STDERR) {
    int stream = file->kind == TROE_FILE_STDOUT ? 1 : 2;
    if (troe_active_host->write(troe_active_host->context, stream,
                                (const uint8_t *)source, wanted) != 0) {
      file->error = 1;
      return 0;
    }
    file->position += (uint64_t)wanted;
    return count;
  }
  if (file->append)
    file->position = (uint64_t)file->length;
  if (file->position > (uint64_t)(size_t)-1 ||
      wanted > (size_t)-1 - (size_t)file->position) {
    file->error = 1;
    errno = ERANGE;
    return 0;
  }
  position = (size_t)file->position;
  if (troe_file_reserve(file, position + wanted) != 0) {
    file->error = 1;
    return 0;
  }
  if (position > file->length)
    memset(file->buffer + file->length, 0, position - file->length);
  memcpy(file->buffer + position, source, wanted);
  file->position += (uint64_t)wanted;
  if (position + wanted > file->length)
    file->length = position + wanted;
  file->dirty = file->path != NULL;
  file->eof = 0;
  return count;
}

int fseek(FILE *file, long offset, int origin) {
  int64_t base;
  int64_t target;
  if (file == NULL || file->kind == TROE_FILE_STDIN ||
      file->kind == TROE_FILE_STDOUT || file->kind == TROE_FILE_STDERR) {
    errno = EINVAL;
    return -1;
  }
  base = origin == SEEK_SET ? 0
         : origin == SEEK_CUR ? (int64_t)file->position
         : origin == SEEK_END
             ? (int64_t)(file->buffer != NULL ? file->length
                                              : file->source_length)
             : -1;
  if (base < 0 || __builtin_add_overflow(base, (int64_t)offset, &target) ||
      target < 0) {
    errno = EINVAL;
    return -1;
  }
  file->position = (uint64_t)target;
  file->ungot = EOF;
  file->eof = 0;
  return 0;
}

long ftell(FILE *file) {
  if (file == NULL || file->position > (uint64_t)LONG_MAX) {
    errno = ERANGE;
    return -1;
  }
  return (long)file->position;
}

int remove(const char *path) {
  if (path == NULL || troe_active_host == NULL ||
      troe_active_host->file_remove(troe_active_host->context,
                                    (const uint8_t *)path,
                                    strlen(path)) != 0) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

int rename(const char *old_path, const char *new_path) {
  if (old_path == NULL || new_path == NULL || troe_active_host == NULL ||
      troe_active_host->file_rename(
          troe_active_host->context, (const uint8_t *)old_path,
          strlen(old_path), (const uint8_t *)new_path,
          strlen(new_path)) != 0) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

int setvbuf(FILE *file, char *buffer, int mode, size_t size) {
  (void)file;
  (void)buffer;
  (void)mode;
  (void)size;
  return 0;
}

FILE *tmpfile(void) {
  FILE *file = troe_file_new();
  if (file != NULL) {
    file->kind = TROE_FILE_MEMORY;
    file->readable = 1;
    file->writable = 1;
  }
  return file;
}

int ungetc(int character, FILE *file) {
  if (file == NULL || character == EOF || !file->readable ||
      file->ungot != EOF || file->position == 0)
    return EOF;
  file->ungot = (unsigned char)character;
  file->position--;
  file->eof = 0;
  return file->ungot;
}
int vfprintf(FILE *file, const char *format, va_list arguments) {
  char buffer[1024];
  int length = vsnprintf(buffer, sizeof(buffer), format, arguments);
  if (length < 0 || (size_t)length >= sizeof(buffer) ||
      fwrite(buffer, 1, (size_t)length, file) != (size_t)length)
    return -1;
  return length;
}
int fprintf(FILE *file, const char *format, ...) {
  va_list arguments;
  int result;
  va_start(arguments, format);
  result = vfprintf(file, format, arguments);
  va_end(arguments);
  return result;
}
#endif

static void troe_write_bytes(int stream, const char *bytes, size_t length) {
  if (length != 0 &&
      (troe_active_host == NULL ||
       troe_active_host->write(troe_active_host->context, stream,
                               (const uint8_t *)bytes, length) != 0))
    troe_output_failed = 1;
}

static void troe_write_error(const char *format, const char *argument) {
  const char *item = strstr(format, "%s");
  if (item == NULL) {
    troe_write_bytes(2, format, strlen(format));
    return;
  }
  troe_write_bytes(2, format, (size_t)(item - format));
  troe_write_bytes(2, argument, strlen(argument));
  troe_write_bytes(2, item + 2, strlen(item + 2));
}

#define lua_writestring(text, length) troe_write_bytes(1, (text), (length))
#define lua_writeline() troe_write_bytes(1, "\n", 1)
#define lua_writestringerror(format, argument) \
  troe_write_error((format), (argument))

static unsigned int troe_make_seed(void) {
  uint64_t wall = 0;
  uint64_t ticks = 0;
  uint64_t frequency = 0;
  uintptr_t address = (uintptr_t)&wall;
  uint64_t mixed = (uint64_t)address ^ ((uint64_t)address << 17);
  if (troe_active_host != NULL) {
    (void)troe_active_host->wall_time(troe_active_host->context, &wall);
    (void)troe_active_host->process_cpu_time(troe_active_host->context, &ticks,
                                             &frequency);
  }
  mixed ^= wall + 0x9e3779b97f4a7c15ULL;
  mixed ^= ticks + (frequency << 23);
  mixed ^= mixed >> 30;
  mixed *= 0xbf58476d1ce4e5b9ULL;
  mixed ^= mixed >> 27;
  mixed *= 0x94d049bb133111ebULL;
  mixed ^= mixed >> 31;
  return (unsigned int)(mixed ^ (mixed >> 32));
}

#define luai_makeseed() troe_make_seed()

#include "lprefix.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>

#define LUA_CORE
#define LUA_LIB
#if defined(TROE_LUA)
#define LUA_PATH_DEFAULT                                                     \
  "/share/lua/5.5/?.lua;/share/lua/5.5/?/init.lua;/share/lua/?.lua;"       \
  "/share/lua/?/init.lua;./?.lua;./?/init.lua"
#define LUA_CPATH_DEFAULT "/lib/lua/5.5/?.so;./?.so"
#endif
#include "luaconf.h"

#undef LUAI_FUNC
#undef LUAI_DDEC
#undef LUAI_DDEF
#define LUAI_FUNC static
#define LUAI_DDEC(def)
#define LUAI_DDEF static

#include "lzio.c"
#include "lctype.c"
#include "lopcodes.c"
#include "lmem.c"
#include "lundump.c"
#include "ldump.c"
#include "lstate.c"
#include "lgc.c"
#include "llex.c"
#include "lcode.c"
#include "lparser.c"
#include "ldebug.c"
#include "lfunc.c"
#include "lobject.c"
#include "ltm.c"
#include "lstring.c"
#include "ltable.c"
#include "ldo.c"
#include "lvm.c"
#include "lapi.c"
#include "lauxlib.c"
#include "lbaselib.c"
#include "loadlib.c"
#include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"
#include "troe_os_shim.c"

typedef struct TroeReader {
  TroeLuaHost *host;
  int failed;
  uint8_t bytes[4094];
} TroeReader;

static const char *troe_reader(lua_State *state, void *context, size_t *size) {
  TroeReader *reader = (TroeReader *)context;
  intptr_t count;
  (void)state;
  count = reader->host->read(reader->host->context, reader->bytes,
                             sizeof(reader->bytes));
  if (count < 0 || (size_t)count > sizeof(reader->bytes)) {
    reader->failed = 1;
    *size = 0;
    return NULL;
  }
  *size = (size_t)count;
  return count == 0 ? NULL : (const char *)reader->bytes;
}

static void troe_require(lua_State *state, const char *name,
                         lua_CFunction open_function) {
  luaL_requiref(state, name, open_function, 1);
  lua_pop(state, 1);
}

static int troe_configure_state(lua_State *state) {
  TroeLuaConfiguration *configuration = troe_active_configuration;
  troe_require(state, LUA_GNAME, luaopen_base);
  troe_require(state, LUA_LOADLIBNAME, luaopen_package);
  troe_require(state, LUA_COLIBNAME, luaopen_coroutine);
  troe_require(state, LUA_DBLIBNAME, luaopen_debug);
  troe_require(state, LUA_IOLIBNAME, luaopen_io);
  troe_require(state, LUA_TABLIBNAME, luaopen_table);
  troe_require(state, LUA_STRLIBNAME, luaopen_string);
  troe_require(state, LUA_MATHLIBNAME, luaopen_math);
  troe_require(state, LUA_UTF8LIBNAME, luaopen_utf8);
  troe_require(state, LUA_OSLIBNAME, troe_luaopen_os);

  lua_createtable(state, (int)configuration->argument_count, 0);
  for (size_t index = 0; index < configuration->argument_count; ++index) {
    const TroeLuaArgument *argument = &configuration->arguments[index];
    lua_pushlstring(state, (const char *)argument->bytes, argument->length);
    lua_seti(state, -2, (lua_Integer)index);
  }
  lua_setglobal(state, "arg");
  return 0;
}

static int troe_traceback(lua_State *state) {
  const char *message = lua_tostring(state, 1);
  if (message == NULL)
    message = "(non-string Lua error)";
  luaL_traceback(state, state, message, 1);
  return 1;
}

enum { TROE_LUA_ACTION_CODE = 1, TROE_LUA_ACTION_REQUIRE = 2 };

static int troe_protected_call(lua_State *state, int argument_count,
                               int result_count) {
  int function = lua_gettop(state) - argument_count;
  int status;
  lua_pushcfunction(state, troe_traceback);
  lua_insert(state, function);
  status = lua_pcall(state, argument_count, result_count, function);
  lua_remove(state, function);
  return status;
}

static int troe_run_action(lua_State *state, const TroeLuaAction *action) {
  int base = lua_gettop(state);
  int status;
  if (action->kind == TROE_LUA_ACTION_CODE) {
    status = luaL_loadbufferx(state, (const char *)action->bytes,
                              action->length, "=(command line)", "t");
    if (status == LUA_OK)
      status = troe_protected_call(state, 0, LUA_MULTRET);
  } else if (action->kind == TROE_LUA_ACTION_REQUIRE) {
    const uint8_t *equals =
        (const uint8_t *)memchr(action->bytes, '=', action->length);
    const uint8_t *module = action->bytes;
    size_t module_length = action->length;
    size_t global_length = 0;
    if (equals != NULL) {
      global_length = (size_t)(equals - action->bytes);
      module = equals + 1;
      module_length = action->length - global_length - 1;
    }
    lua_getglobal(state, "require");
    lua_pushlstring(state, (const char *)module, module_length);
    status = troe_protected_call(state, 1, 1);
    if (status == LUA_OK && equals != NULL && global_length != 0) {
      lua_pushglobaltable(state);
      lua_pushlstring(state, (const char *)action->bytes, global_length);
      lua_pushvalue(state, -3);
      lua_settable(state, -3);
    }
  } else {
    lua_pushliteral(state, "invalid command-line action");
    status = LUA_ERRRUN;
  }
  if (status == LUA_OK)
    lua_settop(state, base);
  return status;
}

static void troe_report_lua_error(lua_State *state) {
  const char *message = lua_tostring(state, -1);
  if (message == NULL)
    message = "Lua failed without a string error";
  troe_write_bytes(2, message, strlen(message));
  troe_write_bytes(2, "\n", 1);
  lua_pop(state, 1);
}

enum {
  TROE_LUA_SUCCESS = 0,
  TROE_LUA_FAILURE = 1,
  TROE_LUA_SOURCE_FAILURE = 2,
  TROE_LUA_OUTPUT_FAILURE = 3,
  TROE_LUA_OUT_OF_MEMORY = 4,
  TROE_LUA_REQUESTED_EXIT = 5
};

int troe_lua_run(TroeLuaConfiguration *configuration) {
  lua_State *state;
  TroeReader reader;
  int status;
  int handler;
  troe_active_host = configuration->host;
  troe_active_configuration = configuration;
  troe_output_failed = 0;

  state = lua_newstate(configuration->host->allocate,
                       configuration->host->context, troe_make_seed());
  if (state == NULL) {
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return TROE_LUA_OUT_OF_MEMORY;
  }
  lua_setwarnf(state, warnfoff, state);
  if (configuration->warnings_enabled)
    lua_warning(state, "@on", 0);
  if (configuration->ignore_environment) {
    lua_pushboolean(state, 1);
    lua_setfield(state, LUA_REGISTRYINDEX, "LUA_NOENV");
  }
  troe_exit_jump_active = 1;
  if (setjmp(troe_unclosed_exit_jump) != 0) {
    /* os.exit(_, false) abandons this state exactly as process exit would. */
    troe_exit_jump_active = 0;
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return TROE_LUA_REQUESTED_EXIT;
  }
  lua_pushcfunction(state, troe_configure_state);
  status = lua_pcall(state, 0, 0, 0);
  if (status != LUA_OK) {
    troe_report_lua_error(state);
    troe_exit_jump_active = 0;
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE : TROE_LUA_FAILURE;
  }
  (void)lua_gc(state, LUA_GCGEN);

  for (size_t index = 0; index < configuration->action_count; ++index) {
    status = troe_run_action(state, &configuration->actions[index]);
    if (configuration->requested_exit) {
      troe_exit_jump_active = 0;
      if (configuration->requested_exit_close)
        lua_close(state);
      troe_active_configuration = NULL;
      troe_active_host = NULL;
      return TROE_LUA_REQUESTED_EXIT;
    }
    if (status != LUA_OK) {
      troe_report_lua_error(state);
      troe_exit_jump_active = 0;
      lua_close(state);
      troe_active_configuration = NULL;
      troe_active_host = NULL;
      return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE : TROE_LUA_FAILURE;
    }
  }
  if (!configuration->has_source) {
    troe_exit_jump_active = 0;
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE : TROE_LUA_SUCCESS;
  }

  lua_pushlstring(state, (const char *)configuration->source_name,
                  configuration->source_name_length);
  const char *source_name = lua_tostring(state, -1);
  reader.host = configuration->host;
  reader.failed = 0;
  status = lua_load(state, troe_reader, &reader, source_name, "bt");
  lua_remove(state, -2);
  if (reader.failed) {
    if (status != LUA_OK)
      lua_pop(state, 1);
    troe_write_bytes(2, "lua: source read failed\n", 24);
    troe_exit_jump_active = 0;
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE
                              : TROE_LUA_SOURCE_FAILURE;
  }
  if (status != LUA_OK) {
    troe_report_lua_error(state);
    troe_exit_jump_active = 0;
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE : TROE_LUA_FAILURE;
  }

  lua_pushcfunction(state, troe_traceback);
  lua_insert(state, -2);
  handler = lua_gettop(state) - 1;
  status = lua_pcall(state, 0, LUA_MULTRET, handler);
  if (configuration->requested_exit) {
    /* The close=true path reached us through Lua's valid base-level unwind. */
    troe_exit_jump_active = 0;
    if (configuration->requested_exit_close)
      lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return TROE_LUA_REQUESTED_EXIT;
  }
  lua_remove(state, handler);
  if (status != LUA_OK)
    troe_report_lua_error(state);
  troe_exit_jump_active = 0;
  lua_close(state);
  troe_active_configuration = NULL;
  troe_active_host = NULL;
  if (troe_output_failed)
    return TROE_LUA_OUTPUT_FAILURE;
  return status == LUA_OK ? TROE_LUA_SUCCESS : TROE_LUA_FAILURE;
}
