#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__aarch64__)
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
typedef int (*TroeYield)(void *context);

struct TroeLuaHost {
  void *context;
  TroeAllocate allocate;
  TroeRead read;
  TroeWrite write;
  TroeYield yield_now;
};

typedef struct TroeLuaArgument {
  const uint8_t *bytes;
  size_t length;
} TroeLuaArgument;

typedef struct TroeLuaConfiguration {
  TroeLuaHost *host;
  const uint8_t *source_name;
  size_t source_name_length;
  const TroeLuaArgument *arguments;
  size_t argument_count;
} TroeLuaConfiguration;

extern int troe_parse_decimal(const uint8_t *bytes, size_t length,
                              double *result);

int errno;
FILE *stdin;
FILE *stdout;
FILE *stderr;

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
  (void)error;
  return "operation unavailable in KEX";
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

int fclose(FILE *file) {
  (void)file;
  return EOF;
}
int feof(FILE *file) {
  (void)file;
  return 1;
}
int ferror(FILE *file) {
  (void)file;
  return 1;
}
int fflush(FILE *file) {
  (void)file;
  return 0;
}
char *fgets(char *buffer, int size, FILE *file) {
  (void)buffer;
  (void)size;
  (void)file;
  return NULL;
}
FILE *fopen(const char *path, const char *mode) {
  (void)path;
  (void)mode;
  return NULL;
}
FILE *freopen(const char *path, const char *mode, FILE *file) {
  (void)path;
  (void)mode;
  (void)file;
  return NULL;
}
int getc(FILE *file) {
  (void)file;
  return EOF;
}
size_t fread(void *destination, size_t size, size_t count, FILE *file) {
  (void)destination;
  (void)size;
  (void)count;
  (void)file;
  return 0;
}
size_t fwrite(const void *source, size_t size, size_t count, FILE *file) {
  (void)source;
  (void)size;
  (void)count;
  (void)file;
  return 0;
}
int remove(const char *path) {
  (void)path;
  return -1;
}
int rename(const char *old_path, const char *new_path) {
  (void)old_path;
  (void)new_path;
  return -1;
}
int vfprintf(FILE *file, const char *format, va_list arguments) {
  (void)file;
  (void)format;
  (void)arguments;
  return -1;
}
int fprintf(FILE *file, const char *format, ...) {
  (void)file;
  (void)format;
  return -1;
}

static TroeLuaHost *troe_active_host;
static TroeLuaConfiguration *troe_active_configuration;
static int troe_output_failed;

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
#define luai_makeseed() 0x54524f45u

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
#include "lcorolib.c"
#include "lmathlib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"

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

static void troe_instruction_hook(lua_State *state, lua_Debug *debug) {
  (void)debug;
  if (troe_active_host == NULL ||
      troe_active_host->yield_now(troe_active_host->context) != 0)
    luaL_error(state, "cooperative yield failed");
}

static void troe_require(lua_State *state, const char *name,
                         lua_CFunction open_function) {
  luaL_requiref(state, name, open_function, 1);
  lua_pop(state, 1);
}

static int troe_configure_state(lua_State *state) {
  TroeLuaConfiguration *configuration = troe_active_configuration;
  troe_require(state, LUA_GNAME, luaopen_base);
  troe_require(state, LUA_COLIBNAME, luaopen_coroutine);
  troe_require(state, LUA_TABLIBNAME, luaopen_table);
  troe_require(state, LUA_STRLIBNAME, luaopen_string);
  troe_require(state, LUA_MATHLIBNAME, luaopen_math);
  troe_require(state, LUA_UTF8LIBNAME, luaopen_utf8);

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
  TROE_LUA_OUT_OF_MEMORY = 4
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
                       configuration->host->context, 0x54524f45u);
  if (state == NULL) {
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return TROE_LUA_OUT_OF_MEMORY;
  }
  lua_sethook(state, troe_instruction_hook, LUA_MASKCOUNT, 2048);

  lua_pushcfunction(state, troe_configure_state);
  status = lua_pcall(state, 0, 0, 0);
  if (status != LUA_OK) {
    troe_report_lua_error(state);
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE : TROE_LUA_FAILURE;
  }

  lua_pushlstring(state, (const char *)configuration->source_name,
                  configuration->source_name_length);
  const char *source_name = lua_tostring(state, -1);
  reader.host = configuration->host;
  reader.failed = 0;
  status = lua_load(state, troe_reader, &reader, source_name, "t");
  lua_remove(state, -2);
  if (reader.failed) {
    if (status != LUA_OK)
      lua_pop(state, 1);
    troe_write_bytes(2, "lua: source read failed\n", 24);
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE
                              : TROE_LUA_SOURCE_FAILURE;
  }
  if (status != LUA_OK) {
    troe_report_lua_error(state);
    lua_close(state);
    troe_active_configuration = NULL;
    troe_active_host = NULL;
    return troe_output_failed ? TROE_LUA_OUTPUT_FAILURE : TROE_LUA_FAILURE;
  }

  lua_pushcfunction(state, troe_traceback);
  lua_insert(state, -2);
  handler = lua_gettop(state) - 1;
  status = lua_pcall(state, 0, LUA_MULTRET, handler);
  lua_remove(state, handler);
  if (status != LUA_OK)
    troe_report_lua_error(state);
  lua_close(state);
  troe_active_configuration = NULL;
  troe_active_host = NULL;
  if (troe_output_failed)
    return TROE_LUA_OUTPUT_FAILURE;
  return status == LUA_OK ? TROE_LUA_SUCCESS : TROE_LUA_FAILURE;
}
