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
typedef intptr_t (*TroeEnvironmentGet)(void *context, const uint8_t *name,
                                       size_t name_length,
                                       uint8_t *destination,
                                       size_t capacity);
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
typedef int (*TroeProcessExecute)(void *context, const uint8_t *command,
                                  size_t command_length, uint32_t *status);
typedef int (*TroeProcessOpen)(void *context, const uint8_t *command,
                               size_t command_length, int mode,
                               uint64_t *child_token, uint64_t *pipe_token,
                               uint64_t *script_identifier);
typedef intptr_t (*TroeProcessRead)(void *context, uint64_t pipe_token,
                                    uint8_t *destination, size_t capacity);
typedef int (*TroeProcessWrite)(void *context, uint64_t pipe_token,
                                const uint8_t *bytes, size_t length);
typedef int (*TroeProcessClose)(void *context, uint64_t child_token,
                                uint64_t pipe_token,
                                uint64_t script_identifier, int mode,
                                uint32_t *status);

struct TroeLuaHost {
  void *context;
  TroeAllocate allocate;
  TroeRead read;
  TroeWrite write;
  TroeProcessCpuTime process_cpu_time;
  TroeWallTime wall_time;
  TroeEnvironmentGet environment_get;
  TroeReadInput read_input;
  TroeFileOpen file_open;
  TroeFileRead file_read;
  TroeFileClose file_close;
  TroeFileReplace file_replace;
  TroeFilePathOperation file_remove;
  TroeFileRename file_rename;
  int file_mutation_available;
  TroeProcessExecute process_execute;
  TroeProcessOpen process_open;
  TroeProcessRead process_read;
  TroeProcessWrite process_write;
  TroeProcessClose process_close;
  int process_available;
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
#include "../../../sdk/c/troe-kex-runtime/troe_libc_core.c"

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
  static char value[2049];
  intptr_t length;
  if (name == NULL || troe_active_host == NULL)
    return NULL;
  length = troe_active_host->environment_get(
      troe_active_host->context, (const uint8_t *)name, strlen(name),
      (uint8_t *)value, sizeof(value) - 1);
  if (length < 0 || (size_t)length >= sizeof(value))
    return NULL;
  value[length] = '\0';
  return value;
}

time_t time(time_t *destination) {
  uint64_t seconds;
  time_t result;
  if (troe_active_host == NULL ||
      troe_active_host->wall_time(troe_active_host->context, &seconds) != 0 ||
      seconds > (uint64_t)LONG_MAX) {
    errno = EOVERFLOW;
    result = (time_t)-1;
  } else {
    result = (time_t)seconds;
  }
  if (destination != NULL)
    *destination = result;
  return result;
}

enum {
  TROE_FILE_REGULAR = 0,
  TROE_FILE_STDIN = 1,
  TROE_FILE_STDOUT = 2,
  TROE_FILE_STDERR = 3,
  TROE_FILE_MEMORY = 4,
  TROE_FILE_PROCESS = 5
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
  uint64_t child_token;
  uint64_t pipe_token;
  uint64_t script_identifier;
  int process_mode;
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

static int troe_callback_errno(int result) {
  return result > 0 ? result : EIO;
}

static int troe_read_errno(intptr_t result) {
  return result < 0 && result >= -(intptr_t)INT_MAX ? (int)-result : EIO;
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
      errno = count < 0 ? troe_read_errno(count) : EIO;
      return -1;
    }
    offset += (size_t)count;
  }
  file->length = offset;
  int close_result = troe_active_host->file_close(
      troe_active_host->context, file->token, file->source_length);
  if (close_result != 0) {
    errno = troe_callback_errno(close_result);
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

static FILE *troe_popen(const char *command, const char *mode) {
  FILE *file;
  uint64_t child_token = 0;
  uint64_t pipe_token = 0;
  uint64_t script_identifier = 0;
  int selected_mode;
  int result;
  if (command == NULL || mode == NULL ||
      (mode[0] != 'r' && mode[0] != 'w') || mode[1] != '\0' ||
      troe_active_host == NULL || !troe_active_host->process_available) {
    errno = EINVAL;
    return NULL;
  }
  selected_mode = (unsigned char)mode[0];
  result = troe_active_host->process_open(
      troe_active_host->context, (const uint8_t *)command, strlen(command),
      selected_mode, &child_token, &pipe_token, &script_identifier);
  if (result != 0) {
    errno = troe_callback_errno(result);
    return NULL;
  }
  file = troe_file_new();
  if (file == NULL) {
    uint32_t ignored_status;
    (void)troe_active_host->process_close(
        troe_active_host->context, child_token, pipe_token, script_identifier,
        selected_mode, &ignored_status);
    return NULL;
  }
  file->kind = TROE_FILE_PROCESS;
  file->readable = selected_mode == 'r';
  file->writable = selected_mode == 'w';
  file->child_token = child_token;
  file->pipe_token = pipe_token;
  file->script_identifier = script_identifier;
  file->process_mode = selected_mode;
  return file;
}

static int troe_pclose(FILE *file) {
  uint32_t status = 0;
  int result;
  if (file == NULL || file->kind != TROE_FILE_PROCESS ||
      troe_active_host == NULL) {
    errno = EINVAL;
    return -1;
  }
  result = troe_active_host->process_close(
      troe_active_host->context, file->child_token, file->pipe_token,
      file->script_identifier, file->process_mode, &status);
  troe_file_dispose(file);
  if (result != 0) {
    errno = troe_callback_errno(result);
    return -1;
  }
  return (int)(status & 0xffu);
}

int fclose(FILE *file) {
  int result = 0;
  int close_result;
  if (file == NULL || file == stdin || file == stdout || file == stderr) {
    errno = EINVAL;
    return EOF;
  }
  if (file->kind == TROE_FILE_PROCESS)
    return troe_pclose(file);
  if (fflush(file) != 0)
    result = EOF;
  if (file->token != 0) {
    close_result = troe_active_host->file_close(
        troe_active_host->context, file->token, file->source_length);
    if (close_result != 0) {
      errno = troe_callback_errno(close_result);
      result = EOF;
    }
  }
  troe_file_dispose(file);
  return result;
}

int feof(FILE *file) { return file == NULL ? 0 : file->eof; }
int ferror(FILE *file) { return file == NULL ? 1 : file->error; }

int fflush(FILE *file) {
  int result;
  if (file == NULL)
    return 0;
  if (!file->writable || !file->dirty || file->path == NULL)
    return file->error ? EOF : 0;
  if (troe_active_host == NULL) {
    file->error = 1;
    errno = EINVAL;
    return EOF;
  }
  result = troe_active_host->file_replace(
      troe_active_host->context, (const uint8_t *)file->path,
      file->path_length, file->buffer, file->length);
  if (result != 0) {
    file->error = 1;
    errno = troe_callback_errno(result);
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
  int open_result = ENOENT;
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
    open_result = troe_active_host->file_open(
        troe_active_host->context, (const uint8_t *)path, strlen(path), &token,
        &length);
    if (open_result == 0) {
      file->token = token;
      file->source_length = length;
      existed = 1;
    } else if (initial == 'r' || open_result != ENOENT) {
      troe_file_dispose(file);
      errno = troe_callback_errno(open_result);
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
      errno = got < 0 ? troe_read_errno(got) : EIO;
      return copied / size;
    }
    copied += (size_t)got;
    file->position += (uint64_t)got;
  } else if (copied < wanted && file->kind == TROE_FILE_PROCESS) {
    intptr_t got = troe_active_host->process_read(
        troe_active_host->context, file->pipe_token, output + copied,
        wanted - copied);
    if (got < 0 || (size_t)got > wanted - copied) {
      file->error = 1;
      errno = got < 0 ? troe_read_errno(got) : EIO;
      return copied / size;
    }
    copied += (size_t)got;
    file->position += (uint64_t)got;
    if (got == 0)
      file->eof = 1;
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
      errno = got < 0 ? troe_read_errno(got) : EIO;
      return copied / size;
    }
    copied += (size_t)got;
    file->position += (uint64_t)got;
  }
  if (copied < wanted && file->kind != TROE_FILE_PROCESS)
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
    int result = troe_active_host->write(
        troe_active_host->context, stream, (const uint8_t *)source, wanted);
    if (result != 0) {
      file->error = 1;
      errno = troe_callback_errno(result);
      return 0;
    }
    file->position += (uint64_t)wanted;
    return count;
  }
  if (file->kind == TROE_FILE_PROCESS) {
    int result = troe_active_host->process_write(
        troe_active_host->context, file->pipe_token, (const uint8_t *)source,
        wanted);
    if (result != 0) {
      file->error = 1;
      errno = troe_callback_errno(result);
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
  if (file->kind == TROE_FILE_PROCESS) {
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
  int result;
  if (path == NULL || troe_active_host == NULL) {
    errno = EINVAL;
    return -1;
  }
  result = troe_active_host->file_remove(
      troe_active_host->context, (const uint8_t *)path, strlen(path));
  if (result != 0) {
    errno = troe_callback_errno(result);
    return -1;
  }
  return 0;
}

int rename(const char *old_path, const char *new_path) {
  int result;
  if (old_path == NULL || new_path == NULL || troe_active_host == NULL) {
    errno = EINVAL;
    return -1;
  }
  result = troe_active_host->file_rename(
      troe_active_host->context, (const uint8_t *)old_path, strlen(old_path),
      (const uint8_t *)new_path, strlen(new_path));
  if (result != 0) {
    errno = troe_callback_errno(result);
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
  extern uint32_t troe_runtime_mix_seed(uint64_t address,
                                        uint64_t wall_seconds, uint64_t ticks,
                                        uint64_t frequency_hz);
  if (troe_active_host != NULL) {
    (void)troe_active_host->wall_time(troe_active_host->context, &wall);
    (void)troe_active_host->process_cpu_time(troe_active_host->context, &ticks,
                                             &frequency);
  }
  return troe_runtime_mix_seed((uint64_t)address, wall, ticks, frequency);
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
#if !defined(TROE_LUA_HOST_TEST)
#define l_popen(L, command, mode)                                             \
  ((void)(L), troe_popen((command), (mode)))
#define l_pclose(L, file) ((void)(L), troe_pclose((file)))
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
