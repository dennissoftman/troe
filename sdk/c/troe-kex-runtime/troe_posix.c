/* Bounded, capability-scoped POSIX and stdio facade for freestanding KEX C. */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include <troe/runtime.h>

extern void troe_runtime_run_tss_destructors(void);

/* The timezone rules live once, in the Rust KEX runtime, so libc, Lua, and
   CPython cannot disagree about a transition. See ADR 0067. */
#define TROE_ZONE_ABBREVIATION_BYTES 16

typedef struct TroeRuntimeCalendar {
  int64_t year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
  int week_day;
  int year_day;
  int gmt_offset;
  int daylight;
  unsigned char zone[TROE_ZONE_ABBREVIATION_BYTES];
  unsigned char zone_length;
} TroeRuntimeCalendar;

typedef struct TroeRuntimeCalendarResult {
  int status;
  int64_t seconds;
  TroeRuntimeCalendar calendar;
} TroeRuntimeCalendarResult;

typedef struct TroeRuntimeZoneSummary {
  int standard_offset;
  int daylight_offset;
  int observes_daylight;
  unsigned char standard[TROE_ZONE_ABBREVIATION_BYTES];
  unsigned char standard_length;
  unsigned char daylight[TROE_ZONE_ABBREVIATION_BYTES];
  unsigned char daylight_length;
} TroeRuntimeZoneSummary;

extern TroeRuntimeCalendar troe_runtime_local_calendar_from_seconds(
    const unsigned char *timezone_text, size_t timezone_length, int64_t seconds);
extern TroeRuntimeCalendarResult troe_runtime_normalize_local_calendar(
    const unsigned char *timezone_text, size_t timezone_length,
    TroeRuntimeCalendar calendar);
extern TroeRuntimeZoneSummary troe_runtime_zone_summary(
    const unsigned char *timezone_text, size_t timezone_length);

#define TROE_FILE_SLOTS 16U
#define TROE_PATH_BUFFER TROE_C_MAX_PATH_BYTES
#define TROE_FILE_BUFFER 4096U

enum TroeDescriptorKind {
  TROE_DESCRIPTOR_FREE = 0,
  TROE_DESCRIPTOR_INPUT = 1,
  TROE_DESCRIPTOR_OUTPUT = 2,
  TROE_DESCRIPTOR_FILE = 3,
  TROE_DESCRIPTOR_REPLACEMENT = 4,
  TROE_DESCRIPTOR_DIRECTORY = 5
};

struct TroeDescriptor {
  unsigned int kind;
  unsigned int readable;
  unsigned int writable;
  unsigned int append;
  uint32_t token;
  uint64_t position;
  uint64_t byte_count;
  char path[TROE_PATH_BUFFER];
};

struct TroeDirectoryStream {
  unsigned int used;
  uint64_t cursor;
  char path[TROE_PATH_BUFFER];
  struct dirent entry;
};

enum TroeFileDirection {
  TROE_FILE_IDLE = 0,
  TROE_FILE_READING = 1,
  TROE_FILE_WRITING = 2
};

struct TroeFile {
  unsigned int used;
  unsigned int owns_descriptor;
  unsigned int direction;
  int descriptor;
  int eof;
  int error;
  int ungot;
  int buffering;
  size_t buffered;
  size_t consumed;
  size_t capacity;
  unsigned char *buffer;
  unsigned char internal[TROE_FILE_BUFFER];
};

static const struct troe_runtime_host *troe_host;
static struct TroeDescriptor troe_descriptors[TROE_C_MAX_DESCRIPTORS];
static struct TroeDirectoryStream troe_directories[TROE_C_MAX_DIRECTORIES];
static struct TroeFile troe_files[TROE_FILE_SLOTS];
static struct TroeFile troe_standard_files[3];
static char troe_cwd[TROE_PATH_BUFFER];
static void (*troe_atexit[TROE_C_MAX_ATEXIT])(void);
static size_t troe_atexit_count;
static int troe_initialized;
/* `TZ` is fixed for the life of a launch: `setenv` is unsupported and ADR 0054
   makes the launch environment immutable. The cache is therefore written once
   and only read afterwards, so `tm_zone` may point into it safely. */
static char troe_tz_standard[TROE_ZONE_ABBREVIATION_BYTES + 1];
static char troe_tz_daylight[TROE_ZONE_ABBREVIATION_BYTES + 1];
static const char *troe_tz_text;
static size_t troe_tz_length;
static int troe_tz_ready;

int __troe_argc;
char **__troe_argv;
char **environ;
char *tzname[2] = {troe_tz_standard, troe_tz_daylight};
long timezone;
int daylight;
FILE *stdin;
FILE *stdout;
FILE *stderr;

static int troe_host_error(int result) {
  return result > 0 && result <= INT_MAX ? result : EIO;
}

static int troe_host_read_error(intptr_t result) {
  return result < 0 && result >= -(intptr_t)INT_MAX ? (int)-result : EIO;
}

static int troe_fail(int error) {
  errno = error;
  return -1;
}

static int troe_add_component(char *destination, size_t *length,
                              const char *component, size_t component_length) {
  if (component_length == 0 ||
      (component_length == 1 && component[0] == '.'))
    return 0;
  if (component_length == 2 && component[0] == '.' && component[1] == '.') {
    if (*length > 1) {
      --*length;
      while (*length > 1 && destination[*length - 1] != '/')
        --*length;
    }
    destination[*length] = '\0';
    return 0;
  }
  if (component_length > TROE_C_MAX_NAME_BYTES)
    return ENAMETOOLONG;
  size_t separator = *length > 1 ? 1 : 0;
  if (*length + separator + component_length >= TROE_PATH_BUFFER)
    return ENAMETOOLONG;
  if (separator != 0)
    destination[(*length)++] = '/';
  memcpy(destination + *length, component, component_length);
  *length += component_length;
  destination[*length] = '\0';
  return 0;
}

static int troe_resolve_path(const char *path, char *destination) {
  if (path == NULL || path[0] == '\0')
    return EINVAL;
  size_t length;
  if (path[0] == '/') {
    destination[0] = '/';
    destination[1] = '\0';
    length = 1;
  } else {
    length = strnlen(troe_cwd, TROE_PATH_BUFFER);
    if (length == TROE_PATH_BUFFER)
      return EIO;
    memcpy(destination, troe_cwd, length + 1);
  }
  const char *cursor = path;
  while (*cursor != '\0') {
    while (*cursor == '/')
      ++cursor;
    const char *component = cursor;
    while (*cursor != '\0' && *cursor != '/')
      ++cursor;
    int result = troe_add_component(destination, &length, component,
                                    (size_t)(cursor - component));
    if (result != 0)
      return result;
  }
  return 0;
}

static int troe_resolve(const char *path, char *destination) {
  int result = troe_resolve_path(path, destination);
  if (result != 0) {
    errno = result;
    return -1;
  }
  return 0;
}

void *malloc(size_t size) {
  if (troe_host == NULL || troe_host->allocate == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  void *pointer = troe_host->allocate(troe_host->context, NULL, size,
                                      _Alignof(max_align_t), 0);
  if (pointer == NULL)
    errno = ENOMEM;
  return pointer;
}

void *calloc(size_t count, size_t size) {
  size_t bytes;
  if (__builtin_mul_overflow(count, size, &bytes)) {
    errno = ENOMEM;
    return NULL;
  }
  if (troe_host == NULL || troe_host->allocate == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  void *pointer = troe_host->allocate(troe_host->context, NULL, bytes,
                                      _Alignof(max_align_t), 1);
  if (pointer == NULL)
    errno = ENOMEM;
  return pointer;
}

void *realloc(void *pointer, size_t size) {
  if (troe_host == NULL || troe_host->allocate == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  void *replacement =
      troe_host->allocate(troe_host->context, pointer, size,
                          _Alignof(max_align_t), 0);
  if (replacement == NULL && size != 0)
    errno = ENOMEM;
  return replacement;
}

void free(void *pointer) {
  if (pointer != NULL && troe_host != NULL && troe_host->allocate != NULL)
    (void)troe_host->allocate(troe_host->context, pointer, 0,
                              _Alignof(max_align_t), 0);
}

void *aligned_alloc(size_t alignment, size_t size) {
  if (alignment == 0 || size % alignment != 0 ||
      (alignment & (alignment - 1)) != 0 || alignment < sizeof(void *)) {
    errno = EINVAL;
    return NULL;
  }
  if (troe_host == NULL || troe_host->allocate == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  void *pointer =
      troe_host->allocate(troe_host->context, NULL, size, alignment, 0);
  if (pointer == NULL)
    errno = ENOMEM;
  return pointer;
}

int posix_memalign(void **pointer, size_t alignment, size_t size) {
  if (pointer == NULL || alignment < sizeof(void *) ||
      (alignment & (alignment - 1)) != 0 || alignment % sizeof(void *) != 0)
    return EINVAL;
  if (troe_host == NULL || troe_host->allocate == NULL)
    return ENOMEM;
  void *allocation =
      troe_host->allocate(troe_host->context, NULL, size, alignment, 0);
  if (allocation == NULL)
    return ENOMEM;
  *pointer = allocation;
  return 0;
}

static int troe_descriptor_allocate(void) {
  for (unsigned int descriptor = 3; descriptor < TROE_C_MAX_DESCRIPTORS;
       ++descriptor) {
    if (troe_descriptors[descriptor].kind == TROE_DESCRIPTOR_FREE)
      return (int)descriptor;
  }
  errno = EMFILE;
  return -1;
}

static struct TroeDescriptor *troe_descriptor(int descriptor) {
  if (descriptor < 0 || descriptor >= (int)TROE_C_MAX_DESCRIPTORS ||
      troe_descriptors[descriptor].kind == TROE_DESCRIPTOR_FREE) {
    errno = EBADF;
    return NULL;
  }
  return &troe_descriptors[descriptor];
}

static int troe_abort_descriptor(struct TroeDescriptor *entry) {
  int result = 0;
  if (entry->kind == TROE_DESCRIPTOR_FILE && troe_host != NULL &&
      troe_host->file_close != NULL)
    result = troe_host->file_close(troe_host->context, entry->token);
  else if (entry->kind == TROE_DESCRIPTOR_REPLACEMENT && troe_host != NULL &&
           troe_host->replace_finish != NULL)
    result = troe_host->replace_finish(troe_host->context, entry->token, 0);
  memset(entry, 0, sizeof(*entry));
  return result;
}

static int troe_begin_replacement(struct TroeDescriptor *entry,
                                  const char *path, int preserve) {
  if (troe_host == NULL || troe_host->replace_begin == NULL ||
      troe_host->replace_append == NULL || troe_host->replace_finish == NULL)
    return EACCES;
  uint32_t token = 0;
  uint64_t initial_offset = 0;
  int result = troe_host->replace_begin(troe_host->context,
                                        (const uint8_t *)path, strlen(path),
                                        preserve, &token, &initial_offset);
  if (result != 0)
    return troe_host_error(result);
  entry->kind = TROE_DESCRIPTOR_REPLACEMENT;
  entry->writable = 1;
  entry->token = token;
  entry->position = initial_offset;
  entry->byte_count = initial_offset;
  strcpy(entry->path, path);
  return 0;
}

int open(const char *path, int flags, ...) {
  const int known = O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND |
                    O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
  if ((flags & ~known) != 0)
    return troe_fail(ENOTSUP);
  int access_mode = flags & O_ACCMODE;
  if (access_mode != O_RDONLY && access_mode != O_WRONLY &&
      access_mode != O_RDWR)
    return troe_fail(EINVAL);
  char resolved[TROE_PATH_BUFFER];
  if (troe_resolve(path, resolved) != 0)
    return -1;
  if ((flags & O_NOFOLLOW) != 0) {
    struct troe_host_metadata metadata;
    if (troe_host == NULL || troe_host->metadata == NULL)
      return troe_fail(EACCES);
    int result = troe_host->metadata(troe_host->context,
                                     (const uint8_t *)resolved,
                                     strlen(resolved), 0, &metadata);
    if (result == 0) {
      if (metadata.kind == TROE_NODE_SYMLINK)
        return troe_fail(ELOOP);
      // O_NOFOLLOW constrains an existing final component only. A creating
      // open of a missing name stays valid and is resolved below.
    } else if (troe_host_error(result) != ENOENT || (flags & O_CREAT) == 0) {
      return troe_fail(troe_host_error(result));
    }
  }
  int descriptor = troe_descriptor_allocate();
  if (descriptor < 0)
    return -1;
  struct TroeDescriptor *entry = &troe_descriptors[descriptor];
  memset(entry, 0, sizeof(*entry));
  if (access_mode == O_RDONLY) {
    if ((flags & (O_CREAT | O_EXCL | O_TRUNC | O_APPEND)) != 0)
      return troe_fail(EINVAL);
    if ((flags & O_DIRECTORY) != 0) {
      struct troe_host_metadata metadata;
      if (troe_host == NULL || troe_host->metadata == NULL)
        return troe_fail(EACCES);
      int result = troe_host->metadata(troe_host->context,
                                       (const uint8_t *)resolved,
                                       strlen(resolved), 1, &metadata);
      if (result != 0)
        return troe_fail(troe_host_error(result));
      if (metadata.kind != TROE_NODE_DIRECTORY)
        return troe_fail(ENOTDIR);
      entry->kind = TROE_DESCRIPTOR_DIRECTORY;
      entry->readable = 1;
      strcpy(entry->path, resolved);
      return descriptor;
    }
    if (troe_host == NULL || troe_host->file_open == NULL)
      return troe_fail(EACCES);
    int result = troe_host->file_open(
        troe_host->context, (const uint8_t *)resolved, strlen(resolved),
        &entry->token, &entry->byte_count);
    if (result != 0)
      return troe_fail(troe_host_error(result));
    entry->kind = TROE_DESCRIPTOR_FILE;
    entry->readable = 1;
    strcpy(entry->path, resolved);
    return descriptor;
  }
  if ((flags & O_DIRECTORY) != 0)
    return troe_fail(EISDIR);
  if ((flags & (O_CREAT | O_TRUNC | O_APPEND)) == 0)
    return troe_fail(ENOTSUP);
  if ((flags & O_EXCL) != 0 && (flags & O_CREAT) == 0)
    return troe_fail(EINVAL);
  if (troe_host == NULL || troe_host->metadata == NULL)
    return troe_fail(EACCES);
  struct troe_host_metadata metadata;
  int probe = troe_host->metadata(troe_host->context,
                                  (const uint8_t *)resolved,
                                  strlen(resolved), 0, &metadata);
  int exists = probe == 0;
  if (!exists && troe_host_error(probe) != ENOENT)
    return troe_fail(troe_host_error(probe));
  if (exists && metadata.kind == TROE_NODE_DIRECTORY)
    return troe_fail(EISDIR);
  if (exists && (flags & O_EXCL) != 0)
    return troe_fail(EEXIST);
  if (!exists && (flags & O_CREAT) == 0)
    return troe_fail(ENOENT);
  if (exists && (flags & (O_TRUNC | O_APPEND)) == 0)
    return troe_fail(ENOTSUP);

  // A read-write descriptor reads back only what this replacement staged, so
  // rewinding and re-reading works while rewriting earlier bytes does not.
  if (access_mode == O_RDWR &&
      (troe_host == NULL || troe_host->replace_read == NULL))
    return troe_fail(ENOTSUP);

  int preserve = exists && (flags & O_APPEND) != 0 && (flags & O_TRUNC) == 0;
  int result = troe_begin_replacement(entry, resolved, preserve);
  if (result != 0)
    return troe_fail(result);
  if (preserve)
    entry->append = 1;
  if (access_mode == O_RDWR)
    entry->readable = 1;
  return descriptor;
}

int openat(int directory, const char *path, int flags, ...) {
  if (directory != AT_FDCWD)
    return troe_fail(ENOTSUP);
  return open(path, flags);
}

int close(int descriptor) {
  struct TroeDescriptor *entry = troe_descriptor(descriptor);
  if (entry == NULL)
    return -1;
  int result = 0;
  if (entry->kind == TROE_DESCRIPTOR_FILE) {
    if (troe_host == NULL || troe_host->file_close == NULL)
      result = EIO;
    else
      result = troe_host->file_close(troe_host->context, entry->token);
  } else if (entry->kind == TROE_DESCRIPTOR_REPLACEMENT) {
    if (troe_host == NULL || troe_host->replace_finish == NULL)
      result = EIO;
    else
      result = troe_host->replace_finish(troe_host->context, entry->token, 1);
  }
  memset(entry, 0, sizeof(*entry));
  return result == 0 ? 0 : troe_fail(troe_host_error(result));
}

ssize_t read(int descriptor, void *destination, size_t capacity) {
  struct TroeDescriptor *entry = troe_descriptor(descriptor);
  if (entry == NULL)
    return -1;
  if (!entry->readable)
    return (ssize_t)troe_fail(EBADF);
  if (capacity == 0)
    return 0;
  intptr_t count;
  if (entry->kind == TROE_DESCRIPTOR_INPUT) {
    if (troe_host == NULL || troe_host->stream_read == NULL)
      return (ssize_t)troe_fail(EACCES);
    count = troe_host->stream_read(troe_host->context, destination, capacity);
  } else if (entry->kind == TROE_DESCRIPTOR_FILE) {
    if (troe_host == NULL || troe_host->file_read == NULL)
      return (ssize_t)troe_fail(EACCES);
    count = troe_host->file_read(troe_host->context, entry->token,
                                 entry->position, destination, capacity);
  } else if (entry->kind == TROE_DESCRIPTOR_REPLACEMENT) {
    if (troe_host == NULL || troe_host->replace_read == NULL)
      return (ssize_t)troe_fail(EACCES);
    count = troe_host->replace_read(troe_host->context, entry->token,
                                    entry->position, destination, capacity);
  } else {
    return (ssize_t)troe_fail(EBADF);
  }
  if (count < 0 || (size_t)count > capacity)
    return (ssize_t)troe_fail(count < 0 ? troe_host_read_error(count) : EIO);
  entry->position += (uint64_t)count;
  return (ssize_t)count;
}

ssize_t write(int descriptor, const void *source, size_t length) {
  struct TroeDescriptor *entry = troe_descriptor(descriptor);
  if (entry == NULL)
    return -1;
  if (!entry->writable)
    return (ssize_t)troe_fail(EBADF);
  if (length == 0)
    return 0;
  if (entry->kind == TROE_DESCRIPTOR_OUTPUT) {
    if (troe_host == NULL || troe_host->stream_write == NULL)
      return (ssize_t)troe_fail(EACCES);
    int stream = descriptor == STDERR_FILENO ? 2 : 1;
    int result = troe_host->stream_write(troe_host->context, stream, source,
                                         length);
    if (result != 0)
      return (ssize_t)troe_fail(troe_host_error(result));
  } else if (entry->kind == TROE_DESCRIPTOR_REPLACEMENT) {
    if (troe_host == NULL || troe_host->replace_append == NULL)
      return (ssize_t)troe_fail(EACCES);
    // Staged bytes are immutable once written, so a rewound read-write
    // descriptor must return to the end before it can extend the stream.
    if (entry->position != entry->byte_count)
      return (ssize_t)troe_fail(ENOTSUP);
    int result = troe_host->replace_append(troe_host->context, entry->token,
                                           entry->position, source, length);
    if (result != 0)
      return (ssize_t)troe_fail(troe_host_error(result));
  } else {
    return (ssize_t)troe_fail(EBADF);
  }
  entry->position += length;
  if (entry->position > entry->byte_count)
    entry->byte_count = entry->position;
  return (ssize_t)length;
}

off_t lseek(int descriptor, off_t offset, int origin) {
  struct TroeDescriptor *entry = troe_descriptor(descriptor);
  if (entry == NULL)
    return -1;
  if (entry->kind != TROE_DESCRIPTOR_FILE &&
      entry->kind != TROE_DESCRIPTOR_REPLACEMENT)
    return (off_t)troe_fail(ESPIPE);
  uint64_t base;
  if (origin == SEEK_SET)
    base = 0;
  else if (origin == SEEK_CUR)
    base = entry->position;
  else if (origin == SEEK_END)
    base = entry->byte_count;
  else
    return (off_t)troe_fail(EINVAL);
  uint64_t target;
  if (offset < 0) {
    uint64_t magnitude = (uint64_t)(-(offset + 1)) + 1;
    if (magnitude > base)
      return (off_t)troe_fail(EINVAL);
    target = base - magnitude;
  } else if (__builtin_add_overflow(base, (uint64_t)offset, &target) ||
             target > (uint64_t)LONG_MAX) {
    return (off_t)troe_fail(EOVERFLOW);
  }
  // A write-only replacement stays strictly sequential. A read-write
  // replacement may seek anywhere it has already staged so that a caller can
  // rewind and re-read; writing still resumes only at the staged end.
  if (entry->kind == TROE_DESCRIPTOR_REPLACEMENT && target != entry->position &&
      (!entry->readable || target > entry->byte_count))
    return (off_t)troe_fail(ENOTSUP);
  entry->position = target;
  return (off_t)target;
}

static void troe_metadata_to_stat(const struct troe_host_metadata *source,
                                  struct stat *destination) {
  memset(destination, 0, sizeof(*destination));
  destination->st_dev = 1;
  destination->st_ino = source->identity;
  destination->st_nlink = 1;
  destination->st_size = source->byte_count > (uint64_t)LONG_MAX
                             ? LONG_MAX
                             : (off_t)source->byte_count;
  destination->st_blksize = TROE_FILE_BUFFER;
  destination->st_blocks = (blkcnt_t)((source->byte_count + 511U) / 512U);
  if (source->kind == TROE_NODE_FILE)
    destination->st_mode = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  else if (source->kind == TROE_NODE_DIRECTORY)
    destination->st_mode = S_IFDIR | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
                           S_IXGRP | S_IROTH | S_IXOTH;
  else
    destination->st_mode = S_IFLNK | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
}

static int troe_stat_path(const char *path, struct stat *metadata, int follow) {
  char resolved[TROE_PATH_BUFFER];
  if (metadata == NULL)
    return troe_fail(EFAULT);
  if (troe_resolve(path, resolved) != 0)
    return -1;
  if (troe_host == NULL || troe_host->metadata == NULL)
    return troe_fail(EACCES);
  struct troe_host_metadata result;
  int status = troe_host->metadata(troe_host->context,
                                   (const uint8_t *)resolved,
                                   strlen(resolved), follow, &result);
  if (status != 0)
    return troe_fail(troe_host_error(status));
  troe_metadata_to_stat(&result, metadata);
  return 0;
}

int stat(const char *path, struct stat *metadata) {
  return troe_stat_path(path, metadata, 1);
}

int lstat(const char *path, struct stat *metadata) {
  return troe_stat_path(path, metadata, 0);
}

int fstat(int descriptor, struct stat *metadata) {
  struct TroeDescriptor *entry = troe_descriptor(descriptor);
  if (entry == NULL)
    return -1;
  if (metadata == NULL)
    return troe_fail(EFAULT);
  if (entry->kind == TROE_DESCRIPTOR_INPUT ||
      entry->kind == TROE_DESCRIPTOR_OUTPUT) {
    memset(metadata, 0, sizeof(*metadata));
    metadata->st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    metadata->st_ino = (ino_t)(descriptor + 1);
    return 0;
  }
  return stat(entry->path, metadata);
}

int access(const char *path, int mode) {
  if ((mode & ~(R_OK | W_OK | X_OK)) != 0)
    return troe_fail(EINVAL);
  struct stat metadata;
  if (stat(path, &metadata) != 0)
    return -1;
  if ((mode & W_OK) != 0 &&
      (troe_host == NULL || troe_host->path_operation == NULL ||
       troe_host->replace_begin == NULL))
    return troe_fail(EACCES);
  if ((mode & X_OK) != 0)
    return troe_fail(EACCES);
  return 0;
}

int chdir(const char *path) {
  char resolved[TROE_PATH_BUFFER];
  if (troe_resolve(path, resolved) != 0)
    return -1;
  if (troe_host == NULL || troe_host->metadata == NULL)
    return troe_fail(EACCES);
  struct troe_host_metadata metadata;
  int result = troe_host->metadata(troe_host->context,
                                    (const uint8_t *)resolved,
                                    strlen(resolved), 1, &metadata);
  if (result != 0)
    return troe_fail(troe_host_error(result));
  if (metadata.kind != TROE_NODE_DIRECTORY)
    return troe_fail(ENOTDIR);
  strcpy(troe_cwd, resolved);
  return 0;
}

char *getcwd(char *destination, size_t capacity) {
  size_t length = strlen(troe_cwd) + 1;
  if (destination == NULL) {
    if (capacity != 0)
      return (errno = EINVAL, (char *)NULL);
    destination = malloc(length);
    if (destination == NULL)
      return NULL;
    capacity = length;
  }
  if (capacity < length) {
    errno = ERANGE;
    return NULL;
  }
  memcpy(destination, troe_cwd, length);
  return destination;
}

static int troe_path_operation(unsigned int operation, const char *first,
                               const char *second, int resolve_second) {
  if (troe_host == NULL || troe_host->path_operation == NULL)
    return troe_fail(EACCES);
  char first_path[TROE_PATH_BUFFER];
  char second_path[TROE_PATH_BUFFER];
  if (troe_resolve(first, first_path) != 0)
    return -1;
  const uint8_t *second_bytes = NULL;
  size_t second_length = 0;
  if (second != NULL) {
    if (resolve_second) {
      if (troe_resolve(second, second_path) != 0)
        return -1;
    } else {
      size_t length = strnlen(second, TROE_PATH_BUFFER);
      if (length == TROE_PATH_BUFFER)
        return troe_fail(ENAMETOOLONG);
      memcpy(second_path, second, length + 1);
    }
    second_bytes = (const uint8_t *)second_path;
    second_length = strlen(second_path);
  }
  int result = troe_host->path_operation(
      troe_host->context, operation, (const uint8_t *)first_path,
      strlen(first_path), second_bytes, second_length);
  return result == 0 ? 0 : troe_fail(troe_host_error(result));
}

int mkdir(const char *path, mode_t mode) {
  if ((mode & ~(S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP |
                S_IROTH | S_IWOTH | S_IXOTH)) != 0)
    return troe_fail(ENOTSUP);
  return troe_path_operation(TROE_PATH_MKDIR, path, NULL, 0);
}

int rmdir(const char *path) {
  return troe_path_operation(TROE_PATH_RMDIR, path, NULL, 0);
}

int unlink(const char *path) {
  return troe_path_operation(TROE_PATH_UNLINK, path, NULL, 0);
}

int link(const char *existing, const char *new_path) {
  return troe_path_operation(TROE_PATH_HARD_LINK, existing, new_path, 1);
}

int symlink(const char *target, const char *link_path) {
  /* The target remains lexical data; only the link location is cwd-resolved. */
  if (troe_host == NULL || troe_host->path_operation == NULL)
    return troe_fail(EACCES);
  size_t target_length = strnlen(target, TROE_PATH_BUFFER);
  if (target_length == 0 || target_length == TROE_PATH_BUFFER)
    return troe_fail(EINVAL);
  char resolved[TROE_PATH_BUFFER];
  if (troe_resolve(link_path, resolved) != 0)
    return -1;
  int result = troe_host->path_operation(
      troe_host->context, TROE_PATH_SYMLINK, (const uint8_t *)target,
      target_length, (const uint8_t *)resolved, strlen(resolved));
  return result == 0 ? 0 : troe_fail(troe_host_error(result));
}

int rename(const char *old_path, const char *new_path) {
  return troe_path_operation(TROE_PATH_RENAME, old_path, new_path, 1);
}

int remove(const char *path) {
  struct stat metadata;
  if (lstat(path, &metadata) != 0)
    return -1;
  return S_ISDIR(metadata.st_mode) ? rmdir(path) : unlink(path);
}

ssize_t readlink(const char *path, char *destination, size_t capacity) {
  char resolved[TROE_PATH_BUFFER];
  if (destination == NULL && capacity != 0)
    return (ssize_t)troe_fail(EFAULT);
  if (troe_resolve(path, resolved) != 0)
    return -1;
  if (troe_host == NULL || troe_host->read_link == NULL)
    return (ssize_t)troe_fail(EACCES);
  intptr_t result = troe_host->read_link(
      troe_host->context, (const uint8_t *)resolved, strlen(resolved),
      (uint8_t *)destination, capacity);
  if (result < 0 || (size_t)result > capacity)
    return (ssize_t)troe_fail(result < 0 ? troe_host_read_error(result) : EIO);
  return (ssize_t)result;
}

int chmod(const char *path, mode_t mode) {
  (void)path;
  (void)mode;
  return troe_fail(ENOTSUP);
}

int isatty(int descriptor) {
  if (troe_descriptor(descriptor) == NULL)
    return 0;
  if (descriptor >= 0 && descriptor <= 2)
    return 1;
  errno = ENOTTY;
  return 0;
}

pid_t getpid(void) { return 1; }

DIR *opendir(const char *path) {
  char resolved[TROE_PATH_BUFFER];
  if (troe_resolve(path, resolved) != 0)
    return NULL;
  if (troe_host == NULL || troe_host->metadata == NULL ||
      troe_host->directory_next == NULL) {
    errno = EACCES;
    return NULL;
  }
  struct troe_host_metadata metadata;
  int result = troe_host->metadata(troe_host->context,
                                    (const uint8_t *)resolved,
                                    strlen(resolved), 1, &metadata);
  if (result != 0) {
    errno = troe_host_error(result);
    return NULL;
  }
  if (metadata.kind != TROE_NODE_DIRECTORY) {
    errno = ENOTDIR;
    return NULL;
  }
  for (unsigned int index = 0; index < TROE_C_MAX_DIRECTORIES; ++index) {
    if (!troe_directories[index].used) {
      struct TroeDirectoryStream *directory = &troe_directories[index];
      memset(directory, 0, sizeof(*directory));
      directory->used = 1;
      strcpy(directory->path, resolved);
      return directory;
    }
  }
  errno = EMFILE;
  return NULL;
}

struct dirent *readdir(DIR *directory) {
  if (directory == NULL || !directory->used) {
    errno = EBADF;
    return NULL;
  }
  if (directory->cursor == UINT64_MAX)
    return NULL;
  uint32_t kind = 0;
  uint64_t next = 0;
  intptr_t count = troe_host->directory_next(
      troe_host->context, (const uint8_t *)directory->path,
      strlen(directory->path), directory->cursor,
      (uint8_t *)directory->entry.d_name, TROE_C_MAX_NAME_BYTES, &kind, &next);
  if (count < 0 || (size_t)count > TROE_C_MAX_NAME_BYTES) {
    errno = count < 0 ? troe_host_read_error(count) : EIO;
    return NULL;
  }
  if (count == 0)
    return NULL;
  directory->entry.d_name[count] = '\0';
  directory->entry.d_ino = next;
  directory->entry.d_type = kind == TROE_NODE_FILE
                                ? DT_REG
                                : kind == TROE_NODE_DIRECTORY ? DT_DIR : DT_LNK;
  directory->cursor = next;
  return &directory->entry;
}

int closedir(DIR *directory) {
  if (directory == NULL || !directory->used)
    return troe_fail(EBADF);
  memset(directory, 0, sizeof(*directory));
  return 0;
}

void rewinddir(DIR *directory) {
  if (directory != NULL && directory->used)
    directory->cursor = 0;
  else
    errno = EBADF;
}

long telldir(DIR *directory) {
  if (directory == NULL || !directory->used || directory->cursor > LONG_MAX)
    return troe_fail(directory == NULL || !directory->used ? EBADF : EOVERFLOW);
  return (long)directory->cursor;
}

void seekdir(DIR *directory, long position) {
  if (directory == NULL || !directory->used || position < 0)
    errno = EINVAL;
  else
    directory->cursor = (uint64_t)position;
}

int dirfd(DIR *directory) {
  (void)directory;
  errno = ENOTSUP;
  return -1;
}

static FILE *troe_file_slot(void) {
  for (unsigned int index = 0; index < TROE_FILE_SLOTS; ++index) {
    if (!troe_files[index].used) {
      FILE *file = &troe_files[index];
      memset(file, 0, sizeof(*file));
      file->used = 1;
      file->descriptor = -1;
      file->ungot = EOF;
      file->buffering = _IOFBF;
      file->buffer = file->internal;
      file->capacity = sizeof(file->internal);
      return file;
    }
  }
  errno = EMFILE;
  return NULL;
}

static int troe_parse_mode(const char *mode, int *flags) {
  if (mode == NULL || mode[0] == '\0')
    return EINVAL;
  int plus = 0;
  for (const char *cursor = mode + 1; *cursor != '\0'; ++cursor) {
    if (*cursor == '+') {
      if (plus)
        return EINVAL;
      plus = 1;
    } else if (*cursor != 'b' && *cursor != 'e') {
      return EINVAL;
    }
  }
  if (plus)
    return ENOTSUP;
  if (mode[0] == 'r')
    *flags = O_RDONLY;
  else if (mode[0] == 'w')
    *flags = O_WRONLY | O_CREAT | O_TRUNC;
  else if (mode[0] == 'a')
    *flags = O_WRONLY | O_CREAT | O_APPEND;
  else
    return EINVAL;
  return 0;
}

FILE *fdopen(int descriptor, const char *mode) {
  struct TroeDescriptor *entry = troe_descriptor(descriptor);
  if (entry == NULL)
    return NULL;
  int flags;
  int result = troe_parse_mode(mode, &flags);
  if (result != 0) {
    errno = result;
    return NULL;
  }
  if (((flags & O_ACCMODE) == O_RDONLY && !entry->readable) ||
      ((flags & O_ACCMODE) == O_WRONLY && !entry->writable)) {
    errno = EINVAL;
    return NULL;
  }
  FILE *file = troe_file_slot();
  if (file == NULL)
    return NULL;
  file->descriptor = descriptor;
  file->owns_descriptor = 1;
  return file;
}

FILE *fopen(const char *path, const char *mode) {
  int flags;
  int result = troe_parse_mode(mode, &flags);
  if (result != 0) {
    errno = result;
    return NULL;
  }
  int descriptor = open(path, flags, S_IRUSR | S_IWUSR);
  if (descriptor < 0)
    return NULL;
  FILE *file = troe_file_slot();
  if (file == NULL) {
    struct TroeDescriptor *entry = &troe_descriptors[descriptor];
    (void)troe_abort_descriptor(entry);
    return NULL;
  }
  file->descriptor = descriptor;
  file->owns_descriptor = 1;
  return file;
}

static int troe_file_flush_write(FILE *file) {
  if (file->direction != TROE_FILE_WRITING || file->buffered == 0)
    return 0;
  ssize_t count = write(file->descriptor, file->buffer, file->buffered);
  if (count < 0 || (size_t)count != file->buffered) {
    file->error = 1;
    if (count >= 0)
      errno = EIO;
    return EOF;
  }
  file->buffered = 0;
  return 0;
}

int fflush(FILE *file) {
  if (file == NULL) {
    int result = 0;
    for (unsigned int index = 0; index < TROE_FILE_SLOTS; ++index) {
      if (troe_files[index].used && troe_file_flush_write(&troe_files[index]) != 0)
        result = EOF;
    }
    for (unsigned int index = 0; index < 3; ++index) {
      if (troe_standard_files[index].used &&
          troe_file_flush_write(&troe_standard_files[index]) != 0)
        result = EOF;
    }
    return result;
  }
  if (!file->used)
    return troe_fail(EBADF);
  if (file->direction == TROE_FILE_READING && file->buffered > file->consumed) {
    size_t unread = file->buffered - file->consumed;
    if (lseek(file->descriptor, -(off_t)unread, SEEK_CUR) < 0) {
      file->error = 1;
      return EOF;
    }
    file->buffered = 0;
    file->consumed = 0;
  }
  return troe_file_flush_write(file);
}

int fclose(FILE *file) {
  if (file == NULL || !file->used)
    return troe_fail(EINVAL);
  int result = fflush(file);
  if (file->owns_descriptor && close(file->descriptor) != 0)
    result = EOF;
  memset(file, 0, sizeof(*file));
  return result;
}

FILE *freopen(const char *path, const char *mode, FILE *file) {
  if (file == NULL || !file->used) {
    errno = EINVAL;
    return NULL;
  }
  int flags;
  int result = troe_parse_mode(mode, &flags);
  if (result != 0) {
    errno = result;
    return NULL;
  }
  int descriptor = open(path, flags, S_IRUSR | S_IWUSR);
  if (descriptor < 0)
    return NULL;
  if (fflush(file) != 0) {
    (void)troe_abort_descriptor(&troe_descriptors[descriptor]);
    return NULL;
  }
  if (file->owns_descriptor && close(file->descriptor) != 0) {
    (void)troe_abort_descriptor(&troe_descriptors[descriptor]);
    return NULL;
  }
  unsigned char *buffer = file->buffer;
  size_t capacity = file->capacity;
  int buffering = file->buffering;
  unsigned int is_internal = buffer == file->internal;
  memset(file, 0, sizeof(*file));
  file->used = 1;
  file->owns_descriptor = 1;
  file->descriptor = descriptor;
  file->ungot = EOF;
  file->buffering = buffering;
  file->buffer = is_internal ? file->internal : buffer;
  file->capacity = capacity;
  return file;
}

void clearerr(FILE *file) {
  if (file != NULL && file->used) {
    file->error = 0;
    file->eof = 0;
  }
}

int feof(FILE *file) { return file != NULL && file->used ? file->eof : 0; }
int ferror(FILE *file) { return file != NULL && file->used ? file->error : 1; }

size_t fread(void *destination, size_t size, size_t count, FILE *file) {
  if (file == NULL || !file->used || (destination == NULL && size != 0 && count != 0)) {
    errno = EINVAL;
    return 0;
  }
  size_t wanted;
  if (__builtin_mul_overflow(size, count, &wanted)) {
    file->error = 1;
    errno = EOVERFLOW;
    return 0;
  }
  if (wanted == 0)
    return 0;
  if (file->direction == TROE_FILE_WRITING && troe_file_flush_write(file) != 0)
    return 0;
  file->direction = TROE_FILE_READING;
  unsigned char *output = destination;
  size_t copied = 0;
  if (file->ungot != EOF) {
    output[copied++] = (unsigned char)file->ungot;
    file->ungot = EOF;
  }
  while (copied < wanted) {
    if (file->consumed < file->buffered) {
      size_t available = file->buffered - file->consumed;
      size_t take = available < wanted - copied ? available : wanted - copied;
      memcpy(output + copied, file->buffer + file->consumed, take);
      file->consumed += take;
      copied += take;
      continue;
    }
    file->buffered = 0;
    file->consumed = 0;
    if (file->buffering == _IONBF) {
      ssize_t got = read(file->descriptor, output + copied, wanted - copied);
      if (got < 0) {
        file->error = 1;
        break;
      }
      if (got == 0) {
        file->eof = 1;
        break;
      }
      copied += (size_t)got;
      continue;
    }
    ssize_t got = read(file->descriptor, file->buffer, file->capacity);
    if (got < 0) {
      file->error = 1;
      break;
    }
    if (got == 0) {
      file->eof = 1;
      break;
    }
    file->buffered = (size_t)got;
  }
  return copied / size;
}

size_t fwrite(const void *source, size_t size, size_t count, FILE *file) {
  if (file == NULL || !file->used || (source == NULL && size != 0 && count != 0)) {
    errno = EINVAL;
    return 0;
  }
  size_t wanted;
  if (__builtin_mul_overflow(size, count, &wanted)) {
    file->error = 1;
    errno = EOVERFLOW;
    return 0;
  }
  if (wanted == 0)
    return 0;
  if (file->direction == TROE_FILE_READING && fflush(file) != 0)
    return 0;
  file->direction = TROE_FILE_WRITING;
  const unsigned char *input = source;
  size_t copied = 0;
  while (copied < wanted) {
    if (file->buffering == _IONBF) {
      ssize_t put = write(file->descriptor, input + copied, wanted - copied);
      if (put < 0) {
        file->error = 1;
        break;
      }
      copied += (size_t)put;
      continue;
    }
    if (file->buffered == file->capacity && troe_file_flush_write(file) != 0)
      break;
    size_t available = file->capacity - file->buffered;
    size_t take = available < wanted - copied ? available : wanted - copied;
    memcpy(file->buffer + file->buffered, input + copied, take);
    if (file->buffering == _IOLBF && memchr(input + copied, '\n', take) != NULL) {
      file->buffered += take;
      copied += take;
      if (troe_file_flush_write(file) != 0)
        break;
    } else {
      file->buffered += take;
      copied += take;
    }
  }
  return copied / size;
}

int fgetc(FILE *file) {
  unsigned char character;
  return fread(&character, 1, 1, file) == 1 ? (int)character : EOF;
}
int getc(FILE *file) { return fgetc(file); }
int getchar(void) { return fgetc(stdin); }

char *fgets(char *buffer, int size, FILE *file) {
  if (buffer == NULL || size <= 0) {
    errno = EINVAL;
    return NULL;
  }
  int offset = 0;
  while (offset + 1 < size) {
    int character = fgetc(file);
    if (character == EOF)
      break;
    buffer[offset++] = (char)character;
    if (character == '\n')
      break;
  }
  if (offset == 0)
    return NULL;
  buffer[offset] = '\0';
  return buffer;
}

int fputc(int character, FILE *file) {
  unsigned char byte = (unsigned char)character;
  return fwrite(&byte, 1, 1, file) == 1 ? (int)byte : EOF;
}
int putc(int character, FILE *file) { return fputc(character, file); }
int putchar(int character) { return fputc(character, stdout); }
int fputs(const char *text, FILE *file) {
  size_t length = strlen(text);
  return fwrite(text, 1, length, file) == length ? 0 : EOF;
}
int puts(const char *text) {
  return fputs(text, stdout) == 0 && fputc('\n', stdout) != EOF ? 0 : EOF;
}

int fseek(FILE *file, long offset, int origin) {
  if (file == NULL || !file->used)
    return troe_fail(EINVAL);
  if (fflush(file) != 0)
    return -1;
  if (lseek(file->descriptor, (off_t)offset, origin) < 0)
    return -1;
  file->direction = TROE_FILE_IDLE;
  file->buffered = 0;
  file->consumed = 0;
  file->ungot = EOF;
  file->eof = 0;
  return 0;
}

long ftell(FILE *file) {
  if (file == NULL || !file->used)
    return troe_fail(EINVAL);
  off_t position = lseek(file->descriptor, 0, SEEK_CUR);
  if (position < 0)
    return -1;
  if (file->direction == TROE_FILE_READING)
    position -= (off_t)(file->buffered - file->consumed);
  else if (file->direction == TROE_FILE_WRITING)
    position += (off_t)file->buffered;
  return (long)position;
}

int fgetpos(FILE *file, fpos_t *position) {
  if (position == NULL)
    return troe_fail(EINVAL);
  long result = ftell(file);
  if (result < 0)
    return -1;
  *position = (fpos_t)result;
  return 0;
}
int fsetpos(FILE *file, const fpos_t *position) {
  if (position == NULL)
    return troe_fail(EINVAL);
  return fseek(file, (long)*position, SEEK_SET);
}
void rewind(FILE *file) {
  if (fseek(file, 0, SEEK_SET) == 0)
    clearerr(file);
}
int fileno(FILE *file) {
  if (file == NULL || !file->used)
    return troe_fail(EBADF);
  return file->descriptor;
}

int setvbuf(FILE *file, char *buffer, int mode, size_t size) {
  if (file == NULL || !file->used || file->direction != TROE_FILE_IDLE ||
      (mode != _IOFBF && mode != _IOLBF && mode != _IONBF))
    return troe_fail(EINVAL);
  if (mode == _IONBF) {
    file->buffering = mode;
    file->buffer = file->internal;
    file->capacity = 1;
    return 0;
  }
  if (size == 0)
    return troe_fail(EINVAL);
  if (buffer == NULL) {
    if (size > sizeof(file->internal))
      return troe_fail(ENOTSUP);
    file->buffer = file->internal;
  } else {
    file->buffer = (unsigned char *)buffer;
  }
  file->capacity = size;
  file->buffering = mode;
  return 0;
}

void setbuf(FILE *file, char *buffer) {
  (void)setvbuf(file, buffer, buffer == NULL ? _IONBF : _IOFBF,
                buffer == NULL ? 1 : BUFSIZ);
}

int ungetc(int character, FILE *file) {
  if (file == NULL || !file->used || character == EOF || file->ungot != EOF ||
      file->direction == TROE_FILE_WRITING)
    return EOF;
  file->ungot = (unsigned char)character;
  file->eof = 0;
  return file->ungot;
}

int vfprintf(FILE *file, const char *format, va_list arguments) {
  va_list copy;
  va_copy(copy, arguments);
  int length = vsnprintf(NULL, 0, format, copy);
  va_end(copy);
  if (length < 0)
    return -1;
  size_t bytes = (size_t)length + 1;
  char local[256];
  char *buffer = bytes <= sizeof(local) ? local : malloc(bytes);
  if (buffer == NULL)
    return -1;
  int rendered = vsnprintf(buffer, bytes, format, arguments);
  int result = rendered == length &&
                       fwrite(buffer, 1, (size_t)length, file) == (size_t)length
                   ? length
                   : -1;
  if (buffer != local)
    free(buffer);
  return result;
}

int fprintf(FILE *file, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = vfprintf(file, format, arguments);
  va_end(arguments);
  return result;
}
int vprintf(const char *format, va_list arguments) {
  return vfprintf(stdout, format, arguments);
}
int printf(const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = vfprintf(stdout, format, arguments);
  va_end(arguments);
  return result;
}

int vfscanf(FILE *file, const char *format, va_list arguments) {
  if (file == NULL || format == NULL)
    return troe_fail(EINVAL);
  char input[BUFSIZ];
  size_t length = 0;
  int character = EOF;
  while (length + 1 < sizeof(input)) {
    character = fgetc(file);
    if (character == EOF || character == '\n')
      break;
    input[length++] = (char)character;
  }
  if (length + 1 == sizeof(input) && character != EOF && character != '\n')
    return troe_fail(EOVERFLOW);
  if (length == 0 && character == EOF)
    return EOF;
  input[length] = '\0';
  return vsscanf(input, format, arguments);
}

int fscanf(FILE *file, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  int result = vfscanf(file, format, arguments);
  va_end(arguments);
  return result;
}

FILE *tmpfile(void) {
  errno = ENOTSUP;
  return NULL;
}
FILE *popen(const char *command, const char *mode) {
  (void)command;
  (void)mode;
  errno = ENOTSUP;
  return NULL;
}
int pclose(FILE *file) {
  (void)file;
  return troe_fail(ENOTSUP);
}
int system(const char *command) {
  (void)command;
  return troe_fail(ENOTSUP);
}

int fflush_unlocked(FILE *file) { return fflush(file); }
int fgetc_unlocked(FILE *file) { return fgetc(file); }
int fputc_unlocked(int character, FILE *file) { return fputc(character, file); }
size_t fread_unlocked(void *destination, size_t size, size_t count, FILE *file) {
  return fread(destination, size, count, file);
}
size_t fwrite_unlocked(const void *source, size_t size, size_t count,
                       FILE *file) {
  return fwrite(source, size, count, file);
}

char *getenv(const char *name) {
  if (name == NULL || name[0] == '\0' || strchr(name, '=') != NULL ||
      environ == NULL)
    return NULL;
  size_t length = strlen(name);
  for (char **entry = environ; *entry != NULL; ++entry) {
    if (strncmp(*entry, name, length) == 0 && (*entry)[length] == '=')
      return *entry + length + 1;
  }
  return NULL;
}

int setenv(const char *name, const char *value, int overwrite) {
  (void)name;
  (void)value;
  (void)overwrite;
  return troe_fail(ENOTSUP);
}

int unsetenv(const char *name) {
  (void)name;
  return troe_fail(ENOTSUP);
}

int atexit(void (*function)(void)) {
  if (function == NULL)
    return -1;
  if (troe_atexit_count == TROE_C_MAX_ATEXIT) {
    errno = ENOMEM;
    return -1;
  }
  troe_atexit[troe_atexit_count++] = function;
  return 0;
}

time_t time(time_t *destination) {
  if (troe_host == NULL || troe_host->wall_time == NULL) {
    errno = EACCES;
    if (destination != NULL)
      *destination = (time_t)-1;
    return (time_t)-1;
  }
  uint64_t seconds = 0;
  int result = troe_host->wall_time(troe_host->context, &seconds);
  if (result != 0 || seconds > (uint64_t)LONG_MAX) {
    errno = result != 0 ? troe_host_error(result) : EOVERFLOW;
    if (destination != NULL)
      *destination = (time_t)-1;
    return (time_t)-1;
  }
  time_t value = (time_t)seconds;
  if (destination != NULL)
    *destination = value;
  return value;
}

static int troe_scale_ticks(uint64_t ticks, uint64_t frequency,
                            uint64_t target, uint64_t *result) {
  if (frequency == 0)
    return EIO;
  uint64_t whole = ticks / frequency;
  uint64_t remainder = ticks % frequency;
  uint64_t scaled_whole;
  uint64_t scaled_remainder;
  if (__builtin_mul_overflow(whole, target, &scaled_whole) ||
      __builtin_mul_overflow(remainder, target, &scaled_remainder) ||
      __builtin_add_overflow(scaled_whole, scaled_remainder / frequency,
                             result))
    return EOVERFLOW;
  return 0;
}

clock_t clock(void) {
  if (troe_host == NULL || troe_host->process_cpu_time == NULL) {
    errno = EACCES;
    return (clock_t)-1;
  }
  uint64_t ticks = 0;
  uint64_t frequency = 0;
  int result = troe_host->process_cpu_time(troe_host->context, &ticks,
                                           &frequency);
  uint64_t scaled = 0;
  if (result == 0)
    result = troe_scale_ticks(ticks, frequency, CLOCKS_PER_SEC, &scaled);
  if (result != 0 || scaled > (uint64_t)LONG_MAX) {
    errno = result != 0 ? troe_host_error(result) : EOVERFLOW;
    return (clock_t)-1;
  }
  return (clock_t)scaled;
}

int clock_gettime(clockid_t clock_id, struct timespec *destination) {
  if (destination == NULL)
    return troe_fail(EFAULT);
  if (clock_id == CLOCK_REALTIME) {
    time_t seconds = time(NULL);
    if (seconds == (time_t)-1)
      return -1;
    destination->tv_sec = seconds;
    destination->tv_nsec = 0;
    return 0;
  }
  uint64_t ticks = 0;
  uint64_t frequency = 0;
  int result;
  if (clock_id == CLOCK_MONOTONIC) {
    if (troe_host == NULL || troe_host->monotonic_time == NULL)
      return troe_fail(EACCES);
    result = troe_host->monotonic_time(troe_host->context, &ticks, &frequency);
  } else if (clock_id == CLOCK_PROCESS_CPUTIME_ID) {
    if (troe_host == NULL || troe_host->process_cpu_time == NULL)
      return troe_fail(EACCES);
    result = troe_host->process_cpu_time(troe_host->context, &ticks, &frequency);
  } else {
    return troe_fail(EINVAL);
  }
  if (result != 0)
    return troe_fail(troe_host_error(result));
  if (frequency == 0 || ticks / frequency > (uint64_t)LONG_MAX)
    return troe_fail(EOVERFLOW);
  destination->tv_sec = (time_t)(ticks / frequency);
  uint64_t nanoseconds = 0;
  result = troe_scale_ticks(ticks % frequency, frequency, 1000000000ULL,
                            &nanoseconds);
  if (result != 0)
    return troe_fail(result);
  destination->tv_nsec = (long)nanoseconds;
  return 0;
}

int nanosleep(const struct timespec *duration, struct timespec *remaining) {
  if (duration == NULL || duration->tv_sec < 0 || duration->tv_nsec < 0 ||
      duration->tv_nsec >= 1000000000L)
    return troe_fail(EINVAL);
  if (troe_host == NULL || troe_host->monotonic_time == NULL ||
      troe_host->sleep_until == NULL)
    return troe_fail(EACCES);
  uint64_t ticks = 0;
  uint64_t frequency = 0;
  int result = troe_host->monotonic_time(troe_host->context, &ticks, &frequency);
  if (result != 0)
    return troe_fail(troe_host_error(result));
  uint64_t now_ms = 0;
  result = troe_scale_ticks(ticks, frequency, 1000, &now_ms);
  uint64_t duration_ms;
  uint64_t seconds_ms;
  if (result != 0 ||
      __builtin_mul_overflow((uint64_t)duration->tv_sec, 1000ULL,
                             &seconds_ms) ||
      __builtin_add_overflow(seconds_ms,
                             ((uint64_t)duration->tv_nsec + 999999ULL) /
                                 1000000ULL,
                             &duration_ms) ||
      __builtin_add_overflow(now_ms, duration_ms, &duration_ms))
    return troe_fail(EOVERFLOW);
  result = troe_host->sleep_until(troe_host->context, duration_ms);
  if (result != 0) {
    if (remaining != NULL)
      *remaining = *duration;
    return troe_fail(troe_host_error(result));
  }
  if (remaining != NULL) {
    remaining->tv_sec = 0;
    remaining->tv_nsec = 0;
  }
  return 0;
}

unsigned int sleep(unsigned int seconds) {
  struct timespec duration = {(time_t)seconds, 0};
  struct timespec remaining = {0, 0};
  return nanosleep(&duration, &remaining) == 0
             ? 0
             : (unsigned int)remaining.tv_sec;
}

int usleep(unsigned int microseconds) {
  struct timespec duration = {(time_t)(microseconds / 1000000U),
                              (long)(microseconds % 1000000U) * 1000L};
  return nanosleep(&duration, NULL);
}

double difftime(time_t left, time_t right) { return (double)left - (double)right; }

static int64_t troe_floor_div(int64_t value, int64_t divisor) {
  int64_t quotient = value / divisor;
  int64_t remainder = value % divisor;
  return remainder < 0 ? quotient - 1 : quotient;
}

static void troe_civil_from_days(int64_t days, int *year, unsigned int *month,
                                 unsigned int *day) {
  days += 719468;
  int64_t era = troe_floor_div(days, 146097);
  unsigned int day_of_era = (unsigned int)(days - era * 146097);
  unsigned int year_of_era =
      (day_of_era - day_of_era / 1460 + day_of_era / 36524 -
       day_of_era / 146096) /
      365;
  int calculated_year = (int)year_of_era + (int)(era * 400);
  unsigned int day_of_year =
      day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  unsigned int march_month = (5 * day_of_year + 2) / 153;
  *day = day_of_year - (153 * march_month + 2) / 5 + 1;
  *month = march_month < 10 ? march_month + 3 : march_month - 9;
  calculated_year += *month <= 2;
  *year = calculated_year;
}

static int64_t troe_days_from_civil(int year, unsigned int month,
                                    unsigned int day) {
  year -= month <= 2;
  int64_t era = troe_floor_div(year, 400);
  unsigned int year_of_era = (unsigned int)(year - era * 400);
  unsigned int adjusted_month = month > 2 ? month - 3 : month + 9;
  unsigned int day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
  unsigned int day_of_era =
      year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  return era * 146097 + (int64_t)day_of_era - 719468;
}

struct tm *gmtime_r(const time_t *seconds, struct tm *destination) {
  if (seconds == NULL || destination == NULL) {
    errno = EFAULT;
    return NULL;
  }
  int64_t days = troe_floor_div(*seconds, 86400);
  int64_t day_seconds = (int64_t)*seconds - days * 86400;
  int year;
  unsigned int month;
  unsigned int day;
  troe_civil_from_days(days, &year, &month, &day);
  destination->tm_sec = (int)(day_seconds % 60);
  destination->tm_min = (int)((day_seconds / 60) % 60);
  destination->tm_hour = (int)(day_seconds / 3600);
  destination->tm_mday = (int)day;
  destination->tm_mon = (int)month - 1;
  destination->tm_year = year - 1900;
  destination->tm_wday = (int)((days + 4) % 7);
  if (destination->tm_wday < 0)
    destination->tm_wday += 7;
  destination->tm_yday =
      (int)(days - troe_days_from_civil(year, 1, 1));
  destination->tm_isdst = 0;
  destination->tm_gmtoff = 0;
  destination->tm_zone = "UTC";
  return destination;
}

struct tm *gmtime(const time_t *seconds) {
  static struct tm calendar;
  return gmtime_r(seconds, &calendar);
}
static void troe_copy_abbreviation(char *destination,
                                   const unsigned char *source,
                                   unsigned char length) {
  size_t count = length > TROE_ZONE_ABBREVIATION_BYTES
                     ? (size_t)TROE_ZONE_ABBREVIATION_BYTES
                     : (size_t)length;
  memcpy(destination, source, count);
  destination[count] = '\0';
}

void tzset(void) {
  if (troe_tz_ready)
    return;
  /* An absent or refused `TZ` reads as UTC. A launcher validates the value it
     composes, so a process only ever observes a string that already parsed. */
  troe_tz_text = getenv("TZ");
  troe_tz_length = troe_tz_text == NULL ? 0 : strlen(troe_tz_text);
  TroeRuntimeZoneSummary summary = troe_runtime_zone_summary(
      (const unsigned char *)troe_tz_text, troe_tz_length);
  troe_copy_abbreviation(troe_tz_standard, summary.standard,
                         summary.standard_length);
  troe_copy_abbreviation(troe_tz_daylight, summary.daylight,
                         summary.daylight_length);
  /* POSIX writes `timezone` west-positive; the runtime reports it east. */
  timezone = -(long)summary.standard_offset;
  daylight = summary.observes_daylight;
  troe_tz_ready = 1;
}

static struct tm *troe_fill_calendar(struct tm *destination,
                                     const TroeRuntimeCalendar *calendar) {
  destination->tm_sec = calendar->second;
  destination->tm_min = calendar->minute;
  destination->tm_hour = calendar->hour;
  destination->tm_mday = calendar->day;
  destination->tm_mon = calendar->month - 1;
  destination->tm_year = (int)(calendar->year - 1900);
  destination->tm_wday = calendar->week_day;
  destination->tm_yday = calendar->year_day;
  destination->tm_isdst = calendar->daylight;
  destination->tm_gmtoff = calendar->gmt_offset;
  destination->tm_zone = calendar->daylight ? tzname[1] : tzname[0];
  return destination;
}

struct tm *localtime_r(const time_t *seconds, struct tm *destination) {
  if (seconds == NULL || destination == NULL) {
    errno = EFAULT;
    return NULL;
  }
  tzset();
  TroeRuntimeCalendar calendar = troe_runtime_local_calendar_from_seconds(
      (const unsigned char *)troe_tz_text, troe_tz_length, (int64_t)*seconds);
  return troe_fill_calendar(destination, &calendar);
}

struct tm *localtime(const time_t *seconds) {
  static struct tm calendar;
  return localtime_r(seconds, &calendar);
}

time_t mktime(struct tm *calendar) {
  if (calendar == NULL) {
    errno = EFAULT;
    return (time_t)-1;
  }
  tzset();
  TroeRuntimeCalendar fields;
  memset(&fields, 0, sizeof(fields));
  fields.year = (int64_t)calendar->tm_year + 1900;
  fields.month = calendar->tm_mon + 1;
  fields.day = calendar->tm_mday;
  fields.hour = calendar->tm_hour;
  fields.minute = calendar->tm_min;
  fields.second = calendar->tm_sec;
  fields.daylight = calendar->tm_isdst;
  TroeRuntimeCalendarResult result = troe_runtime_normalize_local_calendar(
      (const unsigned char *)troe_tz_text, troe_tz_length, fields);
  if (result.status != 0) {
    errno = EOVERFLOW;
    return (time_t)-1;
  }
  troe_fill_calendar(calendar, &result.calendar);
  return (time_t)result.seconds;
}

time_t timegm(struct tm *calendar) {
  if (calendar == NULL) {
    errno = EFAULT;
    return (time_t)-1;
  }
  int64_t year = (int64_t)calendar->tm_year + 1900;
  int64_t month = calendar->tm_mon;
  year += troe_floor_div(month, 12);
  month -= troe_floor_div(month, 12) * 12;
  int64_t days = troe_days_from_civil((int)year, (unsigned int)month + 1, 1) +
                 (int64_t)calendar->tm_mday - 1;
  int64_t seconds;
  int64_t day_seconds = (int64_t)calendar->tm_hour * 3600 +
                        (int64_t)calendar->tm_min * 60 + calendar->tm_sec;
  if (__builtin_mul_overflow(days, 86400LL, &seconds) ||
      __builtin_add_overflow(seconds, day_seconds, &seconds)) {
    errno = EOVERFLOW;
    return (time_t)-1;
  }
  time_t result = (time_t)seconds;
  if (gmtime_r(&result, calendar) == NULL)
    return (time_t)-1;
  return result;
}

static int troe_strftime_append(char *destination, size_t capacity,
                                size_t *length, const char *text) {
  size_t count = strlen(text);
  if (count >= capacity - *length)
    return -1;
  memcpy(destination + *length, text, count);
  *length += count;
  return 0;
}

static int troe_strftime_number(char *destination, size_t capacity,
                                size_t *length, int value, int width) {
  char buffer[16];
  int count = snprintf(buffer, sizeof(buffer), "%0*d", width, value);
  return count < 0 ? -1
                   : troe_strftime_append(destination, capacity, length, buffer);
}

size_t strftime(char *destination, size_t capacity, const char *format,
                const struct tm *calendar) {
  static const char *weekdays[] = {"Sun", "Mon", "Tue", "Wed",
                                   "Thu", "Fri", "Sat"};
  static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  if (destination == NULL || format == NULL || calendar == NULL || capacity == 0)
    return 0;
  size_t length = 0;
  for (const char *cursor = format; *cursor != '\0'; ++cursor) {
    if (*cursor != '%') {
      char literal[2] = {*cursor, '\0'};
      if (troe_strftime_append(destination, capacity, &length, literal) != 0)
        return 0;
      continue;
    }
    ++cursor;
    int failed = 0;
    switch (*cursor) {
    case '%': failed = troe_strftime_append(destination, capacity, &length, "%"); break;
    case 'Y': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_year + 1900, 4); break;
    case 'm': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_mon + 1, 2); break;
    case 'd': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_mday, 2); break;
    case 'H': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_hour, 2); break;
    case 'M': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_min, 2); break;
    case 'S': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_sec, 2); break;
    case 'j': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_yday + 1, 3); break;
    case 'w': failed = troe_strftime_number(destination, capacity, &length, calendar->tm_wday, 1); break;
    case 'a': failed = calendar->tm_wday >= 0 && calendar->tm_wday < 7 ? troe_strftime_append(destination, capacity, &length, weekdays[calendar->tm_wday]) : -1; break;
    case 'b': failed = calendar->tm_mon >= 0 && calendar->tm_mon < 12 ? troe_strftime_append(destination, capacity, &length, months[calendar->tm_mon]) : -1; break;
    case 'z': {
      long offset = calendar->tm_gmtoff;
      long magnitude = offset < 0 ? -offset : offset;
      char buffer[16];
      int count = snprintf(buffer, sizeof(buffer), "%c%02ld%02ld",
                           offset < 0 ? '-' : '+', magnitude / 3600,
                           magnitude % 3600 / 60);
      failed = count < 0
                   ? -1
                   : troe_strftime_append(destination, capacity, &length, buffer);
      break;
    }
    case 'Z': failed = troe_strftime_append(destination, capacity, &length, calendar->tm_zone == NULL ? "" : calendar->tm_zone); break;
    default: return 0;
    }
    if (failed != 0)
      return 0;
  }
  destination[length] = '\0';
  return length;
}

int troe_getrandom(void *destination, size_t length, unsigned int flags) {
  if (flags != 0)
    return troe_fail(ENOTSUP);
  if (length != 0 && destination == NULL)
    return troe_fail(EFAULT);
  if (length == 0)
    return 0;
  if (troe_host == NULL || troe_host->random_bytes == NULL)
    return troe_fail(EACCES);
  int result = troe_host->random_bytes(troe_host->context, destination, length);
  return result == 0 ? 0 : troe_fail(troe_host_error(result));
}

ssize_t getrandom(void *destination, size_t length, unsigned int flags) {
  if (flags != 0 && flags != GRND_NONBLOCK)
    return (ssize_t)troe_fail(ENOTSUP);
  if (troe_getrandom(destination, length, 0) != 0)
    return -1;
  return (ssize_t)length;
}

void troe_assert_fail(const char *expression, const char *file, int line,
                      const char *function) {
  (void)fprintf(stderr, "assertion failed: %s (%s:%d %s)\n", expression, file,
                line, function);
  abort();
}

static void troe_initialize_file(FILE *file, int descriptor, int buffering) {
  memset(file, 0, sizeof(*file));
  file->used = 1;
  file->descriptor = descriptor;
  file->ungot = EOF;
  file->buffering = buffering;
  file->buffer = file->internal;
  file->capacity = sizeof(file->internal);
}

int troe_runtime_initialize(const struct troe_runtime_configuration *configuration) {
  if (troe_initialized || configuration == NULL || configuration->host == NULL ||
      configuration->host->abi != TROE_C_RUNTIME_ABI ||
      configuration->host->structure_bytes < sizeof(struct troe_runtime_host) ||
      configuration->argc < 0 ||
      (configuration->argc != 0 && configuration->argv == NULL)) {
    errno = EINVAL;
    return -1;
  }
  memset(troe_descriptors, 0, sizeof(troe_descriptors));
  memset(troe_directories, 0, sizeof(troe_directories));
  memset(troe_files, 0, sizeof(troe_files));
  memset(troe_atexit, 0, sizeof(troe_atexit));
  troe_atexit_count = 0;
  troe_host = configuration->host;
  __troe_argc = configuration->argc;
  __troe_argv = configuration->argv;
  environ = configuration->environment;
  strcpy(troe_cwd, "/");
  if (configuration->cwd != NULL) {
    int result = troe_resolve_path(configuration->cwd, troe_cwd);
    if (result != 0) {
      troe_host = NULL;
      errno = result;
      return -1;
    }
  }
  troe_descriptors[STDIN_FILENO].kind = TROE_DESCRIPTOR_INPUT;
  troe_descriptors[STDIN_FILENO].readable = 1;
  troe_descriptors[STDOUT_FILENO].kind = TROE_DESCRIPTOR_OUTPUT;
  troe_descriptors[STDOUT_FILENO].writable = 1;
  troe_descriptors[STDERR_FILENO].kind = TROE_DESCRIPTOR_OUTPUT;
  troe_descriptors[STDERR_FILENO].writable = 1;
  troe_initialize_file(&troe_standard_files[0], STDIN_FILENO, _IOFBF);
  troe_initialize_file(&troe_standard_files[1], STDOUT_FILENO, _IOLBF);
  troe_initialize_file(&troe_standard_files[2], STDERR_FILENO, _IONBF);
  stdin = &troe_standard_files[0];
  stdout = &troe_standard_files[1];
  stderr = &troe_standard_files[2];
  troe_initialized = 1;
  return 0;
}

void troe_runtime_finalize(void) {
  if (!troe_initialized)
    return;
  (void)fflush(NULL);
  for (unsigned int index = 0; index < TROE_FILE_SLOTS; ++index) {
    if (troe_files[index].used) {
      int descriptor = troe_files[index].descriptor;
      int owns = troe_files[index].owns_descriptor;
      (void)troe_file_flush_write(&troe_files[index]);
      memset(&troe_files[index], 0, sizeof(troe_files[index]));
      if (owns && descriptor >= 3 &&
          descriptor < (int)TROE_C_MAX_DESCRIPTORS)
        (void)close(descriptor);
    }
  }
  for (unsigned int descriptor = 3; descriptor < TROE_C_MAX_DESCRIPTORS;
       ++descriptor) {
    if (troe_descriptors[descriptor].kind != TROE_DESCRIPTOR_FREE)
      (void)close((int)descriptor);
  }
  memset(troe_directories, 0, sizeof(troe_directories));
  troe_runtime_run_tss_destructors();
  memset(troe_standard_files, 0, sizeof(troe_standard_files));
  memset(troe_descriptors, 0, sizeof(troe_descriptors));
  stdin = NULL;
  stdout = NULL;
  stderr = NULL;
  environ = NULL;
  __troe_argv = NULL;
  __troe_argc = 0;
  troe_atexit_count = 0;
  troe_initialized = 0;
  troe_host = NULL;
}

void _Exit(int status) {
  const struct troe_runtime_host *host = troe_host;
  if (host != NULL && host->terminate != NULL)
    host->terminate(host->context, (uint32_t)status);
  __builtin_trap();
}

void exit(int status) {
  while (troe_atexit_count != 0) {
    void (*function)(void) = troe_atexit[--troe_atexit_count];
    if (function != NULL)
      function();
  }
  const struct troe_runtime_host *host = troe_host;
  void *context = host != NULL ? host->context : NULL;
  troe_runtime_finalize();
  if (host != NULL && host->terminate != NULL)
    host->terminate(context, (uint32_t)status);
  __builtin_trap();
}

void abort(void) {
  const struct troe_runtime_host *host = troe_host;
  if (host != NULL && host->terminate != NULL)
    host->terminate(host->context, 134U);
  __builtin_trap();
}
