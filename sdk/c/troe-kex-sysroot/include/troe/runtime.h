#ifndef TROE_RUNTIME_H
#define TROE_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#define TROE_C_RUNTIME_ABI 1U
#define TROE_C_MAX_DESCRIPTORS 64U
#define TROE_C_MAX_DIRECTORIES 16U
#define TROE_C_MAX_ATEXIT 32U
#define TROE_C_MAX_TSS_KEYS 32U
#define TROE_C_MAX_PATH_BYTES 256U
#define TROE_C_MAX_NAME_BYTES 64U

enum troe_node_kind {
  TROE_NODE_FILE = 1,
  TROE_NODE_DIRECTORY = 2,
  TROE_NODE_SYMLINK = 3
};

struct troe_host_metadata {
  uint64_t byte_count;
  uint64_t identity;
  uint32_t kind;
  uint32_t reserved;
};

struct troe_runtime_host {
  uint32_t abi;
  uint32_t structure_bytes;
  void *context;
  void *(*allocate)(void *context, void *pointer, size_t size,
                    size_t alignment, int zeroed);
  intptr_t (*stream_read)(void *context, uint8_t *destination, size_t capacity);
  int (*stream_write)(void *context, int stream, const uint8_t *source,
                      size_t length);
  int (*file_open)(void *context, const uint8_t *path, size_t path_length,
                   uint32_t *token, uint64_t *byte_count);
  intptr_t (*file_read)(void *context, uint32_t token, uint64_t offset,
                        uint8_t *destination, size_t capacity);
  int (*file_close)(void *context, uint32_t token);
  int (*replace_begin)(void *context, const uint8_t *path, size_t path_length,
                       int preserve, uint32_t *token,
                       uint64_t *initial_offset);
  int (*replace_append)(void *context, uint32_t token, uint64_t offset,
                        const uint8_t *source, size_t length);
  int (*replace_finish)(void *context, uint32_t token, int commit);
  intptr_t (*replace_read)(void *context, uint32_t token, uint64_t offset,
                           uint8_t *destination, size_t capacity);
  int (*metadata)(void *context, const uint8_t *path, size_t path_length,
                  int follow, struct troe_host_metadata *metadata);
  intptr_t (*directory_next)(void *context, const uint8_t *path,
                             size_t path_length, uint64_t cursor,
                             uint8_t *name, size_t name_capacity,
                             uint32_t *kind, uint64_t *next_cursor);
  int (*path_operation)(void *context, uint32_t operation,
                        const uint8_t *first, size_t first_length,
                        const uint8_t *second, size_t second_length);
  intptr_t (*read_link)(void *context, const uint8_t *path,
                        size_t path_length, uint8_t *destination,
                        size_t capacity);
  int (*monotonic_time)(void *context, uint64_t *ticks,
                        uint64_t *frequency_hz);
  int (*process_cpu_time)(void *context, uint64_t *ticks,
                          uint64_t *frequency_hz);
  int (*wall_time)(void *context, uint64_t *seconds);
  int (*sleep_until)(void *context, uint64_t monotonic_milliseconds);
  int (*random_bytes)(void *context, uint8_t *destination, size_t length);
  void (*terminate)(void *context, uint32_t status) __attribute__((noreturn));
};

enum troe_path_operation {
  TROE_PATH_MKDIR = 1,
  TROE_PATH_RMDIR = 2,
  TROE_PATH_UNLINK = 3,
  TROE_PATH_RENAME = 4,
  TROE_PATH_SYMLINK = 5,
  TROE_PATH_HARD_LINK = 6
};

struct troe_runtime_configuration {
  const struct troe_runtime_host *host;
  int argc;
  char **argv;
  char **environment;
  const char *cwd;
};

int troe_runtime_initialize(const struct troe_runtime_configuration *configuration);
void troe_runtime_finalize(void);
int troe_getrandom(void *destination, size_t length, unsigned int flags);

_Static_assert(sizeof(void *) == 8, "TROE C ABI requires 64-bit pointers");
_Static_assert(sizeof(size_t) == 8, "TROE C ABI requires 64-bit size_t");
_Static_assert(sizeof(long) == 8, "TROE C ABI is LP64");
_Static_assert(sizeof(wchar_t) == 4, "TROE C ABI uses 32-bit wchar_t");
_Static_assert(sizeof(struct troe_host_metadata) == 24,
               "TROE host metadata layout changed");

#endif
