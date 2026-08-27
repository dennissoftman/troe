#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct HostContext {
  const uint8_t *source;
  size_t source_length;
  size_t source_offset;
  uint64_t cpu_ticks;
  uint64_t wall_seconds;
} HostContext;

int troe_lua_run(TroeLuaConfiguration *configuration);

static void *host_allocate(void *context, void *pointer, size_t old_size,
                           size_t new_size) {
  (void)context;
  (void)old_size;
  if (new_size == 0) {
    free(pointer);
    return NULL;
  }
  return realloc(pointer, new_size);
}

static intptr_t host_read(void *opaque, uint8_t *destination,
                          size_t capacity) {
  HostContext *context = (HostContext *)opaque;
  size_t remaining = context->source_length - context->source_offset;
  size_t count = remaining < capacity ? remaining : capacity;
  if (count != 0) {
    memcpy(destination, context->source + context->source_offset, count);
    context->source_offset += count;
  }
  return (intptr_t)count;
}

static int host_write(void *context, int stream, const uint8_t *bytes,
                      size_t length) {
  FILE *output;
  (void)context;
  output = stream == 1 ? stdout : (stream == 2 ? stderr : NULL);
  return output != NULL && fwrite(bytes, 1, length, output) == length ? 0 : -1;
}

static int host_process_cpu_time(void *opaque, uint64_t *ticks,
                                 uint64_t *frequency_hz) {
  HostContext *context = (HostContext *)opaque;
  *ticks = context->cpu_ticks;
  *frequency_hz = 1000;
  context->cpu_ticks += 1;
  return 0;
}

static int host_wall_time(void *opaque, uint64_t *seconds) {
  HostContext *context = (HostContext *)opaque;
  *seconds = context->wall_seconds;
  context->wall_seconds += 1;
  return 0;
}

static intptr_t host_unavailable_read(void *context, uint8_t *destination,
                                      size_t capacity) {
  (void)context;
  (void)destination;
  (void)capacity;
  return -1;
}

static int host_unavailable_open(void *context, const uint8_t *path,
                                 size_t path_length, uint32_t *token,
                                 uint64_t *length) {
  (void)context; (void)path; (void)path_length; (void)token; (void)length;
  return -1;
}

static intptr_t host_unavailable_file_read(void *context, uint32_t token,
                                           uint64_t length, uint64_t offset,
                                           uint8_t *destination,
                                           size_t capacity) {
  (void)context; (void)token; (void)length; (void)offset;
  (void)destination; (void)capacity;
  return -1;
}

static int host_unavailable_close(void *context, uint32_t token,
                                  uint64_t length) {
  (void)context; (void)token; (void)length;
  return -1;
}

static int host_unavailable_replace(void *context, const uint8_t *path,
                                    size_t path_length, const uint8_t *bytes,
                                    size_t length) {
  (void)context; (void)path; (void)path_length; (void)bytes; (void)length;
  return -1;
}

static int host_unavailable_path(void *context, const uint8_t *path,
                                 size_t path_length) {
  (void)context; (void)path; (void)path_length;
  return -1;
}

static int host_unavailable_rename(void *context, const uint8_t *old_path,
                                   size_t old_path_length,
                                   const uint8_t *new_path,
                                   size_t new_path_length) {
  (void)context; (void)old_path; (void)old_path_length;
  (void)new_path; (void)new_path_length;
  return -1;
}

int main(int argc, char **argv) {
  HostContext context;
  TroeLuaHost host;
  TroeLuaConfiguration configuration;
  TroeLuaArgument *arguments;
  size_t argument_count;
  int result;

  if (argc < 2) {
    fprintf(stderr, "usage: lua-host-runner CODE [ARG...]\n");
    return 2;
  }
  argument_count = (size_t)argc - 1;
  arguments = calloc(argument_count, sizeof(*arguments));
  if (arguments == NULL)
    return 2;
  arguments[0].bytes = (const uint8_t *)"lua";
  arguments[0].length = 3;
  for (size_t index = 1; index < argument_count; ++index) {
    arguments[index].bytes = (const uint8_t *)argv[index + 1];
    arguments[index].length = strlen(argv[index + 1]);
  }

  context = (HostContext){
      .source = (const uint8_t *)argv[1],
      .source_length = strlen(argv[1]),
      .source_offset = 0,
      .cpu_ticks = 0,
      .wall_seconds = 1700000000,
  };
  host = (TroeLuaHost){
      .context = &context,
      .allocate = host_allocate,
      .read = host_read,
      .write = host_write,
      .process_cpu_time = host_process_cpu_time,
      .wall_time = host_wall_time,
      .read_input = host_unavailable_read,
      .file_open = host_unavailable_open,
      .file_read = host_unavailable_file_read,
      .file_close = host_unavailable_close,
      .file_replace = host_unavailable_replace,
      .file_remove = host_unavailable_path,
      .file_rename = host_unavailable_rename,
      .file_mutation_available = 0,
  };
  configuration = (TroeLuaConfiguration){
      .host = &host,
      .source_name = (const uint8_t *)"=(host unit test)",
      .source_name_length = 17,
      .arguments = arguments,
      .argument_count = argument_count,
      .actions = NULL,
      .action_count = 0,
      .has_source = 1,
      .warnings_enabled = 0,
      .ignore_environment = 0,
      .current_directory = (const uint8_t *)"/",
      .current_directory_length = 1,
      .requested_exit = 0,
      .requested_exit_status = 0,
      .requested_exit_close = 0,
  };

  result = troe_lua_run(&configuration);
  fprintf(stderr,
          "\nTROE_TEST_RESULT result=%d requested=%d status=%u close=%d\n",
          result, configuration.requested_exit, configuration.requested_exit_status,
          configuration.requested_exit_close);
  free(arguments);
  return 0;
}
