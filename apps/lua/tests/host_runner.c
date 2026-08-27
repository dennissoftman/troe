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

struct TroeLuaHost {
  void *context;
  TroeAllocate allocate;
  TroeRead read;
  TroeWrite write;
  TroeProcessCpuTime process_cpu_time;
  TroeWallTime wall_time;
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
  };
  configuration = (TroeLuaConfiguration){
      .host = &host,
      .source_name = (const uint8_t *)"=(host unit test)",
      .source_name_length = 17,
      .arguments = arguments,
      .argument_count = argument_count,
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
