#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct TroeCalendarTime {
  int64_t year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
  int week_day;
  int year_day;
} TroeCalendarTime;

typedef struct TroeCalendarResult {
  int status;
  int64_t seconds;
  TroeCalendarTime calendar;
} TroeCalendarResult;

typedef struct TroeFormatResult {
  size_t count;
  int status;
  int option;
} TroeFormatResult;

extern time_t timegm(struct tm *calendar);

TroeCalendarTime troe_runtime_calendar_from_seconds(int64_t seconds) {
  time_t value = (time_t)seconds;
  struct tm *calendar = gmtime(&value);
  if (calendar == NULL)
    return (TroeCalendarTime){0};
  return (TroeCalendarTime){
      .year = (int64_t)calendar->tm_year + 1900,
      .month = calendar->tm_mon + 1,
      .day = calendar->tm_mday,
      .hour = calendar->tm_hour,
      .minute = calendar->tm_min,
      .second = calendar->tm_sec,
      .week_day = calendar->tm_wday,
      .year_day = calendar->tm_yday,
  };
}

TroeCalendarResult troe_runtime_normalize_calendar(
    int64_t year, int64_t month, int64_t day, int64_t hour, int64_t minute,
    int64_t second) {
  struct tm calendar = {
      .tm_year = (int)(year - 1900),
      .tm_mon = (int)(month - 1),
      .tm_mday = (int)day,
      .tm_hour = (int)hour,
      .tm_min = (int)minute,
      .tm_sec = (int)second,
  };
  time_t seconds = timegm(&calendar);
  return (TroeCalendarResult){
      .status = 0,
      .seconds = (int64_t)seconds,
      .calendar = troe_runtime_calendar_from_seconds((int64_t)seconds),
  };
}

TroeFormatResult troe_runtime_format_calendar(
    TroeCalendarTime calendar, const uint8_t *format, size_t format_length,
    uint8_t *destination, size_t capacity) {
  char pattern[4097];
  struct tm value = {
      .tm_year = (int)(calendar.year - 1900),
      .tm_mon = calendar.month - 1,
      .tm_mday = calendar.day,
      .tm_hour = calendar.hour,
      .tm_min = calendar.minute,
      .tm_sec = calendar.second,
      .tm_wday = calendar.week_day,
      .tm_yday = calendar.year_day,
  };
  if (format_length == 0)
    return (TroeFormatResult){.count = 0, .status = 0, .option = 0};
  if (format_length >= sizeof(pattern))
    return (TroeFormatResult){.status = 3};
  memcpy(pattern, format, format_length);
  pattern[format_length] = '\0';
  size_t count = strftime((char *)destination, capacity, pattern, &value);
  return (TroeFormatResult){
      .count = count,
      .status = count == 0 ? 3 : 0,
      .option = 0,
  };
}

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
  int64_t argument_base;
  size_t script_argument_count;
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
  uint32_t seed;
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

static intptr_t host_environment_get(void *context, const uint8_t *name,
                                     size_t name_length,
                                     uint8_t *destination, size_t capacity) {
  static const char *const entries[] = {
      "HOME=/",       "PATH=/bin",   "TMPDIR=/tmp", "SHELL=/bin/sh",
      "USER=root",    "LOGNAME=root", "PWD=/",
  };
  (void)context;
  if (name_length == 12 && memcmp(name, "LUA_INIT_5_5", 12) == 0) {
    const char *initialization = getenv("TROE_TEST_LUA_INIT");
    if (initialization != NULL) {
      size_t value_length = strlen(initialization);
      if (value_length > capacity)
        return -75;
      memcpy(destination, initialization, value_length);
      return (intptr_t)value_length;
    }
  }
  for (size_t index = 0; index < sizeof(entries) / sizeof(entries[0]); ++index) {
    const char *separator = strchr(entries[index], '=');
    size_t entry_name_length = (size_t)(separator - entries[index]);
    size_t value_length = strlen(separator + 1);
    if (entry_name_length == name_length &&
        memcmp(entries[index], name, name_length) == 0) {
      if (value_length > capacity)
        return -75;
      memcpy(destination, separator + 1, value_length);
      return (intptr_t)value_length;
    }
  }
  return -2;
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

static int host_process_execute(void *context, const uint8_t *command,
                                size_t command_length, uint32_t *status) {
  (void)context;
  *status = command_length == 5 && memcmp(command, "false", 5) == 0 ? 1u : 0u;
  return 0;
}

static int host_unavailable_process_open(
    void *context, const uint8_t *command, size_t command_length, int mode,
    uint64_t *child_token, uint64_t *pipe_token, uint64_t *script_identifier) {
  (void)context; (void)command; (void)command_length; (void)mode;
  (void)child_token; (void)pipe_token; (void)script_identifier;
  return -1;
}

static intptr_t host_unavailable_process_read(void *context,
                                              uint64_t pipe_token,
                                              uint8_t *destination,
                                              size_t capacity) {
  (void)context; (void)pipe_token; (void)destination; (void)capacity;
  return -1;
}

static int host_unavailable_process_write(void *context, uint64_t pipe_token,
                                          const uint8_t *bytes,
                                          size_t length) {
  (void)context; (void)pipe_token; (void)bytes; (void)length;
  return -1;
}

static int host_unavailable_process_close(void *context, uint64_t child_token,
                                          uint64_t pipe_token,
                                          uint64_t script_identifier,
                                          int mode, uint32_t *status) {
  (void)context; (void)child_token; (void)pipe_token;
  (void)script_identifier; (void)mode; (void)status;
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
  argument_count = (size_t)argc;
  arguments = calloc(argument_count, sizeof(*arguments));
  if (arguments == NULL)
    return 2;
  arguments[0].bytes = (const uint8_t *)"lua";
  arguments[0].length = 3;
  arguments[1].bytes = (const uint8_t *)"host.lua";
  arguments[1].length = 8;
  for (size_t index = 2; index < argument_count; ++index) {
    arguments[index].bytes = (const uint8_t *)argv[index];
    arguments[index].length = strlen(argv[index]);
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
      .environment_get = host_environment_get,
      .read_input = host_unavailable_read,
      .file_open = host_unavailable_open,
      .file_read = host_unavailable_file_read,
      .file_close = host_unavailable_close,
      .file_replace = host_unavailable_replace,
      .file_remove = host_unavailable_path,
      .file_rename = host_unavailable_rename,
      .file_mutation_available = 0,
      .process_execute = host_process_execute,
      .process_open = host_unavailable_process_open,
      .process_read = host_unavailable_process_read,
      .process_write = host_unavailable_process_write,
      .process_close = host_unavailable_process_close,
      .process_available = 1,
  };
  configuration = (TroeLuaConfiguration){
      .host = &host,
      .source_name = (const uint8_t *)"=(host unit test)",
      .source_name_length = 17,
      .arguments = arguments,
      .argument_count = argument_count,
      .argument_base = -1,
      .script_argument_count = argument_count - 2,
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
      .seed = 0x5eed1234,
  };

  result = troe_lua_run(&configuration);
  fprintf(stderr,
          "\nTROE_TEST_RESULT result=%d requested=%d status=%u close=%d\n",
          result, configuration.requested_exit, configuration.requested_exit_status,
          configuration.requested_exit_close);
  free(arguments);
  return 0;
}
