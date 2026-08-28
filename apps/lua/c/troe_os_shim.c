/* Capability-aware Lua 5.5 operating-system library for TROE. */

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

extern TroeCalendarTime troe_runtime_calendar_from_seconds(int64_t seconds);
extern TroeCalendarResult troe_runtime_normalize_calendar(
    int64_t year, int64_t month, int64_t day, int64_t hour, int64_t minute,
    int64_t second);
extern TroeFormatResult troe_runtime_format_calendar(
    TroeCalendarTime calendar, const uint8_t *format, size_t format_length,
    uint8_t *destination, size_t capacity);

static int troe_current_time(lua_State *state, int64_t *seconds) {
  uint64_t wall_seconds;
  if (troe_active_host == NULL ||
      troe_active_host->wall_time(troe_active_host->context, &wall_seconds) !=
          0)
    return luaL_error(state, "wall clock is unavailable in TROE");
  if (wall_seconds > INT64_MAX)
    return luaL_error(state, "wall-clock value is out of range");
  *seconds = (int64_t)wall_seconds;
  return 0;
}

static void troe_set_integer_field(lua_State *state, const char *name,
                                   lua_Integer value) {
  lua_pushinteger(state, value);
  lua_setfield(state, -2, name);
}

static void troe_set_calendar_fields(lua_State *state,
                                     const TroeCalendarTime *calendar) {
  troe_set_integer_field(state, "year", (lua_Integer)calendar->year);
  troe_set_integer_field(state, "month", calendar->month);
  troe_set_integer_field(state, "day", calendar->day);
  troe_set_integer_field(state, "hour", calendar->hour);
  troe_set_integer_field(state, "min", calendar->minute);
  troe_set_integer_field(state, "sec", calendar->second);
  troe_set_integer_field(state, "wday", calendar->week_day + 1);
  troe_set_integer_field(state, "yday", calendar->year_day + 1);
  lua_pushboolean(state, 0);
  lua_setfield(state, -2, "isdst");
}

static lua_Integer troe_get_time_field(lua_State *state, const char *name,
                                       lua_Integer default_value,
                                       int required) {
  int is_integer;
  lua_Integer result;
  int field_type = lua_getfield(state, 1, name);
  result = lua_tointegerx(state, -1, &is_integer);
  if (!is_integer) {
    if (field_type != LUA_TNIL)
      luaL_error(state, "field '%s' is not an integer", name);
    if (required)
      luaL_error(state, "field '%s' missing in date table", name);
    result = default_value;
  }
  lua_pop(state, 1);
  return result;
}

static void troe_seconds_from_table(lua_State *state, int64_t *seconds,
                                    TroeCalendarTime *normalized) {
  int64_t year = (int64_t)troe_get_time_field(state, "year", 0, 1);
  int64_t month = (int64_t)troe_get_time_field(state, "month", 0, 1);
  int64_t day = (int64_t)troe_get_time_field(state, "day", 0, 1);
  int64_t hour = (int64_t)troe_get_time_field(state, "hour", 12, 0);
  int64_t minute = (int64_t)troe_get_time_field(state, "min", 0, 0);
  int64_t second = (int64_t)troe_get_time_field(state, "sec", 0, 0);
  TroeCalendarResult result = troe_runtime_normalize_calendar(
      year, month, day, hour, minute, second);
  if (result.status != 0) {
    luaL_error(state, "time result cannot be represented");
    return;
  }
  *seconds = result.seconds;
  *normalized = result.calendar;
}

static int troe_os_clock(lua_State *state) {
  uint64_t ticks;
  uint64_t frequency_hz;
  if (troe_active_host == NULL ||
      troe_active_host->process_cpu_time(troe_active_host->context, &ticks,
                                         &frequency_hz) != 0 ||
      frequency_hz == 0)
    return luaL_error(state, "os.clock is unavailable in TROE");
  lua_pushnumber(state, (lua_Number)ticks / (lua_Number)frequency_hz);
  return 1;
}

static int troe_os_date(lua_State *state) {
  uint8_t formatted[4096];
  size_t format_length;
  const char *format = luaL_optlstring(state, 1, "%c", &format_length);
  int64_t seconds;
  TroeCalendarTime calendar;
  if (lua_isnoneornil(state, 2))
    troe_current_time(state, &seconds);
  else
    seconds = (int64_t)luaL_checkinteger(state, 2);
  if (format_length != 0 && format[0] == '!') {
    ++format;
    --format_length;
  }
  calendar = troe_runtime_calendar_from_seconds(seconds);
  if (format_length == 2 && format[0] == '*' && format[1] == 't') {
    lua_createtable(state, 0, 9);
    troe_set_calendar_fields(state, &calendar);
  } else {
    TroeFormatResult result = troe_runtime_format_calendar(
        calendar, (const uint8_t *)format, format_length, formatted,
        sizeof(formatted));
    if (result.status == 2) {
      if (result.option == 0)
        luaL_argerror(state, 1,
                      "invalid conversion specifier at end of format");
      luaL_argerror(
          state, 1,
          lua_pushfstring(state, "invalid conversion specifier '%%%c'",
                          result.option));
    }
    if (result.status != 0)
      luaL_error(state, "formatted date exceeds TROE runtime limit");
    lua_pushlstring(state, (const char *)formatted, result.count);
  }
  return 1;
}

static int troe_os_time(lua_State *state) {
  int64_t seconds;
  if (lua_isnoneornil(state, 1))
    troe_current_time(state, &seconds);
  else {
    TroeCalendarTime normalized;
    luaL_checktype(state, 1, LUA_TTABLE);
    lua_settop(state, 1);
    troe_seconds_from_table(state, &seconds, &normalized);
    troe_set_calendar_fields(state, &normalized);
  }
  lua_pushinteger(state, (lua_Integer)seconds);
  return 1;
}

static int troe_os_difftime(lua_State *state) {
  lua_Integer left = luaL_checkinteger(state, 1);
  lua_Integer right = luaL_checkinteger(state, 2);
  lua_pushnumber(state, (lua_Number)left - (lua_Number)right);
  return 1;
}

static int troe_os_execute(lua_State *state) {
  const char *command;
  size_t command_length;
  uint32_t status;
  if (lua_isnoneornil(state, 1)) {
    lua_pushboolean(state, troe_active_host != NULL &&
                               troe_active_host->process_available);
    return 1;
  }
  command = luaL_checklstring(state, 1, &command_length);
  int result;
  if (troe_active_host == NULL || !troe_active_host->process_available) {
    errno = EINVAL;
    return luaL_fileresult(state, 0, command);
  }
  result = troe_active_host->process_execute(
      troe_active_host->context, (const uint8_t *)command, command_length,
      &status);
  if (result != 0) {
    errno = result;
    return luaL_fileresult(state, 0, command);
  }
  if (status == 0)
    lua_pushboolean(state, 1);
  else
    luaL_pushfail(state);
  lua_pushliteral(state, "exit");
  lua_pushinteger(state, (lua_Integer)status);
  return 3;
}

static int troe_os_getenv(lua_State *state) {
  uint8_t value[2048];
  size_t name_length;
  const char *name = luaL_checklstring(state, 1, &name_length);
  intptr_t length;
  if (troe_active_host == NULL) {
    luaL_pushfail(state);
    return 1;
  }
  length = troe_active_host->environment_get(
      troe_active_host->context, (const uint8_t *)name, name_length, value,
      sizeof(value));
  if (length < 0)
    luaL_pushfail(state);
  else
    lua_pushlstring(state, (const char *)value, (size_t)length);
  return 1;
}

static int troe_os_remove(lua_State *state) {
  const char *path = luaL_checkstring(state, 1);
  errno = 0;
  return luaL_fileresult(state, remove(path) == 0, path);
}

static int troe_os_rename(lua_State *state) {
  const char *old_path = luaL_checkstring(state, 1);
  const char *new_path = luaL_checkstring(state, 2);
  errno = 0;
  return luaL_fileresult(state, rename(old_path, new_path) == 0, NULL);
}

static int troe_os_setlocale(lua_State *state) {
  static const char *const categories[] = {"all",      "collate", "ctype",
                                           "monetary", "numeric", "time",
                                           NULL};
  const char *locale = luaL_optstring(state, 1, NULL);
  (void)luaL_checkoption(state, 2, "all", categories);
  if (locale == NULL || locale[0] == '\0' || strcmp(locale, "C") == 0 ||
      strcmp(locale, "POSIX") == 0)
    lua_pushliteral(state, "C");
  else
    luaL_pushfail(state);
  return 1;
}

static int troe_os_tmpname(lua_State *state) {
  static uint32_t counter;
  uint64_t wall = 0;
  char name[48];
  if (troe_active_host != NULL)
    (void)troe_active_host->wall_time(troe_active_host->context, &wall);
  ++counter;
  (void)snprintf(name, sizeof(name), "/tmp/lua_%llx_%x",
                 (unsigned long long)wall, counter);
  lua_pushstring(state, name);
  return 1;
}

static int troe_os_exit(lua_State *state) {
  lua_State *exit_state;
  lua_Integer requested;
  uint32_t status;
  if (lua_isboolean(state, 1))
    status = lua_toboolean(state, 1) ? 0u : 1u;
  else {
    requested = luaL_optinteger(state, 1, 0);
    status = (uint32_t)((lua_Unsigned)requested & 0xffu);
  }
  if (troe_active_configuration == NULL || !troe_exit_jump_active)
    return luaL_error(state, "os.exit is unavailable during Lua shutdown");
  troe_active_configuration->requested_exit = 1;
  troe_active_configuration->requested_exit_status = status;
  troe_active_configuration->requested_exit_close = lua_toboolean(state, 2);
  if (!troe_active_configuration->requested_exit_close)
    longjmp(troe_unclosed_exit_jump, 1);
  exit_state = mainthread(G(state));
  lua_pushliteral(exit_state, "TROE os.exit");
  luaD_throwbaselevel(exit_state, LUA_ERRRUN);
}

static const luaL_Reg troe_os_functions[] = {
    {"clock", troe_os_clock},         {"date", troe_os_date},
    {"difftime", troe_os_difftime},   {"execute", troe_os_execute},
    {"exit", troe_os_exit},           {"getenv", troe_os_getenv},
    {"remove", troe_os_remove},       {"rename", troe_os_rename},
    {"setlocale", troe_os_setlocale}, {"time", troe_os_time},
    {"tmpname", troe_os_tmpname},     {NULL, NULL},
};

static int troe_luaopen_os(lua_State *state) {
  luaL_newlib(state, troe_os_functions);
  return 1;
}
