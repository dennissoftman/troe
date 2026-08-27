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

static const char *const troe_weekday_short[] = {"Sun", "Mon", "Tue", "Wed",
                                                 "Thu", "Fri", "Sat"};
static const char *const troe_weekday_long[] = {
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
    "Saturday"};
static const char *const troe_month_short[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
static const char *const troe_month_long[] = {
    "January", "February", "March",     "April",   "May",      "June",
    "July",    "August",   "September", "October", "November", "December"};

static int64_t troe_floor_divide(int64_t value, int64_t divisor) {
  int64_t quotient = value / divisor;
  int64_t remainder = value % divisor;
  return remainder < 0 ? quotient - 1 : quotient;
}

static int64_t troe_days_from_civil(int64_t year, int month, int day) {
  int64_t era;
  unsigned year_of_era;
  unsigned day_of_year;
  unsigned day_of_era;
  year -= month <= 2;
  era = troe_floor_divide(year, 400);
  year_of_era = (unsigned)(year - era * 400);
  day_of_year =
      (153u * (unsigned)(month + (month > 2 ? -3 : 9)) + 2u) / 5u +
      (unsigned)(day - 1);
  day_of_era = year_of_era * 365u + year_of_era / 4u - year_of_era / 100u +
               day_of_year;
  return era * 146097 + (int64_t)day_of_era - 719468;
}

static void troe_civil_from_days(int64_t days, int64_t *year, int *month,
                                 int *day) {
  int64_t era;
  unsigned day_of_era;
  unsigned year_of_era;
  int64_t parsed_year;
  unsigned day_of_year;
  unsigned month_prime;
  days += 719468;
  era = troe_floor_divide(days, 146097);
  day_of_era = (unsigned)(days - era * 146097);
  year_of_era =
      (day_of_era - day_of_era / 1460u + day_of_era / 36524u -
       day_of_era / 146096u) /
      365u;
  parsed_year = (int64_t)year_of_era + era * 400;
  day_of_year = day_of_era -
                (365u * year_of_era + year_of_era / 4u - year_of_era / 100u);
  month_prime = (5u * day_of_year + 2u) / 153u;
  *day = (int)(day_of_year - (153u * month_prime + 2u) / 5u + 1u);
  *month = (int)month_prime + (month_prime < 10u ? 3 : -9);
  *year = parsed_year + (*month <= 2);
}

static void troe_calendar_from_seconds(int64_t seconds,
                                       TroeCalendarTime *calendar) {
  int64_t days = troe_floor_divide(seconds, 86400);
  int64_t day_seconds = seconds - days * 86400;
  int week_day;
  troe_civil_from_days(days, &calendar->year, &calendar->month,
                       &calendar->day);
  calendar->hour = (int)(day_seconds / 3600);
  calendar->minute = (int)((day_seconds % 3600) / 60);
  calendar->second = (int)(day_seconds % 60);
  week_day = (int)((days + 4) % 7);
  if (week_day < 0)
    week_day += 7;
  calendar->week_day = week_day;
  calendar->year_day =
      (int)(days - troe_days_from_civil(calendar->year, 1, 1));
}

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
  int64_t month_zero = month - 1;
  int64_t month_years = troe_floor_divide(month_zero, 12);
  int normalized_month = (int)(month_zero - month_years * 12) + 1;
  int64_t days;
  int64_t value;
  int64_t component;
  if (__builtin_add_overflow(year, month_years, &year))
    luaL_error(state, "time result cannot be represented");
  days = troe_days_from_civil(year, normalized_month, 1);
  if (__builtin_add_overflow(days, day - 1, &days) ||
      __builtin_mul_overflow(days, (int64_t)86400, &value) ||
      __builtin_mul_overflow(hour, (int64_t)3600, &component) ||
      __builtin_add_overflow(value, component, &value) ||
      __builtin_mul_overflow(minute, (int64_t)60, &component) ||
      __builtin_add_overflow(value, component, &value) ||
      __builtin_add_overflow(value, second, &value)) {
    luaL_error(state, "time result cannot be represented");
    return;
  }
  *seconds = value;
  troe_calendar_from_seconds(value, normalized);
}

static void troe_add_number(luaL_Buffer *buffer, const char *format,
                            int64_t value) {
  char bytes[64];
  int count = snprintf(bytes, sizeof(bytes), format, (long long)value);
  if (count > 0)
    luaL_addlstring(buffer, bytes, (size_t)count);
}

static void troe_format_date(lua_State *state, luaL_Buffer *buffer,
                             const char *format, size_t length,
                             const TroeCalendarTime *calendar) {
  size_t index;
  for (index = 0; index < length; ++index) {
    char option;
    int hour12;
    if (format[index] != '%') {
      luaL_addchar(buffer, format[index]);
      continue;
    }
    if (++index == length)
      luaL_argerror(state, 1, "invalid conversion specifier at end of format");
    option = format[index];
    hour12 = calendar->hour % 12;
    if (hour12 == 0)
      hour12 = 12;
    switch (option) {
    case 'a': luaL_addstring(buffer, troe_weekday_short[calendar->week_day]); break;
    case 'A': luaL_addstring(buffer, troe_weekday_long[calendar->week_day]); break;
    case 'b': luaL_addstring(buffer, troe_month_short[calendar->month - 1]); break;
    case 'B': luaL_addstring(buffer, troe_month_long[calendar->month - 1]); break;
    case 'c':
      luaL_addstring(buffer, troe_weekday_short[calendar->week_day]);
      luaL_addchar(buffer, ' ');
      luaL_addstring(buffer, troe_month_short[calendar->month - 1]);
      troe_add_number(buffer, " %2lld", calendar->day);
      troe_add_number(buffer, " %02lld", calendar->hour);
      troe_add_number(buffer, ":%02lld", calendar->minute);
      troe_add_number(buffer, ":%02lld", calendar->second);
      troe_add_number(buffer, " %lld", calendar->year);
      break;
    case 'd': troe_add_number(buffer, "%02lld", calendar->day); break;
    case 'H': troe_add_number(buffer, "%02lld", calendar->hour); break;
    case 'I': troe_add_number(buffer, "%02lld", hour12); break;
    case 'j': troe_add_number(buffer, "%03lld", calendar->year_day + 1); break;
    case 'm': troe_add_number(buffer, "%02lld", calendar->month); break;
    case 'M': troe_add_number(buffer, "%02lld", calendar->minute); break;
    case 'p': luaL_addstring(buffer, calendar->hour < 12 ? "AM" : "PM"); break;
    case 'S': troe_add_number(buffer, "%02lld", calendar->second); break;
    case 'U':
      troe_add_number(buffer, "%02lld",
                      (calendar->year_day + 7 - calendar->week_day) / 7);
      break;
    case 'w': troe_add_number(buffer, "%lld", calendar->week_day); break;
    case 'W': {
      int monday_day = (calendar->week_day + 6) % 7;
      troe_add_number(buffer, "%02lld",
                      (calendar->year_day + 7 - monday_day) / 7);
      break;
    }
    case 'x':
      troe_add_number(buffer, "%02lld", calendar->month);
      troe_add_number(buffer, "/%02lld", calendar->day);
      troe_add_number(buffer, "/%02lld", calendar->year % 100);
      break;
    case 'X':
      troe_add_number(buffer, "%02lld", calendar->hour);
      troe_add_number(buffer, ":%02lld", calendar->minute);
      troe_add_number(buffer, ":%02lld", calendar->second);
      break;
    case 'y': troe_add_number(buffer, "%02lld", calendar->year % 100); break;
    case 'Y': troe_add_number(buffer, "%lld", calendar->year); break;
    case 'Z': luaL_addstring(buffer, "UTC"); break;
    case '%': luaL_addchar(buffer, '%'); break;
    default:
      luaL_argerror(state, 1,
                    lua_pushfstring(state, "invalid conversion specifier '%%%c'",
                                    option));
    }
  }
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
  troe_calendar_from_seconds(seconds, &calendar);
  if (format_length == 2 && format[0] == '*' && format[1] == 't') {
    lua_createtable(state, 0, 9);
    troe_set_calendar_fields(state, &calendar);
  } else {
    luaL_Buffer buffer;
    luaL_buffinit(state, &buffer);
    troe_format_date(state, &buffer, format, format_length, &calendar);
    luaL_pushresult(&buffer);
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
  if (lua_isnoneornil(state, 1)) {
    lua_pushboolean(state, 0);
    return 1;
  }
  (void)luaL_checkstring(state, 1);
  luaL_pushfail(state);
  lua_pushliteral(state, "exit");
  lua_pushinteger(state, 127);
  return 3;
}

static int troe_os_getenv(lua_State *state) {
  const char *name = luaL_checkstring(state, 1);
  if (strcmp(name, "PWD") == 0 && troe_active_configuration != NULL)
    lua_pushlstring(
        state, (const char *)troe_active_configuration->current_directory,
        troe_active_configuration->current_directory_length);
  else if (strcmp(name, "HOME") == 0)
    lua_pushliteral(state, "/");
  else if (strcmp(name, "PATH") == 0)
    lua_pushliteral(state, "/bin");
  else if (strcmp(name, "TMPDIR") == 0)
    lua_pushliteral(state, "/tmp");
  else if (strcmp(name, "SHELL") == 0)
    lua_pushliteral(state, "/bin/sh");
  else if (strcmp(name, "USER") == 0 || strcmp(name, "LOGNAME") == 0)
    lua_pushliteral(state, "root");
  else
    luaL_pushfail(state);
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
