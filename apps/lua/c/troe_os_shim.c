/*
** TROE's capability-aware shim for Lua's operating-system library.
**
** Keep the public table stable as implementations gain explicit KEX
** authority. Unsupported operations are callable and fail clearly instead
** of disappearing from the table or reaching the freestanding C stubs.
*/

static int troe_os_clock(lua_State *state) {
  uint64_t milliseconds;
  if (troe_active_host == NULL ||
      troe_active_host->monotonic_millis(troe_active_host->context,
                                         &milliseconds) != 0)
    return luaL_error(state, "os.clock is unavailable in TROE");
  lua_pushnumber(state, (lua_Number)milliseconds / 1000.0);
  return 1;
}

static int troe_os_difftime(lua_State *state) {
  lua_Integer left = luaL_checkinteger(state, 1);
  lua_Integer right = luaL_checkinteger(state, 2);
  lua_pushnumber(state, (lua_Number)left - (lua_Number)right);
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
    luaL_argcheck(state, requested >= 0 && (lua_Unsigned)requested <= UINT32_MAX,
                  1, "exit status is outside the TROE u32 range");
    status = (uint32_t)requested;
  }

  if (troe_active_configuration == NULL || !troe_exit_jump_active)
    return luaL_error(state, "os.exit is unavailable during Lua shutdown");
  troe_active_configuration->requested_exit = 1;
  troe_active_configuration->requested_exit_status = status;
  troe_active_configuration->requested_exit_close = lua_toboolean(state, 2);
  /* A Lua error unwind would run <close> variables even when close is false. */
  if (!troe_active_configuration->requested_exit_close)
    longjmp(troe_unclosed_exit_jump, 1);
  /* Keep Lua's handler chain valid when the caller requests state closing. */
  exit_state = mainthread(G(state));
  lua_pushliteral(exit_state, "TROE os.exit");
  luaD_throwbaselevel(exit_state, LUA_ERRRUN);
}

#define TROE_OS_UNAVAILABLE(name)                                           \
  static int troe_os_##name(lua_State *state) {                            \
    return luaL_error(state, "os." #name " is unavailable in TROE");       \
  }

TROE_OS_UNAVAILABLE(date)
TROE_OS_UNAVAILABLE(execute)
TROE_OS_UNAVAILABLE(getenv)
TROE_OS_UNAVAILABLE(remove)
TROE_OS_UNAVAILABLE(rename)
TROE_OS_UNAVAILABLE(setlocale)
TROE_OS_UNAVAILABLE(time)
TROE_OS_UNAVAILABLE(tmpname)

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
