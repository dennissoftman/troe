#include <Python.h>
#include <stdio.h>

#ifndef TROE_CPYTHON_ARCHITECTURE
#error "TROE_CPYTHON_ARCHITECTURE is required"
#endif
#ifndef TROE_CPYTHON_VERSION
#error "TROE_CPYTHON_VERSION is required"
#endif
#ifndef TROE_CPYTHON_SERIES
#error "TROE_CPYTHON_SERIES is required"
#endif

#define TROE_CPYTHON_ROOT                                                     \
  "/vol/shared/cpython/v1/" TROE_CPYTHON_ARCHITECTURE
#define TROE_CPYTHON_HOME                                                     \
  TROE_CPYTHON_ROOT "/lib/python" TROE_CPYTHON_VERSION
#define TROE_CPYTHON_STDLIB                                                   \
  TROE_CPYTHON_HOME "/python" TROE_CPYTHON_SERIES
#define TROE_CPYTHON_EXECUTABLE                                               \
  TROE_CPYTHON_ROOT "/bin/python" TROE_CPYTHON_SERIES ".kex"
#define TROE_CPYTHON_PACKAGES "/vol/shared/cpython/v1/packages"
#define TROE_CPYTHON_SERIES_PACKAGES                                          \
  TROE_CPYTHON_PACKAGES "/python" TROE_CPYTHON_SERIES

typedef void (*troe_cpython_checkpoint)(void *context);

static int report_status(const char *stage, PyStatus status) {
  if (PyStatus_IsExit(status))
    return status.exitcode;
  fprintf(stderr, "python: %s failed: %s\n", stage,
          status.err_msg == NULL ? "unknown error" : status.err_msg);
  return 1;
}

static PyStatus set_path(PyConfig *config, wchar_t **field,
                         const char *value) {
  return PyConfig_SetBytesString(config, field, value);
}

static PyStatus append_path(PyConfig *config, const char *value) {
  wchar_t *decoded = Py_DecodeLocale(value, NULL);
  if (decoded == NULL)
    return PyStatus_NoMemory();
  PyStatus status = PyWideStringList_Append(&config->module_search_paths,
                                            decoded);
  PyMem_RawFree(decoded);
  return status;
}

// `site` is never imported: its search-path, per-user, and `.pth` behavior are
// exactly the ambient authority this port refuses. Only its two interactive
// conveniences are reproduced here, with no path effect of any kind.
static const char troe_cpython_quitters[] =
    "import builtins\n"
    "class _TroeQuitter:\n"
    "    def __init__(self, name):\n"
    "        self.name = name\n"
    "    def __repr__(self):\n"
    "        return f'Use {self.name}() or Ctrl-D (i.e. EOF) to exit'\n"
    "    def __call__(self, code=None):\n"
    "        raise SystemExit(code)\n"
    "builtins.exit = _TroeQuitter('exit')\n"
    "builtins.quit = _TroeQuitter('quit')\n"
    "del builtins, _TroeQuitter\n";

static int install_interactive_builtins(void) {
  PyObject *globals = PyDict_New();
  if (globals == NULL)
    return -1;
  PyObject *result =
      PyRun_String(troe_cpython_quitters, Py_file_input, globals, globals);
  Py_DECREF(globals);
  if (result == NULL)
    return -1;
  Py_DECREF(result);
  return 0;
}

int troe_cpython_run(int argc, char **argv, void *checkpoint_context,
                     troe_cpython_checkpoint checkpoint) {
  PyStatus status;
  PyPreConfig preconfig;
  PyPreConfig_InitIsolatedConfig(&preconfig);
  preconfig.utf8_mode = 1;
  preconfig.coerce_c_locale = 0;
  preconfig.coerce_c_locale_warn = 0;
  preconfig.configure_locale = 0;
  preconfig.use_environment = 0;
  status = Py_PreInitialize(&preconfig);
  if (PyStatus_Exception(status))
    return report_status("preinitialization", status);

  PyConfig config;
  PyConfig_InitIsolatedConfig(&config);
  config.isolated = 1;
  config.use_environment = 0;
  config.user_site_directory = 0;
  config.site_import = 0;
  config.write_bytecode = 0;
  config.install_signal_handlers = 0;
  config.faulthandler = 0;
  config.tracemalloc = 0;
  config.pathconfig_warnings = 0;
  config.safe_path = 1;
  config.parse_argv = 1;
  config.configure_c_stdio = 1;
  config.buffered_stdio = 1;
  config.module_search_paths_set = 1;

#define SET_PATH(field, value)                                                \
  do {                                                                        \
    status = set_path(&config, &config.field, value);                         \
    if (PyStatus_Exception(status)) {                                         \
      PyConfig_Clear(&config);                                                \
      return report_status("configuration", status);                        \
    }                                                                         \
  } while (0)

  SET_PATH(program_name, "python" TROE_CPYTHON_SERIES);
  SET_PATH(executable, TROE_CPYTHON_EXECUTABLE);
  SET_PATH(base_executable, TROE_CPYTHON_EXECUTABLE);
  SET_PATH(home, TROE_CPYTHON_HOME);
  SET_PATH(prefix, TROE_CPYTHON_HOME);
  SET_PATH(base_prefix, TROE_CPYTHON_HOME);
  SET_PATH(exec_prefix, TROE_CPYTHON_HOME);
  SET_PATH(base_exec_prefix, TROE_CPYTHON_HOME);
  SET_PATH(filesystem_encoding, "utf-8");
  SET_PATH(filesystem_errors, "surrogateescape");
  SET_PATH(stdio_encoding, "utf-8");
  SET_PATH(stdio_errors, "surrogateescape");
#undef SET_PATH

  status = append_path(&config, TROE_CPYTHON_STDLIB);
  if (!PyStatus_Exception(status))
    status = append_path(&config, TROE_CPYTHON_PACKAGES);
  if (!PyStatus_Exception(status))
    status = append_path(&config, TROE_CPYTHON_SERIES_PACKAGES);
  if (!PyStatus_Exception(status))
    status = PyConfig_SetBytesArgv(&config, argc, argv);
  if (PyStatus_Exception(status)) {
    PyConfig_Clear(&config);
    return report_status("configuration", status);
  }

  status = Py_InitializeFromConfig(&config);
  PyConfig_Clear(&config);
  if (PyStatus_Exception(status))
    return report_status("initialization", status);
  if (install_interactive_builtins() != 0) {
    PyErr_Print();
    Py_Finalize();
    return 1;
  }
  if (checkpoint != NULL)
    checkpoint(checkpoint_context);
  return Py_RunMain();
}
