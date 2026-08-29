#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

long timezone = 0;
int daylight = 0;
static char troe_utc[] = "UTC";
char *tzname[2] = {troe_utc, troe_utc};

void tzset(void) {}

int clock_getres(clockid_t clock_id, struct timespec *resolution) {
  if (resolution == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC &&
      clock_id != CLOCK_PROCESS_CPUTIME_ID) {
    errno = EINVAL;
    return -1;
  }
  resolution->tv_sec = 0;
  resolution->tv_nsec = 1;
  return 0;
}

clock_t times(struct tms *process) {
  clock_t current = clock();
  if (current == (clock_t)-1)
    return current;
  if (process != NULL) {
    process->tms_utime = current;
    process->tms_stime = 0;
    process->tms_cutime = 0;
    process->tms_cstime = 0;
  }
  return current;
}

int utime(const char *path, const time_t values[2]) {
  (void)path;
  (void)values;
  errno = ENOTSUP;
  return -1;
}

int fcntl(int descriptor, int command, ...) {
  (void)descriptor;
  switch (command) {
  case F_GETFD:
    return FD_CLOEXEC;
  case F_SETFD:
    return 0;
  case F_GETFL:
    return 0;
  case F_SETFL: {
    va_list arguments;
    va_start(arguments, command);
    int flags = va_arg(arguments, int);
    va_end(arguments);
    if ((flags & O_NONBLOCK) == 0)
      return 0;
    errno = ENOTSUP;
    return -1;
  }
  default:
    errno = ENOTSUP;
    return -1;
  }
}

int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                           const struct timespec *deadline) {
  (void)deadline;
  return pthread_cond_wait(condition, mutex);
}

_Noreturn void pthread_exit(void *result) {
  (void)result;
  abort();
}

int pause(void) {
  errno = ENOTSUP;
  return -1;
}

_Noreturn void _exit(int status) { exit(status); }

wchar_t *wcschr(const wchar_t *text, wchar_t value) {
  while (*text != value) {
    if (*text++ == L'\0')
      return NULL;
  }
  return (wchar_t *)text;
}

wchar_t *wcsrchr(const wchar_t *text, wchar_t value) {
  const wchar_t *last = NULL;
  do {
    if (*text == value)
      last = text;
  } while (*text++ != L'\0');
  return (wchar_t *)last;
}

wchar_t *wcsncpy(wchar_t *destination, const wchar_t *source, size_t size) {
  wchar_t *result = destination;
  while (size != 0 && *source != L'\0') {
    *destination++ = *source++;
    --size;
  }
  while (size-- != 0)
    *destination++ = L'\0';
  return result;
}

long wcstol(const wchar_t *text, wchar_t **end, int base) {
  const wchar_t *cursor = text;
  int negative = 0;
  unsigned long value = 0;
  while (*cursor == L' ' || (*cursor >= L'\t' && *cursor <= L'\r'))
    ++cursor;
  if (*cursor == L'+' || *cursor == L'-')
    negative = *cursor++ == L'-';
  if (base == 0)
    base = 10;
  const wchar_t *digits = cursor;
  while (*cursor >= L'0' && *cursor <= L'9' &&
         (int)(*cursor - L'0') < base) {
    value = value * (unsigned long)base + (unsigned long)(*cursor - L'0');
    ++cursor;
  }
  if (end != NULL)
    *end = (wchar_t *)(cursor == digits ? text : cursor);
  return negative ? -(long)value : (long)value;
}

wchar_t *wcstok(wchar_t *text, const wchar_t *delimiters, wchar_t **context) {
  wchar_t *cursor = text == NULL ? *context : text;
  if (cursor == NULL)
    return NULL;
  while (*cursor != L'\0' && wcschr(delimiters, *cursor) != NULL)
    ++cursor;
  if (*cursor == L'\0') {
    *context = cursor;
    return NULL;
  }
  wchar_t *token = cursor;
  while (*cursor != L'\0' && wcschr(delimiters, *cursor) == NULL)
    ++cursor;
  if (*cursor != L'\0')
    *cursor++ = L'\0';
  *context = cursor;
  return token;
}

int _PySignal_Init(int install_signal_handlers) {
  (void)install_signal_handlers;
  return 0;
}

void _PySignal_Fini(void) {}
int PyErr_CheckSignals(void) { return 0; }
int _PyErr_CheckSignals(void) { return 0; }
int _PyErr_CheckSignalsTstate(PyThreadState *thread_state) {
  (void)thread_state;
  return 0;
}
int PyErr_SetInterruptEx(int signal_number) {
  (void)signal_number;
  return -1;
}
int PyOS_InterruptOccurred(void) { return 0; }
int _PyOS_InterruptOccurred(PyThreadState *thread_state) {
  (void)thread_state;
  return 0;
}
PyStatus _PyFaulthandler_Init(int enable) {
  (void)enable;
  return PyStatus_Ok();
}
void _PyFaulthandler_Fini(void) {}
