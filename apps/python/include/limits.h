#ifndef TROE_CPYTHON_LIMITS_OVERLAY_H
#define TROE_CPYTHON_LIMITS_OVERLAY_H
#include_next <limits.h>
#ifndef SSIZE_MAX
#define SSIZE_MAX LONG_MAX
#endif
#endif
