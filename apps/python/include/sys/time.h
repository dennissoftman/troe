#ifndef TROE_CPYTHON_SYS_TIME_OVERLAY_H
#define TROE_CPYTHON_SYS_TIME_OVERLAY_H
#include <sys/types.h>
struct timeval {
  time_t tv_sec;
  long tv_usec;
};

/* Expat's bundled configuration selects its poor-entropy hash salt, which
   needs this call. CPython overrides that salt with its own CSPRNG value
   through XML_SetHashSalt, so the value here is never security relevant. */
int gettimeofday(struct timeval *destination, void *timezone_unused);
#endif
