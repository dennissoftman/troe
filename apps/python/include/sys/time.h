#ifndef TROE_CPYTHON_SYS_TIME_OVERLAY_H
#define TROE_CPYTHON_SYS_TIME_OVERLAY_H
#include <sys/types.h>
struct timeval {
  time_t tv_sec;
  long tv_usec;
};
#endif
