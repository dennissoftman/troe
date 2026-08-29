#ifndef TROE_TIME_H
#define TROE_TIME_H

#include <stddef.h>
#include <sys/types.h>

#define CLOCKS_PER_SEC 1000000L
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2

typedef int clockid_t;
struct timespec { time_t tv_sec; long tv_nsec; };
struct tm {
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
};

time_t time(time_t *destination);
clock_t clock(void);
int clock_gettime(clockid_t clock, struct timespec *destination);
int nanosleep(const struct timespec *duration, struct timespec *remaining);
double difftime(time_t left, time_t right);
struct tm *gmtime(const time_t *seconds);
struct tm *gmtime_r(const time_t *seconds, struct tm *destination);
struct tm *localtime(const time_t *seconds);
struct tm *localtime_r(const time_t *seconds, struct tm *destination);
time_t mktime(struct tm *calendar);
size_t strftime(char *destination, size_t capacity, const char *format,
                const struct tm *calendar);

#endif
