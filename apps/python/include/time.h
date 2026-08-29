#ifndef TROE_CPYTHON_TIME_OVERLAY_H
#define TROE_CPYTHON_TIME_OVERLAY_H
#include_next <time.h>
#include <sys/time.h>
#include <sys/times.h>
int clock_getres(clockid_t clock, struct timespec *resolution);
int utime(const char *path, const time_t times[2]);
void tzset(void);
extern long timezone;
extern int daylight;
extern char *tzname[2];
#endif
