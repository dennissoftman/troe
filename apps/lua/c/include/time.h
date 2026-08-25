#ifndef TROE_TIME_H
#define TROE_TIME_H

typedef long time_t;
typedef long clock_t;

#define CLOCKS_PER_SEC 1000000L

time_t time(time_t *destination);

#endif
