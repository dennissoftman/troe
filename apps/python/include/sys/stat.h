#ifndef TROE_CPYTHON_SYS_STAT_OVERLAY_H
#define TROE_CPYTHON_SYS_STAT_OVERLAY_H
#include_next <sys/stat.h>
#ifndef S_IFCHR
#define S_IFCHR 0020000U
#endif
#ifndef S_ISCHR
#define S_ISCHR(mode) (((mode) & S_IFMT) == S_IFCHR)
#endif
#endif
