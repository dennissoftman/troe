#ifndef TROE_CPYTHON_FCNTL_OVERLAY_H
#define TROE_CPYTHON_FCNTL_OVERLAY_H
#include_next <fcntl.h>
#define FD_CLOEXEC 1
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 0x8000
int fcntl(int descriptor, int command, ...);
#endif
