#ifndef TROE_FCNTL_H
#define TROE_FCNTL_H

#include <sys/types.h>

#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR 0x0002
#define O_ACCMODE 0x0003
#define O_CREAT 0x0100
#define O_EXCL 0x0200
#define O_TRUNC 0x0400
#define O_APPEND 0x0800
#define O_CLOEXEC 0x1000
#define O_DIRECTORY 0x2000
#define O_NOFOLLOW 0x4000

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x01
#define AT_REMOVEDIR 0x02

int open(const char *path, int flags, ...);
int openat(int directory, const char *path, int flags, ...);

#endif
