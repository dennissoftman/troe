#ifndef TROE_SYS_STAT_H
#define TROE_SYS_STAT_H

#include <sys/types.h>

#define S_IFMT 0170000U
#define S_IFREG 0100000U
#define S_IFDIR 0040000U
#define S_IFLNK 0120000U
#define S_IRUSR 0000400U
#define S_IWUSR 0000200U
#define S_IXUSR 0000100U
#define S_IRGRP 0000040U
#define S_IWGRP 0000020U
#define S_IXGRP 0000010U
#define S_IROTH 0000004U
#define S_IWOTH 0000002U
#define S_IXOTH 0000001U
#define S_ISREG(mode) (((mode) & S_IFMT) == S_IFREG)
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#define S_ISLNK(mode) (((mode) & S_IFMT) == S_IFLNK)

struct timespec;
struct stat {
  dev_t st_dev;
  ino_t st_ino;
  mode_t st_mode;
  nlink_t st_nlink;
  uid_t st_uid;
  gid_t st_gid;
  dev_t st_rdev;
  off_t st_size;
  blksize_t st_blksize;
  blkcnt_t st_blocks;
  time_t st_atime;
  time_t st_mtime;
  time_t st_ctime;
};

int stat(const char *path, struct stat *metadata);
int lstat(const char *path, struct stat *metadata);
int fstat(int descriptor, struct stat *metadata);
int mkdir(const char *path, mode_t mode);
int chmod(const char *path, mode_t mode);

#endif
