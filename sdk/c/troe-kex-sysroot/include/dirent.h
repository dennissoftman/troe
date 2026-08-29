#ifndef TROE_DIRENT_H
#define TROE_DIRENT_H

#include <stdint.h>

#define DT_UNKNOWN 0
#define DT_REG 1
#define DT_DIR 2
#define DT_LNK 3

typedef struct TroeDirectoryStream DIR;
struct dirent {
  uint64_t d_ino;
  uint8_t d_type;
  char d_name[65];
};

DIR *opendir(const char *path);
struct dirent *readdir(DIR *directory);
int closedir(DIR *directory);
void rewinddir(DIR *directory);
long telldir(DIR *directory);
void seekdir(DIR *directory, long position);
int dirfd(DIR *directory);

#endif
