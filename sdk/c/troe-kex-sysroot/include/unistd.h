#ifndef TROE_UNISTD_H
#define TROE_UNISTD_H

#include <stddef.h>
#include <sys/types.h>

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

int access(const char *path, int mode);
int chdir(const char *path);
int close(int descriptor);
ssize_t read(int descriptor, void *destination, size_t capacity);
ssize_t write(int descriptor, const void *source, size_t length);
off_t lseek(int descriptor, off_t offset, int origin);
char *getcwd(char *destination, size_t capacity);
int unlink(const char *path);
int rmdir(const char *path);
int link(const char *existing, const char *new_path);
int symlink(const char *target, const char *link_path);
ssize_t readlink(const char *path, char *destination, size_t capacity);
int isatty(int descriptor);
unsigned int sleep(unsigned int seconds);
int usleep(unsigned int microseconds);
pid_t getpid(void);

#endif
