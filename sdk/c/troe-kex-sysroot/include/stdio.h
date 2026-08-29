#ifndef TROE_STDIO_H
#define TROE_STDIO_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct TroeFile FILE;
typedef off_t fpos_t;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

#define EOF (-1)
#define BUFSIZ 4096
#define FILENAME_MAX 256
#define L_tmpnam 64
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#define _IOFBF 0
#define _IOLBF 1
#define _IONBF 2

void clearerr(FILE *file);
int fclose(FILE *file);
int feof(FILE *file);
int ferror(FILE *file);
int fflush(FILE *file);
int fgetc(FILE *file);
int getc(FILE *file);
int getchar(void);
char *fgets(char *buffer, int size, FILE *file);
FILE *fopen(const char *path, const char *mode);
FILE *fdopen(int descriptor, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *file);
size_t fread(void *destination, size_t size, size_t count, FILE *file);
size_t fwrite(const void *source, size_t size, size_t count, FILE *file);
int fputc(int character, FILE *file);
int putc(int character, FILE *file);
int putchar(int character);
int fputs(const char *text, FILE *file);
int puts(const char *text);
int fseek(FILE *file, long offset, int origin);
long ftell(FILE *file);
int fgetpos(FILE *file, fpos_t *position);
int fsetpos(FILE *file, const fpos_t *position);
void rewind(FILE *file);
int fileno(FILE *file);
int setvbuf(FILE *file, char *buffer, int mode, size_t size);
void setbuf(FILE *file, char *buffer);
int ungetc(int character, FILE *file);
int remove(const char *path);
int rename(const char *old_path, const char *new_path);
int printf(const char *format, ...);
int fprintf(FILE *file, const char *format, ...);
int vprintf(const char *format, va_list arguments);
int vfprintf(FILE *file, const char *format, va_list arguments);
int snprintf(char *buffer, size_t size, const char *format, ...);
int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments);
int sprintf(char *buffer, const char *format, ...);
int vsscanf(const char *source, const char *format, va_list arguments);
int sscanf(const char *source, const char *format, ...);
int vfscanf(FILE *file, const char *format, va_list arguments);
int fscanf(FILE *file, const char *format, ...);
FILE *tmpfile(void);
FILE *popen(const char *command, const char *mode);
int pclose(FILE *file);
int fflush_unlocked(FILE *file);
int fgetc_unlocked(FILE *file);
int fputc_unlocked(int character, FILE *file);
size_t fread_unlocked(void *destination, size_t size, size_t count, FILE *file);
size_t fwrite_unlocked(const void *source, size_t size, size_t count, FILE *file);

#endif
