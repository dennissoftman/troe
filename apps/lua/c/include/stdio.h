#ifndef TROE_STDIO_H
#define TROE_STDIO_H

#include <stdarg.h>
#include <stddef.h>

typedef struct TroeFile FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

#define EOF (-1)
#define BUFSIZ 4096
#define L_tmpnam 20

int fclose(FILE *file);
int feof(FILE *file);
int ferror(FILE *file);
int fflush(FILE *file);
char *fgets(char *buffer, int size, FILE *file);
FILE *fopen(const char *path, const char *mode);
FILE *freopen(const char *path, const char *mode, FILE *file);
int fprintf(FILE *file, const char *format, ...);
int getc(FILE *file);
size_t fread(void *destination, size_t size, size_t count, FILE *file);
size_t fwrite(const void *source, size_t size, size_t count, FILE *file);
int remove(const char *path);
int rename(const char *old_path, const char *new_path);
int snprintf(char *buffer, size_t size, const char *format, ...);
int sprintf(char *buffer, const char *format, ...);
int vfprintf(FILE *file, const char *format, va_list arguments);
int vsnprintf(char *buffer, size_t size, const char *format, va_list arguments);

#endif
