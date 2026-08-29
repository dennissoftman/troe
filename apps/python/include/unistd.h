#ifndef TROE_CPYTHON_UNISTD_OVERLAY_H
#define TROE_CPYTHON_UNISTD_OVERLAY_H
#include_next <unistd.h>
int pause(void);
_Noreturn void _exit(int status);
#endif
