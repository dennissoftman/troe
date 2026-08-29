#ifndef TROE_CPYTHON_SIGNAL_OVERLAY_H
#define TROE_CPYTHON_SIGNAL_OVERLAY_H
#include_next <signal.h>
#ifndef SIGINT
#define SIGINT 2
#endif
#endif
