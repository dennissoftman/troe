#ifndef TROE_CPYTHON_SIGNAL_OVERLAY_H
#define TROE_CPYTHON_SIGNAL_OVERLAY_H
#include_next <signal.h>
#ifndef SIGINT
#define SIGINT 2
#endif
/* libmpdec's default trap handler raises SIGFPE. `_decimal` replaces that
   handler with its own before use, so the constant only has to exist. */
#ifndef SIGFPE
#define SIGFPE 8
#endif
#endif
