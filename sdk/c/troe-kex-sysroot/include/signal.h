#ifndef TROE_SIGNAL_H
#define TROE_SIGNAL_H

typedef int sig_atomic_t;
#define SIGABRT 6
#define SIG_DFL ((void (*)(int))0)
#define SIG_IGN ((void (*)(int))1)
#define SIG_ERR ((void (*)(int))-1)

void (*signal(int signal_number, void (*handler)(int)))(int);
int raise(int signal_number);

#endif
