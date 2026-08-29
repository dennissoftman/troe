#ifndef TROE_CPYTHON_PTHREAD_OVERLAY_H
#define TROE_CPYTHON_PTHREAD_OVERLAY_H
#include_next <pthread.h>
#include <time.h>
typedef struct { unsigned int state; } pthread_condattr_t;
int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex,
                           const struct timespec *deadline);
_Noreturn void pthread_exit(void *result);
#endif
