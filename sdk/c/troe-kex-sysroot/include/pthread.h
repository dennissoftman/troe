#ifndef TROE_PTHREAD_H
#define TROE_PTHREAD_H

#include <stddef.h>
#include <stdint.h>

typedef uintptr_t pthread_t;
typedef unsigned int pthread_key_t;
typedef struct { unsigned int state; } pthread_mutex_t;
typedef struct { unsigned int state; } pthread_cond_t;
typedef struct { unsigned int state; } pthread_once_t;
typedef struct { unsigned int unsupported; } pthread_attr_t;
typedef struct { unsigned int unsupported; } pthread_mutexattr_t;

#define PTHREAD_MUTEX_INITIALIZER {0}
#define PTHREAD_COND_INITIALIZER {0}
#define PTHREAD_ONCE_INIT {0}

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                   void *(*entry)(void *), void *argument);
int pthread_join(pthread_t thread, void **result);
int pthread_detach(pthread_t thread);
pthread_t pthread_self(void);
int pthread_equal(pthread_t left, pthread_t right);
int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *attributes);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_cond_init(pthread_cond_t *condition, const void *attributes);
int pthread_cond_destroy(pthread_cond_t *condition);
int pthread_cond_wait(pthread_cond_t *condition, pthread_mutex_t *mutex);
int pthread_cond_signal(pthread_cond_t *condition);
int pthread_cond_broadcast(pthread_cond_t *condition);
int pthread_once(pthread_once_t *once, void (*initializer)(void));
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int pthread_key_delete(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
void *pthread_getspecific(pthread_key_t key);

#endif
