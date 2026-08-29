#ifndef TROE_SYS_RANDOM_H
#define TROE_SYS_RANDOM_H

#include <stddef.h>
#include <sys/types.h>

#define GRND_NONBLOCK 0x01

ssize_t getrandom(void *destination, size_t length, unsigned int flags);

#endif
