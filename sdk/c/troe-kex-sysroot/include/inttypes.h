#ifndef TROE_INTTYPES_H
#define TROE_INTTYPES_H

#include <stdint.h>

#define PRId64 "ld"
#define PRIi64 "li"
#define PRIu64 "lu"
#define PRIx64 "lx"
#define PRIX64 "lX"
#define PRIdPTR "ld"
#define PRIuPTR "lu"
#define PRIxPTR "lx"

typedef struct { intmax_t quot; intmax_t rem; } imaxdiv_t;

#endif
