#ifndef TROE_CPYTHON_ERRNO_OVERLAY_H
#define TROE_CPYTHON_ERRNO_OVERLAY_H
#include_next <errno.h>
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
#ifndef ECONNABORTED
#define ECONNABORTED 103
#endif
#ifndef ECONNRESET
#define ECONNRESET 104
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED 111
#endif
#ifndef EALREADY
#define EALREADY 114
#endif
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif
#endif
