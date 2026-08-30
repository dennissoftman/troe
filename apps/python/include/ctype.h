#ifndef TROE_CPYTHON_CTYPE_OVERLAY_H
#define TROE_CPYTHON_CTYPE_OVERLAY_H
#include_next <ctype.h>
/* XSI classification used by libmpdec's numeric string parsing. It is not part
   of ISO C, so the shared sysroot does not declare it. */
#ifndef isascii
#define isascii(character) ((unsigned int)(character) < 128u)
#endif
#endif
