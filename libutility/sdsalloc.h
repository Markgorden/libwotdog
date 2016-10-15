/* SDSLib 2.0 -- A C dynamic strings library
 * from https://github.com/antirez/sds
 */

/* SDS allocator selection.
 *
 * This file is used in order to change the SDS allocator at compile time.
 * Just define the following defines to what you want to use. Also add
 * the include of your alternate allocator if needed (not needed in order
 * to use the default libc allocator). */

/*
#include "zmalloc.h"
#define s_malloc zmalloc
#define s_realloc zrealloc
#define s_free zfree
*/

#define s_malloc malloc
#define s_realloc realloc
#define s_free free
