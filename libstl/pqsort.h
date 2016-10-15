/* The following is the NetBSD libc qsort implementation modified in order to
 * support partial sorting of ranges for ....
 */

#ifndef __PQSORT_H_
#define __PQSORT_H_

void
pqsort(void *a, size_t n, size_t es,
    int (*cmp) (const void *, const void *), size_t lrange, size_t rrange);

#endif
