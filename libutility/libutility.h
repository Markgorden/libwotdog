/*
*/
#ifndef _COE_LIB_UTILITY_H_
#define _COE_LIB_UTILITY_H_
#ifdef __cplusplus
extern "C"{
#endif


#include "util.h"
#include "pqsort.h"
#include "md5.h"
#include "endianconv.h"
#include "crc64.h"
#include "rand.h"
//#include "debugmacro.h"
#include "sha1.h"
#include "zmalloc.h"

short crc16(const char *buf, int len);
#define my_safe_free(a) { if (a) {free(a); a = NULL;} }
#define my_safe_strlen(x) ((x == NULL)?0:strlen(x))
#define get_tickcount() (unsigned long)times(NULL)

#ifdef __cplusplus
}
#endif
#endif

