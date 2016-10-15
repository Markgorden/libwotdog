/* This file contains debugging macros to be used when investigating issues.
 */
#ifndef __DEBUGMACRO_H_
#define __DEBUGMACRO_H_

#include <stdio.h>

#define D(...)                                                               \
    do {                                                                     \
        FILE *fp = fopen("/tmp/log.txt","a");                                \
        fprintf(fp,"%s:%s:%d:\t", __FILE__, __FUNCTION__, __LINE__);         \
        fprintf(fp,__VA_ARGS__);                                             \
        fprintf(fp,"\n");                                                    \
        fclose(fp);                                                          \
    } while (0);


#define my_debug(fmt, ...) \
	printf("DEBUG %s:%d > " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
#define my_debug_mark() \
	printf("-- MARK %s:%d --\n", __FILE__, __LINE__)
#endif

#endif