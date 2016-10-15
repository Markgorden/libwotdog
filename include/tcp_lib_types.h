#ifndef _TCP_LIB_TYPES_H_
#define _TCP_LIB_TYPES_H_

#ifdef __cplusplus
extern "C"
{
#endif


typedef enum __bool 
{ 
	false = 0,
	true = 1,
}bool;

#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

/* Just to avoid compilation warnings. */
#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#ifdef __cplusplus
}
#endif
#endif
