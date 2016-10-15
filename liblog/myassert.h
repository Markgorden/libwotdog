/* myassert.h -- Drop in replacemnet assert.h that prints the stack trace
 *                  in the my server logs.
 *
 * This file should be included instead of "assert.h" inside libraries used by
 * Redis that are using assertions, so instead of Redis disappearing with
 * SIGABORT, we get the details and stack trace inside the log file.
 *
 */

#ifndef __MY_ASSERT_H__
#define __MY_ASSERT_H__

#include <unistd.h> /* for _exit() */

/* Log levels */
#define LL_DEBUG 0
#define LL_VERBOSE 1
#define LL_NOTICE 2
#define LL_WARNING 3
#define LL_RAW (1<<10) /* Modifier to log without timestamp */
#define CONFIG_DEFAULT_VERBOSITY LL_NOTICE
#define LOG_MAX_LEN    1024 /* Default maximum length of syslog messages */

#define assert(_e) ((_e)?(void)0 : (_serverAssert(#_e,__FILE__,__LINE__),_exit(1)))

void _serverAssert(char *estr, char *file, int line);

#endif
