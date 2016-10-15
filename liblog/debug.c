/*
*/

#include "../main/server.h"

#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <locale.h>
#include <sys/socket.h>

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#include <ucontext.h>
#include <fcntl.h>
//#include "bio.h"
#endif /* HAVE_BACKTRACE */

#include "myassert.h"

/*============================ Utility functions ============================ */

/* Low level logging. To use only for very big messages, otherwise
 * serverLog() is to prefer. */
void serverLogRaw(int level, const char *msg) 
{
    SERVER_CONTENT * server = &g_server_content;
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char * c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & LL_RAW);
    int log_to_stdout = server->log.logfile[0] == '\0';
    level &= 0xff; /* clear flags */
    if (level < server->log.verbosity) return;
    fp = log_to_stdout ? stdout : fopen(server->log.logfile,"a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp,"%s",msg);
    } else {
        int off;
        struct timeval tv;
        int role_char;
        pid_t pid = getpid();
        gettimeofday(&tv,NULL);
        off = strftime(buf,sizeof(buf),"%d %b %H:%M:%S.",localtime(&tv.tv_sec));
        snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
        fprintf(fp,"%d:%c %s %c %s\n",
            (int)getpid(),role_char, buf,c[level],msg);
    }
    fflush(fp);
    if (!log_to_stdout) fclose(fp);
   // if (server.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}

/* Like serverLogRaw() but with printf-alike support. This is the function that
 * is used across the code. The raw version is only used in order to dump
 * the INFO output on crash. */
void serverLog(int level, const char *fmt, ...) {
    va_list ap;
    char msg[LOG_MAX_LEN];

   // if ((level&0xff) < server.verbosity) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    serverLogRaw(level,msg);
}

void bugReportStart(void) 
{
    SERVER_CONTENT * c = &g_server_content;
    if (c->log.bug_report_start == 0) 
    {
        serverLogRaw(LL_WARNING|LL_RAW,
        "\n\n=== REDIS BUG REPORT START: Cut & paste starting from here ===\n");
        c->log.bug_report_start = 1;
    }
}

void _serverAssert(char *estr, char *file, int line) {
    bugReportStart();
    serverLog(LL_WARNING,"=== ASSERTION FAILED ===");
    serverLog(LL_WARNING,"==> %s:%d '%s' is not true",file,line,estr);
#ifdef HAVE_BACKTRACE
    //server.assert_failed = estr;
    //server.assert_file = file;
    //server.assert_line = line;
    serverLog(LL_WARNING,"(forcing SIGSEGV to print the bug report.)");
#endif
    *((char*)-1) = 'x';
}

