#include "log.h"
#include <stdio.h>
#include <stdarg.h>

static int use_syslog = 0;
static int log_level = LOG_WARNING;

void init_log(char *_prgname, int _use_syslog) {
        use_syslog = _use_syslog;
        if (use_syslog) {
                openlog(_prgname, LOG_PID, LOG_DAEMON);
        }
}

void set_log_level(int level) {
        log_level = level;
}

void destroy_log(void) {
        if (use_syslog) closelog();
}

void log_stdout(char * format, va_list ap)
{
        vfprintf(stdout, format, ap);
        fflush(stdout);
}

void capt_log(int priority, char * format, ...) {
        va_list ap;
        if (priority<=log_level) {
                va_start(ap, format);
                if (use_syslog) vsyslog(priority, format, ap);
                else log_stdout(format, ap);
                va_end(ap);
        }
}

