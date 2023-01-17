/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2023 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or
 * modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * Homer capture agent is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
*/

#ifndef LOG_C_
#define LOG_C_

#include <captagent/log.h>
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


void log_stdout(const char * format, va_list ap)
{
        vfprintf(stdout, format, ap);
        fprintf(stdout, "\r\n");
        fflush(stdout);
}

void data_log(int priority, const char *fmt, ...) {

	va_list args;
        if (priority<=log_level) {
                //vsnprintf("SYSLOG:%s:%d:%s: ", file, line, func);
                va_start(args, fmt);
                if (use_syslog) vsyslog(priority, fmt, args);
                else log_stdout(fmt, args);
                va_end(args);

        }
}

#endif /* LOG_C_ */
