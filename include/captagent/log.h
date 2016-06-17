/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
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

#ifndef LOG_H_
#define LOG_H_

#include <syslog.h>

void init_log(char *_prgname, int _use_syslog);

void set_log_level(int level);

void destroy_log(void);

void data_log(int priority, const char * fmt, ...);

#define PA_GCC_PRINTF_ATTR(a,b) __attribute__ ((format (printf, a, b)));

#define LEMERG(fmt, args...) data_log(LOG_EMERG, "[DEBUG] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LALERT(fmt, args...) data_log(LOG_ALERT, "[ALERT] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LCRIT(fmt, args...) data_log(LOG_CRIT, "[CRIT] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LERR(fmt, args...) data_log(LOG_ERR, "[ERR] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LWARNING(fmt, args...) data_log(LOG_WARNING, "[WARNING] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LNOTICE(fmt, args...) data_log(LOG_NOTICE, "[NOTICE] " fmt, ## args)
#define LINFO(fmt, args...) data_log(LOG_INFO, "[INFO] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LDEBUG(fmt, args...) data_log(LOG_DEBUG, "[DEBUG] %s:%d " fmt, __FILE__, __LINE__, ## args)
#define LMESSAGE(fmt, args...) data_log(LOG_ERR, "[MESSAGE] " fmt, ## args)

#endif /* LOG_H_ */
