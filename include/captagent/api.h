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

#ifndef API_H_
#define API_H_


#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef DEFAULT_CONFDIR
#define DEFAULT_CONFDIR "/usr/local/etc/captagent/"
#endif

#ifndef DEFAULT_CAPTURE_PLANDIR
#define DEFAULT_CAPTURE_PLANDIR "/usr/local/etc/captagent/scripts"
#endif


#ifdef OS_LINUX
#include <linux/types.h>
#endif /* OS_LINUX */

typedef struct xml_node {
        char *key;
        char *value;
        char **attr;
        struct xml_node *child;
        struct xml_node *parent;
        struct xml_node *next;
} xml_node;

typedef struct _str {
        char* s;
        int len;
} str;

struct rc_info {
    uint8_t     ip_family; /* IP family IPv6 IPv4 */
    uint8_t     ip_proto; /* IP protocol ID : tcp/udp */
    uint8_t     proto_type; /* SIP: 0x001, SDP: 0x03*/
    char        *src_ip;
    char        *dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint32_t    time_sec;
    uint32_t    time_usec;
    uint32_t	liid;
    uint16_t	sessionid;
    uint8_t	    direction;
    char        *uuid;
    str         *correlation_id;
} ;

typedef struct rc_info rc_info_t;


typedef enum msg_body_type {
        MSG_BODY_UNKNOWN = 0,
        MSG_BODY_SDP
} msg_body_type_t;


typedef struct stats_object {
    unsigned int total_req;
    unsigned int curr_req;
    unsigned int total_x2;
    unsigned int failed_x2;
    unsigned long total_x3;
    unsigned long failed_x3;
    unsigned int curr_calls;
    unsigned int total_calls;
} stats_object_t;

extern struct stats_object stats_obj;

struct hep_module *hepmod;
extern int send_message (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
extern int get_basestat(char *module, char *stats, size_t len);
struct module *module_list;

typedef unsigned int bool;

#ifndef TRUE
#define TRUE  1
#endif /* TRUE */

#ifndef FALSE
#define FALSE 0
#endif /* FALSE */

typedef enum {
    DB_INT,       /* Integer number */
    DB_DOUBLE,    /* Decimal number */
    DB_STRING,    /* String */
    DB_STR,       /* str structure */
    DB_DATETIME,   /* Date and time */
    DB_BLOB       /* Binary large object */
} db_type_t;


typedef struct db_value {
		str key;
		db_type_t type;              /* Type of the value */
		int nul;                     /* NULL flag */
        union {
               int int_val;             /* Integer value */
               double double_val;       /* Double value */
               time_t time_val;         /* Unix time_t value */
               const char* string_val;  /* Zero terminated string */
               str str_val;             /* str structure */
               str blob_val;            /* Structure describing blob */
        } val;
} db_value_t;


#endif /* API_H_ */
