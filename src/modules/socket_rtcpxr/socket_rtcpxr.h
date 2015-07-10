/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or modify
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

#ifndef _socket_rtcpxr_H_
#define _socket_rtcpxr_H_

#include "../../xmlread.h"

#define FILTER_LEN 4080

#define PROTO_SIP    0x01

extern char *global_config_path;
extern char *global_scripts_path;

extern char *usefile;
extern int handler(int value);

#define MAX_SOCKETS 10

typedef struct socket_rtcpxr_stats {
	uint64_t recieved_packets_total;
	uint64_t recieved_tcp_packets;
	uint64_t recieved_udp_packets;
	uint64_t recieved_sctp_packets;
	uint64_t send_packets;
} socket_rtcpxr_stats_t;

extern FILE* yyin;
extern int yyparse();

int bind_api(socket_module_api_t* api);
int reload_config (char *erbuf, int erlen);
void free_module_xml_config();
int load_module_xml_config();
int w_send_reply_p(msg_t *_m, char *param1, char *param2);
int w_send_reply(msg_t *_m);
int send_sip_reply(msg_t *_m, int code, char *description);


#endif /* _socket_rtcpxr_H_ */
