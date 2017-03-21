/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
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

#ifndef _PROTOCOL_RTCP_H_
#define _PROTOCOL_RTCP_H_

#include <captagent/xmlread.h>
#include "parser_rtcp.h"


/* SYNC this list: http://hep.sipcapture.org */
#define PROTO_RTCP_JSON   0x05

typedef struct protocol_rtcp_stats {
	uint64_t received_packets_total;
	uint64_t parsed_packets;
	uint64_t send_packets;
} protocol_rtcp_stats_t;

static protocol_rtcp_stats_t stats;

char sip_callid[250];
int rtcp_port = 0;
char *rtcp_portrange = NULL;
char *rtcp_userfilter=NULL;
int rtcp_proto_type = PROTO_RTCP_JSON; /* DEFAULT RTCP */
int rtcp_promisc = 1;
int rtcp_vlan = 0; /*vlan filter*/
int rtcp_as_json = 1;
int send_sdes = 1;

#define JSON_BUFFER_LEN 5000

#define MAX_PROTOCOLS 10
profile_protocol_t profile_protocol[MAX_PROTOCOLS];

int w_parse_rtcp_to_json(msg_t *_m);
int w_set_rtcp_flag(msg_t *msg);
int w_is_rtcp (msg_t *msg);
int w_is_rtcp_or_rtp (msg_t *msg);


int bind_api(protocol_module_api_t* api);

void free_module_xml_config();
int load_module_xml_config();
int reload_config (char *erbuf, int erlen);
int check_module_xml_config();
                                    


#endif /* _PROTOCOL_RTCP_H_ */
