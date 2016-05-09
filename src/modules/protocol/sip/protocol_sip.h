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

#ifndef _PROTOCOL_SIP_H_
#define _PROTOCOL_SIP_H_

#include <captagent/xmlread.h>
#include "parser_sip.h"

#define FILTER_LEN 4080

bind_transport_module_api_t transport_bind_api;
bind_database_module_api_t database_bind_api;

/* SYNC this list: http://hep.sipcapture.org */
#define PROTO_SIP    0x01
#define PROTO_XMPP   0x02
#define PROTO_SDP    0x03
#define PROTO_RTP    0x04
#define PROTO_RTCP   0x05
#define PROTO_MGCP   0x06
#define PROTO_MEGACO 0x07
#define PROTO_M2UA   0x08
#define PROTO_M3UA   0x09
#define PROTO_IAX    0x0a
#define PROTO_H322   0x0b
#define PROTO_H321   0x0c

typedef struct protocol_sip_stats {
	uint64_t recieved_packets_total;
	uint64_t parsed_packets;
	uint64_t send_packets;
} protocol_sip_stats_t;

static protocol_sip_stats_t stats;

extern char* usefile;
extern int handler(int value);
extern int set_raw_rtp_filter();


#define MAX_PROTOCOLS 10
profile_protocol_t profile_protocol[MAX_PROTOCOLS];

profile_protocol_t* get_profile_by_name(char *name);
unsigned int get_profile_index_by_name(char *name);
int bind_api(protocol_module_api_t* api);
int set_value(unsigned int idx, msg_t *msg);
int parse_packet(msg_t *msg, sip_msg_t *sipPacket, unsigned int type);
int parse_only_packet(msg_t *msg, void* packet);
int parse_sip(msg_t *msg, unsigned int type);
int w_light_parse_sip(msg_t *_m);
int w_parse_full_sip(msg_t *_m);
int light_parse_sip(msg_t *msg);



void free_module_xml_config();
int load_module_xml_config();
int reload_config (char *erbuf, int erlen);
int check_module_xml_config();

/* API */
int w_proto_check_size(msg_t *_m, char *param1, char *param2);
int w_parse_sip(msg_t *_m);
int w_clog(msg_t *_m, char *param1, char* param2);
int w_sip_is_method(msg_t *_m);
int w_sip_check(msg_t *_m, char *param1, char *param2);

int w_send_reply_p(msg_t *_m, char *param1, char *param2);
int w_send_reply(msg_t *_m);
int send_sip_reply(msg_t *_m, int code, char *description);
int w_is_flag_set(msg_t *_m, char *param1, char *param2);
                                    


#endif /* _PROTOCOL_SIP_H_ */
