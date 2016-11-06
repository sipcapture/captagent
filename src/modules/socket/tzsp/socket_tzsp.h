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

#ifndef _socket_tzsp_H_
#define _socket_tzsp_H_

#include <captagent/xmlread.h>

#include <uv.h>
#include <pcap.h>

#define FILTER_LEN 4080

#define PROTO_SIP    0x01
#define TZSP_PORT    "37008"
#define TZSP_HOST    "127.0.0.1"
#define TZSP_PROTO   "udp"

#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_RESERVED 2
#define TZSP_TYPE_CONFIGURATION 3
#define TZSP_TYPE_KEEPALIVE 4
#define TZSP_TYPE_PORT_OPENER 5

#define ARRAYSZ(x) (sizeof(x)/sizeof(*x))

extern char *global_config_path;
extern char *global_scripts_path;

extern char *usefile;
extern int handler(int value);

#define MAX_SOCKETS 10

typedef struct socket_tzsp_stats {
	uint64_t recieved_packets_total;
	uint64_t recieved_tcp_packets;
	uint64_t recieved_udp_packets;
	uint64_t recieved_sctp_packets;
	uint64_t send_packets;
} socket_tzsp_stats_t;


#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_RESERVED 2
#define TZSP_TYPE_CONFIGURATION 3
#define TZSP_TYPE_KEEPALIVE 4
#define TZSP_TYPE_PORT_OPENER 5

static const char * const tzsp_type_names[] = {
	[TZSP_TYPE_RECEIVED_TAG_LIST]   = "RECEIVED_TAG_LIST",
	[TZSP_TYPE_PACKET_FOR_TRANSMIT] = "PACKET_FOR_TRANSMIT",
	[TZSP_TYPE_RESERVED]            = "RESERVED",
	[TZSP_TYPE_CONFIGURATION]       = "CONFIGURATION",
	[TZSP_TYPE_KEEPALIVE]           = "KEEPALIVE",
	[TZSP_TYPE_PORT_OPENER]         = "PORT_OPENER",
};

#define TZSP_TAG_END 1
#define TZSP_TAG_PADDING 0

static const char * const tzsp_tag_names[] = {
	[TZSP_TAG_END]     = "END",
	[TZSP_TAG_PADDING] = "PADDING",
};

struct tzsp_header {
	uint8_t version;
	uint8_t type;
	uint16_t encap;
} __attribute__((packed));

struct tzsp_tag {
	uint8_t type;
	uint8_t length;
	char  data[];
} __attribute__((packed));


extern FILE* yyin;
extern int yyparse();

int bind_api(socket_module_api_t* api);
int reload_config (char *erbuf, int erlen);
void free_module_xml_config();
int load_module_xml_config();

void _run_uv_loop(void *arg);
int close_socket(unsigned int loc_idx);
void on_send(uv_udp_send_t* req, int status);
int w_tzsp_payload_extract(msg_t *_m);
void proccess_packet(msg_t *_m, struct pcap_pkthdr *pkthdr, u_char *packet);

#if UV_VERSION_MAJOR == 0                          
uv_buf_t on_alloc(uv_handle_t* client, size_t suggested);
void on_recv(uv_udp_t* handle, ssize_t nread, uv_buf_t rcvbuf, struct sockaddr* addr, unsigned flags);
void _async_callback(uv_async_t *async, int status);
#else 
void on_alloc(uv_handle_t* client, size_t suggested, uv_buf_t* buf);
void on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags);
void _async_callback(uv_async_t *async);
#endif

                                                     



#endif /* _socket_tzsp_H_ */
