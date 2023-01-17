/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2023 (http://www.sipcapture.org)
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

#ifndef SOCKET_COLLECTOR_H_
#define SOCKET_COLLECTOR_H_

#include <captagent/xmlread.h>
#include <uv.h>

#define FILTER_LEN   4080

#define PROTO_SIP    0x01
#define PROTO_REPORT 0x63

#define JSON_BUFFER_LEN 5000

extern char *global_config_path;
extern char *global_scripts_path;

extern char *usefile;
extern int handler(int value);

#define MAX_SOCKETS 10

typedef struct socket_rtcpxr_stats {
	uint64_t received_packets_total;
	uint64_t received_tcp_packets;
	uint64_t received_udp_packets;
	uint64_t received_sctp_packets;
	uint64_t send_packets;
} socket_rtcpxr_stats_t;

extern FILE* yyin;
extern int yyparse();

int bind_api(socket_module_api_t* api);
int reload_config (char *erbuf, int erlen);
void free_module_xml_config();
int load_module_xml_config();

void _run_uv_loop(void *arg);
int close_socket(unsigned int loc_idx);
void on_send(uv_udp_send_t* req, int status);
int send_sip_rtcpxr_reply(msg_t *_m, int code, char *description);
int w_send_rtcpxr_reply_p(msg_t *_m, char *param1, char *param2);
int w_send_rtcpxr_reply(msg_t *_m);

#if UV_VERSION_MAJOR == 0                          
uv_buf_t on_alloc(uv_handle_t* client, size_t suggested);
void on_recv(uv_udp_t* handle, ssize_t nread, uv_buf_t rcvbuf, struct sockaddr* addr, unsigned flags);
void _async_callback(uv_async_t *async, int status);
#else 
void on_alloc(uv_handle_t* client, size_t suggested, uv_buf_t* buf);
void on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags);
void _async_callback(uv_async_t *async);
#endif

#endif /* SOCKET_COLLECTOR_H_ */
