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


#ifndef _socket_raw_H_
#define _socket_raw_H_

#include <captagent/xmlread.h>

#define FILTER_LEN 4080

extern char *usefile;
extern int handler(int value);
extern int set_raw_rtp_filter();
extern char *global_config_path;
extern char *global_scripts_path;

#define BUF_SIZE 65535
#define MIN_UDP_PACKET        18

/* SYNC this list: http://hep.sipcapture.org */
#define PROTO_RTP    0x04
#define PROTO_RTCP   0x05

#ifndef FILTER_RAW_LEN
#define FILTER_RAW_LEN 9000
#endif

#define DEFAULT_DATALINK  DLT_EN10MB


/* header offsets */
#define ETHHDR_SIZE 14
#define TOKENRING_SIZE 22
#define PPPHDR_SIZE 4
#define SLIPHDR_SIZE 16
#define RAWHDR_SIZE 0
#define LOOPHDR_SIZE 4
#define FDDIHDR_SIZE 21
#define ISDNHDR_SIZE 16
#define IEEE80211HDR_SIZE 32

#define MAX_SOCKETS 10
profile_socket_t profile_socket[MAX_SOCKETS];

typedef struct socket_raw_stats {
	uint64_t received_packets_total;
	uint64_t received_tcp_packets;
	uint64_t received_udp_packets;
	uint64_t received_sctp_packets;
	uint64_t send_packets;
} socket_raw_stats_t;

extern FILE* yyin;
extern int yyparse();
extern unsigned int if_nametoindex(const char*);

//lua_State *LUAScript[MAX_SOCKETS];

int bind_api(socket_module_api_t* api);
int reload_config (char *erbuf, int erlen);

int set_raw_filter(unsigned int loc_idx, char *filter);
int iface_bind(int fd, int ifindex);

int convert_arp_to_dl(unsigned int loc_idx, int arptype);

int apply_filter (filter_msg_t *filter);
void free_module_xml_config();
int load_module_xml_config();

/* BIND */
int bind_check_size(msg_t *_m, char *param1, char *param2);
int iface_get_arptype(int fd, const char *device, char *ebuf);
int raw_capture_rcv_loop(unsigned int loc_idx);

#endif /* _socket_raw_H_ */
