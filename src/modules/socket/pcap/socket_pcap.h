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


#ifndef _SOCKET_PCAP_H_
#define _SOCKET_PCAP_H_

#include <captagent/xmlread.h>

#define FILTER_LEN 4080

extern char *usefile;
extern int handler(int value);
extern char *global_config_path;
extern char *global_scripts_path;

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

/* our payload range between 0 - 191 */
#define RTP_FILTER "(ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 )"
/* our payload range between 200 and 204 */
#define RTCP_FILTER "(ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc)"

#define MAX_SOCKETS 10
profile_socket_t profile_socket[MAX_SOCKETS];

typedef struct socket_pcap_stats {
	uint64_t recieved_packets_total;
	uint64_t recieved_tcp_packets;
	uint64_t recieved_udp_packets;
	uint64_t recieved_sctp_packets;
	uint64_t send_packets;
} socket_pcap_stats_t;

extern FILE* yyin;
extern int yyparse();

//lua_State *LUAScript[MAX_SOCKETS];

int bind_api(socket_module_api_t* api);
int reload_config (char *erbuf, int erlen);
int apply_filter (filter_msg_t *filter);
void free_module_xml_config();
int load_module_xml_config();

/* BIND */
int bind_check_size(msg_t *_m, char *param1, char *param2);

int dump_proto_packet(struct pcap_pkthdr *, u_char *, uint8_t, char *, uint32_t, char *,
            char *, uint16_t, uint16_t, uint8_t,uint16_t, uint8_t, uint16_t, uint32_t, uint32_t);

#endif /* _SOCKET_PCAP_H_ */
