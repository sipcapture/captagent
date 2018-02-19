/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) QXIP BV 2012-2018 (http://qxip.net)
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

extern char *usefile;
extern int handler(int value);
extern char *global_config_path;
extern char *global_scripts_path;

int ipv4fragments=0;
int ipv6fragments=0;

/* Ethernet type in case of vlan or mpls header */
#define VLAN            0x8100
#define MPLS_UNI        0x8847
#define MPLS_MULTI      0x8848

/* --- MPLS header --- */
struct mpls_header
{
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  u_int32_t ttl:8, s:1, exp:3, label:20;
#elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
  u_int32_t label:20, exp:3, s:1, ttl:8;
#endif
} __attribute__((packed));

/* --- MPLS struct --- */
union mpls {
  uint32_t u32;
  struct mpls_header mpls;
};

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
#define GREHDR_SIZE 4

#define GRE_PROTO 47
#define IPPROTO_OFFSET 9
#define IPLEN_MASK 0b00001111

#define MAX_SOCKETS 10
profile_socket_t profile_socket[MAX_SOCKETS];

typedef struct socket_pcap_stats {
	uint64_t received_packets_total;
	uint64_t received_tcp_packets;
	uint64_t received_udp_packets;
	uint64_t received_sctp_packets;
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
int set_raw_filter(unsigned int loc_idx, char *filter);
pcap_t* get_pcap_handler(unsigned int loc_idx);

int dump_proto_packet(struct pcap_pkthdr *, u_char *, uint8_t, char *, uint32_t, char *,
            char *, uint16_t, uint16_t, uint8_t,uint16_t, uint8_t, uint16_t, uint32_t, uint32_t);


/*IPv4 filter*/
#define BPF_DEFRAGMENTION_FILTER_IPV4 "(ip[6:2] & 0x3fff != 0)"
/*IPv6 filter*/
#define BPF_DEFRAGMENTION_FILTER_IPV6 "(ip6[6]=44 and (ip6[42:2] & 0xfff8 != 0))"

#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_RESERVED 2
#define TZSP_TYPE_CONFIGURATION 3
#define TZSP_TYPE_KEEPALIVE 4
#define TZSP_TYPE_PORT_OPENER 5

#define ARRAYSZ(x) (sizeof(x)/sizeof(*x))

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

int w_tzsp_payload_extract(msg_t *_m);
void proccess_packet(msg_t *_m, struct pcap_pkthdr *pkthdr, u_char *packet);

#endif /* _SOCKET_PCAP_H_ */


