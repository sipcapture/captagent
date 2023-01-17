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

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

int hep_version = 3;
int usessl = 0;
int pl_compress = 0;


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
} ;

typedef struct rc_info rc_info_t;


/* HEPv3 types */

struct hep_chunk {
       uint16_t vendor_id;
       uint16_t type_id;
       uint16_t length;
} __attribute__((packed));

typedef struct hep_chunk hep_chunk_t;

struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       uint8_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint8 hep_chunk_uint8_t;

struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       uint16_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint16 hep_chunk_uint16_t;

struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       uint32_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint32 hep_chunk_uint32_t;

struct hep_chunk_str {
       hep_chunk_t chunk;
       char *data;
} __attribute__((packed));

typedef struct hep_chunk_str hep_chunk_str_t;

struct hep_chunk_ip4 {
       hep_chunk_t chunk;
       struct in_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip4 hep_chunk_ip4_t;

struct hep_chunk_ip6 {
       hep_chunk_t chunk;
       struct in6_addr data;
} __attribute__((packed));

typedef struct hep_chunk_ip6 hep_chunk_ip6_t;

struct hep_ctrl {
    char id[4];
    uint16_t length;
} __attribute__((packed));

typedef struct hep_ctrl hep_ctrl_t;

struct hep_chunk_payload {
    hep_chunk_t chunk;
    char *data;
} __attribute__((packed));

typedef struct hep_chunk_payload hep_chunk_payload_t;

/* Structure of HEP */

struct hep_generic {
        hep_ctrl_t         header;
        hep_chunk_uint8_t  ip_family;
        hep_chunk_uint8_t  ip_proto;
        hep_chunk_uint16_t src_port;
        hep_chunk_uint16_t dst_port;
        hep_chunk_uint32_t time_sec;
        hep_chunk_uint32_t time_usec;
        hep_chunk_uint8_t  proto_t;
        hep_chunk_uint32_t capt_id;
} __attribute__((packed));

typedef struct hep_generic hep_generic_t;

struct hep_hdr{
    uint8_t hp_v;            /* version */
    uint8_t hp_l;            /* length */
    uint8_t hp_f;            /* family */
    uint8_t hp_p;            /* protocol */
    uint16_t hp_sport;       /* source port */
    uint16_t hp_dport;       /* destination port */
};

struct hep_timehdr{
    uint32_t tv_sec;         /* seconds */
    uint32_t tv_usec;        /* useconds */
    uint16_t captid;         /* Capture ID node */
};

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

#ifdef USE_IPV6
struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};
#endif

/* Structure of HEP */

struct hep_generic_recv {
        hep_ctrl_t         *header;
        hep_chunk_uint8_t  *ip_family;
        hep_chunk_uint8_t  *ip_proto;
        hep_chunk_uint16_t *src_port;
        hep_chunk_uint16_t *dst_port;
        hep_chunk_uint32_t *time_sec;
        hep_chunk_uint32_t *time_usec;
        hep_chunk_ip4_t    *hep_src_ip4;
        hep_chunk_ip4_t	    *hep_dst_ip4;
        hep_chunk_ip6_t    *hep_src_ip6;
        hep_chunk_ip6_t    *hep_dst_ip6;
        hep_chunk_uint8_t  *proto_t;
        hep_chunk_uint32_t *capt_id;
        hep_chunk_uint16_t *keep_tm;
        hep_chunk_str_t    *auth_key;
        hep_chunk_str_t    *correlation_id;        
        hep_chunk_t   *payload_chunk;
} __attribute__((packed));

typedef struct hep_generic_recv hep_generic_recv_t;

