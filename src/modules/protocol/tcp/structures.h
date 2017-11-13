/**
   Container of header structures for 
   - Datalink layer
   - Network layer
   - Transport layer
   
   Author: 2016-2017 Michele Campus <fci1908@gmail.com>
   (C) Homer Project 2012-2017 (http://www.sipcapture.org)
   
   Homer capture agent is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version
   
   Homer capture agent is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**/
#ifndef STRUCTURES_H_
#define STRUCTURES_H_

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <net/ethernet.h>
#include "define.h"
#include "uthash.h"

#ifdef __GNUC__
/* GNU C */
#define PACK_OFF __attribute__ ((__packed__));
#endif


/* ++++++++++++++++++++++++ CISCO HDLC +++++++++++++++++++++++++ */
struct chdlc_hdr
{
  u_int8_t addr;          /* 0x0F (Unicast) - 0x8F (Broadcast) */
  u_int8_t ctrl;          /* always 0x00                       */
  u_int16_t proto_code;   /* protocol type (e.g. 0x0800 IP)    */
} PACK_OFF;



/* +++++++++++++++++++++ Ethernet header ++++++++++++++++++++++ */
struct ether_hdr
{
  u_int8_t ether_dest_addr[ETHER_ADDR_LEN]; // Destination MAC address
  u_int8_t ether_src_addr[ETHER_ADDR_LEN];  // Source MAC address
  u_int16_t type_or_len; // Ethernet Type (for Eth II) or length (for Eth)
} PACK_OFF;



/* +++++++++++++++++ LLC SNAP header (IEEE 802.2) ++++++++++++ */
struct llc_snap_hdr
{
  /* llc, should be 0xaa 0xaa 0x03 for snap */
  u_int8_t dsap;
  u_int8_t ssap;
  u_int8_t control;
  /* snap */
  u_int8_t oui[3];
  u_int16_t type;
} PACK_OFF;



/* +++++++++++++++ 802.1Q header (Virtual LAN) +++++++++++++++ */
struct vlan_hdr
{
  u_int16_t tci;
  u_int16_t type;
} PACK_OFF;



/* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */
struct mpls_hdr
{
  u_int32_t label:20, exp:3, s:1, ttl:8;
} PACK_OFF;



/* ++++++++++ Radio Tap header (for IEEE 802.11) with timestamp +++++++++++++ */
struct radiotap_hdr
{
  u_int8_t  version;         /* set to 0 */
  u_int8_t  pad;
  u_int16_t len;
  u_int32_t present;
  u_int64_t MAC_timestamp;
  u_int8_t flags;
} PACK_OFF;



/* ++++++++++++ Wireless header (IEEE 802.11) ++++++++++++++++ */
struct wifi_hdr
{
  u_int16_t fc;
  u_int16_t duration;
  u_int8_t rcvr[6];
  u_int8_t trsm[6];
  u_int8_t dest[6];
  u_int16_t seq_ctrl;
  /* u_int64_t ccmp - for data encription only - check fc.flag */
} PACK_OFF;



/* +++++++++++++ Internet Protocol (IPv4) header +++++++++++++ */
struct ipv4_hdr
{
#if defined(__LITTLE_ENDIAN)
  u_int8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN)
  u_int8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
  u_int8_t ip_tos;            // type of service
  u_int16_t ip_len;           // total length (ip header + payload)
  u_int16_t ip_id;            // identification number
  u_int16_t ip_frag_offset;   // fragment offset and flags
#define IP_RF 0x8000	      /* reserved fragment flag */
#define IP_DF 0x4000	      /* dont fragment flag */
#define IP_MF 0x2000	      /* more fragments flag */
#define IP_OFFMASK 0x1fff     /* mask for fragmenting bits */
  u_int8_t ip_ttl;            // time to live
  u_int8_t ip_proto;          // transport protocol type
  u_int16_t ip_checksum;      // checksum
  u_int32_t ip_src_addr;      // source IP address
  u_int32_t ip_dst_addr;      // destination IP address
} PACK_OFF;



/* +++++++++++++++++++++++ IPv6 header +++++++++++++++++++++++ */
struct ipv6_addr
{
  /* union */
  /* { */
  u_int8_t   ipv6_addr[16];
  /* u_int16_t  ipv6_addr16[8]; */
    /* u_int32_t  ipv6_addr32[4]; */
  /* } ipv6_addr;  /\* 128-bit IPV6 address *\/ */
};


struct ipv6_hdr
{
  union {
    struct ipv6_hdrctl {
      u_int32_t ipv6_un1_flow;    /* :4 version, :8 TC, :20 flow-ID */
      u_int16_t ipv6_un1_plen;    /* payload length */
      u_int8_t  ipv6_un1_next;    /* next header */
      u_int8_t  ipv6_un1_hlim;    /* hop limit */
    } ipv6_un1;
    
    u_int8_t ipv6_un2_vfc;        /* 4 bits version, top 4 bits tclass */ 
  } ipv6_ctlun;
  
  struct ipv6_addr ipv6_src;	  /* source address */
  struct ipv6_addr ipv6_dst;	  /* destination address */
} PACK_OFF;



/* +++++++++++++++++++++++ TCP header +++++++++++++++++++++++++ */
struct tcp_hdr
{
  u_int16_t tcp_src_port;     // source TCP port
  u_int16_t tcp_dst_port;    // destination TCP port
  u_int32_t tcp_seq;          // TCP sequence number
  u_int32_t tcp_ack;          // TCP acknowledgement number
#if defined(__LITTLE_ENDIAN)
  u_int8_t reserved:4, tcp_offset:4;
#elif defined(__BIG_ENDIAN)
  u_int8_t tcp_offset:4, reserved:4;
#else
# error "Byte order must be defined"
#endif
  u_int8_t tcp_flags;         // TCP flags (and 2-bits from reserved space)
#define TCP_FIN   0x01
#define TCP_SYN   0x02
#define TCP_RST   0x04
#define TCP_PUSH  0x08
#define TCP_ACK   0x10
#define TCP_URG   0x20
#define TH_FLAGS (TCP_FIN|TCP_SYN|TCP_RST|TCP_PUSH|TCP_ACK|TCP_URG)
  u_int16_t tcp_window;     // TCP window size
  u_int16_t tcp_checksum;   // TCP checksum
  u_int16_t tcp_urgent;     // TCP urgent pointer
} PACK_OFF;



/* +++++++++++++++++++++++ UDP header +++++++++++++++++++++++++ */
struct udp_hdr
{
  u_int16_t udp_src_port;
  u_int16_t udp_dst_port;
  u_int16_t len;
  u_int16_t check;
} PACK_OFF;

/* general stats filled by every pkts  */
struct flow_stats
{
  u_int16_t discarded_bytes;
  u_int16_t ethernet_pkts;
  u_int16_t wifi_pkts;
  u_int16_t arp_pkts;
  u_int16_t ipv4_pkts;
  u_int16_t ipv6_pkts;
  u_int16_t vlan_pkts;
  u_int16_t mpls_pkts;
  u_int16_t pppoe_pkts;
  u_int16_t tcp_pkts;
  u_int16_t udp_pkts;
  u_int16_t num_tls_pkts; // count tls pkts
  
};

/* struct passed to the callback proto function */
/* for the detection process */
struct flow_callback_proto
{
  pcap_t *pcap_handle;
  struct flow_stats stats;
};


// Handshake struct for the Flow (to put in Hashtable)
/* 
   - pre-master secret
   - random val (C-S)
   - session ID (C-S)
   - certificate
   - chipher suite from server (RSA only)
*/
struct Handshake
{
  /* u_int8_t *enc_pre_master_secret; // Encrypted Pre-Master Secret */
  u_int8_t pre_master_secret[48];  // Pre-Master Secret
  u_int8_t cli_rand[32];           // Client random num
  u_int8_t srv_rand[32];           // Server random num
  u_int8_t *sessID_c;              // Client session ID
  u_int8_t *sessID_s;              // Server session ID
  u_int8_t *certificate_S;         // Server Certificate
  u_int8_t chiph_serv[2];          // Chipher Suite Server
};

/* struct containing the fields used for a flow */
struct Flow
{
  // IPV4
  u_int32_t ip_src;
  u_int32_t ip_dst;
  // IPV6
  struct ipv6_addr ipv6_src;
  struct ipv6_addr ipv6_dst;
  
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t proto_id_l3;
};

/** HASH TABLE **/
struct Hash_Table
{
  struct Flow flow;
  struct Handshake *handshake;
  int KEY; // Key
  u_int8_t is_handsk_fin;
  UT_hash_handle hh;
};

#endif
