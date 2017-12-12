/**
   decoder - decode TLS/SSL traffic - save handshake and extract certificate
   Copyright (C) 2016-2017 Michele Campus <fci1908@gmail.com>
   
   This file is part of decoder.
   
   decoder is free software: you can redistribute it and/or modify it under the
   terms of the GNU General Public License as published by the Free Software
   Foundation, either version 3 of the License, or (at your option) any later
   version.
   
   decoder is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE. See the GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License along with
   decoder. If not, see <http://www.gnu.org/licenses/>.
**/
#ifndef DECRIPTION_H_
#define DECRIPTION_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <endian.h>
#include <net/ethernet.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <gcrypt.h>
#include "define.h"
#include "uthash.h"

#define SHA384 0x009d
#define SHA256 0x009c

#define MS_LENGTH      48
#define MAX_BLOCK_SIZE 16
#define MAX_KEY_SIZE   32

// for cipher suite
#define ENC_AES        0x35
#define ENC_AES256     0x36
#define ENC_NULL       0x3B
#define DIG_SHA256     0x42
#define DIG_SHA384     0x43

/* Create a RSA structure */
RSA *createRSA(unsigned char * key, int public);

// PRIVATE ENCRIPTION
int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);

// PUBLIC ENCRIPTION
int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);

// PRIVATE DECRIPTION
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted);

// PUBLIC DECRIPTION
int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted);

// Print error
void printLastError(char *msg);

/* **************************** */

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
  u_int8_t ipv6_addr[16];
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
  u_int16_t tcp_src_port;      // source TCP port
  u_int16_t tcp_dst_port;     // destination TCP port
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
  u_int8_t save;
};


/* **************************** */

typedef struct {
  const char *name;
  unsigned int len;
} SslDigestAlgo;

static const char *ciphers[] = {
  "AES",
  "AES256",
  "*UNKNOWN*"
};

/* SSL Cipher Suite modes */
typedef enum {
  MODE_CBC,               /* GenericBlockCipher */
  MODE_GCM,               /* GenericAEADCipher */
  MODE_CCM,               /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
  MODE_CCM_8,             /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
  MODE_POLY1305,
} ssl_cipher_mode_t;

typedef struct {
  int number;             /* The cipher suite identification */
  int kex;                /* The key exchange algorithm */
  int enc;		  /* The private key encryption algorithm */
  int dig;		  /* The digest algorithm */
  ssl_cipher_mode_t mode; /* The cipher suite modes */
} SslCipherSuite;

// cipher suites array
extern const SslCipherSuite cipher_suites[];
// digest array
extern const SslDigestAlgo digests[];
// get index digest index
extern const SslDigestAlgo *ssl_cipher_suite_dig(const SslCipherSuite *cs);

struct _SslDecoder {
  u_int8_t *iv;
  u_int8_t *w_key;
  gcry_cipher_hd_t evp;
};

// Internal function for PRF pseudo-random function
int tls12_prf(int md, unsigned char *secret, const char *usage,
	      u_int8_t *rnd1, u_int8_t *rnd2, unsigned char *out,
	      u_int8_t out_len);

// Handshake struct for the Flow (to put in Hashtable)
/* 
   - pre-master secret
   - public key cert (from server in case of pms presence) TLS1
   - public key cli  (from client key exchange) TLS1.2
   - random val (C-S)
   - session ID (C-S)
   - certificate
   - cipher_suite
   - SSL decoder CLIENT
   - SSL decoder SERVER
*/
struct Handshake
{
  u_int8_t pre_master_secret[49];      // Pre-Master Secret
  u_int8_t master_secret[49];          // Master Secret
  u_int8_t cli_rand[33];               // Client random num
  u_int8_t srv_rand[33];               // Server random num
  u_int8_t *sessID_c;                  // Client session ID
  u_int8_t *sessID_s;                  // Server session ID
  u_int8_t *certificate_S;             // Server Certificate
  SslCipherSuite cipher_suite;         // Cipher Suite
  struct _SslDecoder ssl_decoder_cli;
  struct _SslDecoder ssl_decoder_srv;
  
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
  // Ports
  u_int16_t src_port;
  u_int16_t dst_port;
  // Transport proto
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
