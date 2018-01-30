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

#ifndef _transport_hep_H_
#define _transport_hep_H_

#include <captagent/xmlread.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#include <uv.h>

#ifdef USE_IPv6
#include <netinet/ip6.h>
#endif /* USE_IPv6 */


#ifdef USE_ZLIB
#include <zlib.h>
#endif /* USE_ZLIB */

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#endif /* USE_SSL */

#define MAX_TRANPORTS 10
profile_transport_t profile_transport[MAX_TRANPORTS];

typedef struct transport_hep_stats {
	uint64_t received_packets_total;
	uint64_t send_packets_total;
	uint64_t reconnect_total;
	uint64_t compressed_total;
	uint64_t errors_total;
} transport_hep_stats_t;

typedef enum {
  SEND_UDP_REQUEST = 0,
  SEND_TCP_REQUEST = 1,
  QUIT_REQUEST
} hep_request_type_t;

typedef enum {
  STATE_INIT = 0,
  STATE_CONNECTING,
  STATE_CONNECTED,
  STATE_CLOSING,
  STATE_CLOSED,
  STATE_SHUTTING_DOWN,
  STATE_SHUT_DOWN,
  STATE_ERROR
} conn_state_type_t;

typedef struct hep_connection {
  uint8_t type;
  uv_loop_t *loop;
  uv_thread_t *thread;
  struct sockaddr_in send_addr;
  uv_async_t async_handle;
  uv_sem_t sem;
  uv_mutex_t mutex;
  
  uv_connect_t connect;
  uv_udp_t udp_handle; 
  uv_tcp_t tcp_handle; 
  
  void *context;

  conn_state_type_t conn_state;
  time_t conn_state_changed_time;
} hep_connection_t;

typedef struct hep_request {
  hep_request_type_t request_type;
  hep_connection_t *conn;
  unsigned char *message;
  int len;
} hep_request_t;


#ifdef USE_SSL
SSL_CTX* initCTX(void);
#endif /* USE_SSL */

//struct addrinfo *ai;
//struct addrinfo hints[1] = {{ 0 }};

extern char *global_config_path;


int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int sendzip, unsigned int idx);
int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int idx);
int send_data (void *buf, unsigned int len, unsigned int idx);
int sigPipe(void);
profile_transport_t* get_profile_by_name(char *name);
unsigned int get_profile_index_by_name(char *name);
int bind_usrloc(transport_module_api_t *api);
int send_hep(msg_t *msg, int freeParam);
void free_module_xml_config();
int load_module_xml_config();
int reload_config (char *erbuf, int erlen);
int check_module_xml_config();
/*API*/
int w_send_hep_api(msg_t *_m, char *param1);
int w_send_hep_api_param(msg_t *_m, char *param1, char *param2);
int w_send_hep_proto(msg_t *_m, char *param1, char *param2);

/*LIBUV*/

int send_message(hep_connection_t *conn, unsigned char *message, size_t len, hep_request_type_t type);

#if UV_VERSION_MAJOR == 0                         
uv_buf_t on_alloc(uv_handle_t* client, size_t suggested);
void _async_callback(uv_async_t *async, int status);
void _udp_recv_callback(uv_udp_t *handle, ssize_t nread, uv_buf_t *buf, struct sockaddr *addr, unsigned int flags);
uv_buf_t  _buffer_alloc_callback(uv_handle_t *handle, size_t suggested);
#else     
void on_alloc(uv_handle_t* client, size_t suggested, uv_buf_t* buf);
void _buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst);
void _udp_recv_callback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags);
void _async_callback(uv_async_t *async);
#endif

void _send_callback(uv_udp_send_t *req, int status);
void on_send_udp_request(uv_udp_send_t* req, int status);
void on_send_tcp_request(uv_write_t* req, int status);
int _handle_send_udp_request(hep_connection_t *conn, unsigned char *message, size_t len);
int _handle_send_tcp_request(hep_connection_t *conn, unsigned char *message, size_t len);
int homer_close(hep_connection_t *conn);
void homer_free(hep_connection_t *conn);
int _handle_quit(hep_connection_t *conn);
void _run_uv_loop(void *arg);
int homer_alloc(hep_connection_t *conn);
int init_udp_socket(hep_connection_t *conn, char *host, int port);
void on_tcp_connect(uv_connect_t* connection, int status);
int init_tcp_socket(hep_connection_t *conn, char *host, int port);
     

/* HEPv3 types */

struct hep_chunk {
       u_int16_t vendor_id;
       u_int16_t type_id;
       u_int16_t length;
} __attribute__((packed));

typedef struct hep_chunk hep_chunk_t;

struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       u_int8_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint8 hep_chunk_uint8_t;

struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       u_int16_t data;
} __attribute__((packed));

typedef struct hep_chunk_uint16 hep_chunk_uint16_t;

struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       u_int32_t data;
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
    u_int16_t length;
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

/*
static hep_generic_t HDR_HEP = {
    {0x48455033, 0x0},
    {0, 0x0001, 0x00, 0x00},
    {0, 0x0002, 0x00, 0x00},
    {0, 0x0003, 0x00, 0x00},
    {0, 0x0004, 0x00, 0x00},
    {0, 0x0005, 0x00, 0x00},
    {0, 0x0006, 0x00, 0x00},
    {0, 0x0007, 0x00, 0x00},
    {0, 0x0008, 0x00, 0x00},
    {0, 0x0009, 0x00, 0x00},
    {0, 0x000a, 0x00, 0x00},
    {0, 0x000b, 0x00, 0x00},
    {0, 0x000c, 0x00, 0x00},
    {0, 0x000d, 0x00, 0x00},
    {0, 0x000e, 0x00, 0x00},
    {0, 0x000f, 0x00, 0x00}
};
*/


/* Ethernet / IP / UDP header IPv4 */
const int udp_payload_offset = 14+20+8;

struct hep_hdr{
    u_int8_t hp_v;            /* version */
    u_int8_t hp_l;            /* length */
    u_int8_t hp_f;            /* family */
    u_int8_t hp_p;            /* protocol */
    u_int16_t hp_sport;       /* source port */
    u_int16_t hp_dport;       /* destination port */
};

struct hep_timehdr{
    u_int32_t tv_sec;         /* seconds */
    u_int32_t tv_usec;        /* useconds */
    u_int16_t captid;         /* Capture ID node */
};

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

#ifdef USE_IPv6
struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};
#endif



#endif /* _transport_hep_H_ */
