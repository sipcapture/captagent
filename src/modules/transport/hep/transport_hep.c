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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "transport_hep.h"
#include <captagent/log.h>
#include "localapi.h"

xml_node *module_xml_config = NULL;
char *module_name="transport_hep";
uint64_t module_serial = 0;
char *module_description = NULL;

static transport_hep_stats_t stats;

uint8_t link_offset = 14;
static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int free_profile(unsigned int idx);
static uint64_t serial_module(void);

static void reconnect(int idx);
static void set_conn_state(hep_connection_t* conn, conn_state_type_t new_conn_state);

#if UV_VERSION_MAJOR == 0                         
        /* need implement it */
#else
static uv_key_t hep_conn_key;
#endif  


bind_statistic_module_api_t stats_bind_api;
unsigned int sslInit = 0;
unsigned int profile_size = 0;

static cmd_export_t cmds[] = {
        {"transport_hep_bind_api",  (cmd_function)bind_usrloc,   1, 0, 0, 0},
        {"bind_transport_hep",  (cmd_function)bind_transport_hep,  0, 0, 0, 0},
        { "send_hep", (cmd_function) w_send_hep_api, 1, 0, 0, 0 },
        { "send_hep", (cmd_function) w_send_hep_api_param, 2, 0, 0, 0 },
        { "send_hep_proto", (cmd_function) w_send_hep_proto, 2, 0, 0, 0 },
        {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
        "transport_hep",
        cmds,        /* Exported functions */
        load_module,    /* module initialization function */
        unload_module,
        description,
        statistic,
        serial_module
};

hep_connection_t hep_connection_s[MAX_TRANPORTS];
//hep_connection_t *hep_conn;

int bind_usrloc(transport_module_api_t *api)
{
        api->send_f = send_hep; // should be w_send_hep_api or w_send_hep_api_param
	api->reload_f = reload_config;
	api->module_name = module_name;

        return 0;
}

int w_send_hep_api(msg_t *_m, char *param1) 
{
    
    int ret = 0;

    _m->profile_name = param1;
        
    ret =  send_hep(_m, 1);    
    
    return ret;
}

int w_send_hep_api_param(msg_t *_m, char *param1, char *param2) 
{
    
    int ret = 0;
    int freeParam = 1;
    
    _m->profile_name = param1;
    if(param2 != NULL && !strncmp(param2,"true", 4)) freeParam = 0;
        
    ret =  send_hep(_m, freeParam);    
    
    return ret;
}

int w_send_hep_proto(msg_t *_m, char *param1, char *param2) 
{
    
    int ret = 0;

    _m->profile_name = param1;
    _m->rcinfo.proto_type = atoi(param2);
        
    ret =  send_hep(_m, 1);    
    
    return ret;
}

int reload_config (char *erbuf, int erlen) {

	char module_config_name[500];
	xml_node *config = NULL;

	LNOTICE("reloading config for [%s]", module_name);

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, module_name);

	if(xml_parse_with_report(module_config_name, erbuf, erlen)) {
		unload_module();
		load_module(config);
		return 1;
	}

	return 0;
}

profile_transport_t* get_profile_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return &profile_transport[0];

	for (i = 0; i < profile_size; i++) {

		if(!strncmp(profile_transport[i].name, name, strlen(profile_transport[i].name))) {
			return &profile_transport[1];
		}
	}

	return NULL;
}

unsigned int get_profile_index_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return 0;

	for (i = 0; i < profile_size; i++) {
		if(!strncmp(profile_transport[i].name, name, strlen(profile_transport[i].name))) {
			return i;
		}
	}
	return 0;
}

void ensure_connected(int idx) {
    // Only need to worry about TCP connection.
    if (hep_connection_s[idx].type != 2)
        return;

    // If we're connected, nothing to do.
    if (hep_connection_s[idx].conn_state == STATE_CONNECTED)
        return;

    reconnect(idx);
}

int send_hep (msg_t *msg, int freeParam) {

        unsigned char *zipData = NULL;
        rc_info_t *rcinfo = NULL;
        int sendzip = 0;
        unsigned int idx = 0;
        int ret = 0;

        idx = get_profile_index_by_name(msg->profile_name);
        rcinfo = &msg->rcinfo;

        stats.received_packets_total++;

        // Ensure we are connected by driving our state machine.
        ensure_connected(idx);

#ifdef USE_ZLIB
        int status = 0;
        unsigned long dlen;

        if(profile_transport[idx].compression && profile_transport[idx].version == 3) {
                //dlen = len/1000+len*len+13;

                dlen = compressBound(msg->len);

                zipData  = malloc(dlen); /* give a little bit memmory */

                /* do compress */
                status = compress( zipData, &dlen, msg->data, msg->len );
                if( status != Z_OK ){
                	  LERR("data couldn't be compressed");
                      sendzip = 0;
                      if(zipData) free(zipData); /* release */
                }
                else {
                        sendzip = 1;
                        msg->len = dlen;
                }

                stats.compressed_total++;
        }

#endif /* USE_ZLIB */

        switch(profile_transport[idx].version) {

            case 3:
                ret = send_hepv3(rcinfo, sendzip  ? zipData : msg->data , msg->len , sendzip, idx);
                break;

            case 2:
            case 1:
                ret = send_hepv2(rcinfo, msg->data , msg->len, idx);
                break;

            default:
                LERR("Unsupported HEP version [%d]", profile_transport[idx].version);
                break;
        }

#ifdef USE_ZLIB

        if(profile_transport[idx].compression && zipData) free(zipData);

#endif /* USE_ZLIB */

        if(freeParam == 1)
        {
                if(msg->mfree == 1) {
                     LDEBUG("LETS FREE IT!");
                     free(msg->data);
                }
                if(msg->corrdata)  
                {
                     free(msg->corrdata);
                     msg->corrdata = NULL;
                }                                                                                     
        }
        
        return ret;
}


int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int sendzip, unsigned int idx) {

    struct hep_generic *hg=NULL;
    void* buffer;
    unsigned int buflen=0, iplen=0,tlen=0;
    hep_chunk_ip4_t src_ip4, dst_ip4;
#ifdef USE_IPv6
    hep_chunk_ip6_t src_ip6, dst_ip6;
#endif
    hep_chunk_t payload_chunk;
    hep_chunk_t authkey_chunk;
    hep_chunk_t correlation_chunk;
    hep_chunk_uint16_t cval1;
    hep_chunk_uint16_t cval2;
            
    hg = malloc(sizeof(struct hep_generic));
    memset(hg, 0, sizeof(struct hep_generic));


    /* header set */
    memcpy(hg->header.id, "\x48\x45\x50\x33", 4);

    /* IP proto */
    hg->ip_family.chunk.vendor_id = htons(0x0000);
    hg->ip_family.chunk.type_id   = htons(0x0001);
    hg->ip_family.data = rcinfo->ip_family;
    hg->ip_family.chunk.length = htons(sizeof(hg->ip_family));

    /* Proto ID */
    hg->ip_proto.chunk.vendor_id = htons(0x0000);
    hg->ip_proto.chunk.type_id   = htons(0x0002);
    hg->ip_proto.data = rcinfo->ip_proto;
    hg->ip_proto.chunk.length = htons(sizeof(hg->ip_proto));

    /* IPv4 */
    if(rcinfo->ip_family == AF_INET) {
        /* SRC IP */
        src_ip4.chunk.vendor_id = htons(0x0000);
        src_ip4.chunk.type_id   = htons(0x0003);
        inet_pton(AF_INET, rcinfo->src_ip, &src_ip4.data);
        src_ip4.chunk.length = htons(sizeof(src_ip4));

        /* DST IP */
        dst_ip4.chunk.vendor_id = htons(0x0000);
        dst_ip4.chunk.type_id   = htons(0x0004);
        inet_pton(AF_INET, rcinfo->dst_ip, &dst_ip4.data);
        dst_ip4.chunk.length = htons(sizeof(dst_ip4));

        iplen = sizeof(dst_ip4) + sizeof(src_ip4);
    }
#ifdef USE_IPv6
      /* IPv6 */
    else if(rcinfo->ip_family == AF_INET6) {
        /* SRC IPv6 */
        src_ip6.chunk.vendor_id = htons(0x0000);
        src_ip6.chunk.type_id   = htons(0x0005);
        inet_pton(AF_INET6, rcinfo->src_ip, &src_ip6.data);
        src_ip6.chunk.length = htons(sizeof(src_ip6));

        /* DST IPv6 */
        dst_ip6.chunk.vendor_id = htons(0x0000);
        dst_ip6.chunk.type_id   = htons(0x0006);
        inet_pton(AF_INET6, rcinfo->dst_ip, &dst_ip6.data);
        dst_ip6.chunk.length = htons(sizeof(dst_ip6));

        iplen = sizeof(dst_ip6) + sizeof(src_ip6);
    }
#endif

    /* SRC PORT */
    hg->src_port.chunk.vendor_id = htons(0x0000);
    hg->src_port.chunk.type_id   = htons(0x0007);
    hg->src_port.data = htons(rcinfo->src_port);
    hg->src_port.chunk.length = htons(sizeof(hg->src_port));

    /* DST PORT */
    hg->dst_port.chunk.vendor_id = htons(0x0000);
    hg->dst_port.chunk.type_id   = htons(0x0008);
    hg->dst_port.data = htons(rcinfo->dst_port);
    hg->dst_port.chunk.length = htons(sizeof(hg->dst_port));


    /* TIMESTAMP SEC */
    hg->time_sec.chunk.vendor_id = htons(0x0000);
    hg->time_sec.chunk.type_id   = htons(0x0009);
    hg->time_sec.data = htonl(rcinfo->time_sec);
    hg->time_sec.chunk.length = htons(sizeof(hg->time_sec));


    /* TIMESTAMP USEC */
    hg->time_usec.chunk.vendor_id = htons(0x0000);
    hg->time_usec.chunk.type_id   = htons(0x000a);
    hg->time_usec.data = htonl(rcinfo->time_usec);
    hg->time_usec.chunk.length = htons(sizeof(hg->time_usec));

    /* Protocol TYPE */
    hg->proto_t.chunk.vendor_id = htons(0x0000);
    hg->proto_t.chunk.type_id   = htons(0x000b);
    hg->proto_t.data = rcinfo->proto_type;
    hg->proto_t.chunk.length = htons(sizeof(hg->proto_t));

    /* Capture ID */
    hg->capt_id.chunk.vendor_id = htons(0x0000);
    hg->capt_id.chunk.type_id   = htons(0x000c);
    hg->capt_id.data = htonl(profile_transport[idx].capt_id);
    hg->capt_id.chunk.length = htons(sizeof(hg->capt_id));

    /* Payload */
    payload_chunk.vendor_id = htons(0x0000);
    payload_chunk.type_id   = sendzip ? htons(0x0010) : htons(0x000f);
    payload_chunk.length    = htons(sizeof(payload_chunk) + len);

    tlen = sizeof(struct hep_generic) + len + iplen + sizeof(hep_chunk_t);

    /* auth key */
    if(profile_transport[idx].capt_password != NULL) {

          tlen += sizeof(hep_chunk_t);
          /* Auth key */
          authkey_chunk.vendor_id = htons(0x0000);
          authkey_chunk.type_id   = htons(0x000e);
          authkey_chunk.length    = htons(sizeof(authkey_chunk) + strlen(profile_transport[idx].capt_password));
          tlen += strlen(profile_transport[idx].capt_password);
    }

    /* correlation key */
    if(rcinfo->correlation_id.s && rcinfo->correlation_id.len > 0) {

             tlen += sizeof(hep_chunk_t);
             /* Correlation key */
             correlation_chunk.vendor_id = htons(0x0000);
             correlation_chunk.type_id   = htons(0x0011);
             correlation_chunk.length    = htons(sizeof(correlation_chunk) + rcinfo->correlation_id.len);
             tlen += rcinfo->correlation_id.len;
    }
    
    if(rcinfo->cval1) {
              tlen += sizeof(hep_chunk_uint16_t);
              cval1.chunk.vendor_id = htons(0x0000);
              cval1.chunk.type_id   = htons(0x0020);
              cval1.data = htons(rcinfo->cval1);
              cval1.chunk.length = htons(sizeof(cval1));    
    }
    
    if(rcinfo->cval2) {
              tlen += sizeof(hep_chunk_uint16_t);
              cval2.chunk.vendor_id = htons(0x0000);
              cval2.chunk.type_id   = htons(0x0021);
              cval2.data = htons(rcinfo->cval2);
              cval2.chunk.length = htons(sizeof(cval2));    
    }
    
    /* total */
    hg->header.length = htons(tlen);

    buffer = (void*)malloc(tlen);
    if (buffer==0){
        free(hg);
        return 1;
    }

    memcpy((void*) buffer, hg, sizeof(struct hep_generic));
    buflen = sizeof(struct hep_generic);

    /* IPv4 */
    if(rcinfo->ip_family == AF_INET) {
        /* SRC IP */
        memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip4));
        buflen += sizeof(struct hep_chunk_ip4);

        memcpy((void*) buffer+buflen, &dst_ip4, sizeof(struct hep_chunk_ip4));
        buflen += sizeof(struct hep_chunk_ip4);
    }
#ifdef USE_IPv6
      /* IPv6 */
    else if(rcinfo->ip_family == AF_INET6) {
        /* SRC IPv6 */
        memcpy((void*) buffer+buflen, &src_ip6, sizeof(struct hep_chunk_ip6));
        buflen += sizeof(struct hep_chunk_ip6);

        memcpy((void*) buffer+buflen, &dst_ip6, sizeof(struct hep_chunk_ip6));
        buflen += sizeof(struct hep_chunk_ip6);
    }
#endif

    /* AUTH KEY CHUNK */
    if(profile_transport[idx].capt_password != NULL) {

        memcpy((void*) buffer+buflen, &authkey_chunk,  sizeof(struct hep_chunk));
        buflen += sizeof(struct hep_chunk);

        /* Now copying payload self */
        memcpy((void*) buffer+buflen, profile_transport[idx].capt_password, strlen(profile_transport[idx].capt_password));
        buflen+=strlen(profile_transport[idx].capt_password);
    }

    /* Correlation KEY CHUNK */
    if(rcinfo->correlation_id.s && rcinfo->correlation_id.len > 0) {

           memcpy((void*) buffer+buflen, &correlation_chunk,  sizeof(struct hep_chunk));
           buflen += sizeof(struct hep_chunk);

           /* Now copying payload self */
           memcpy((void*) buffer+buflen, rcinfo->correlation_id.s, rcinfo->correlation_id.len);
           buflen+= rcinfo->correlation_id.len;
    }
    
    /* CVAL1 CHUNK */
    if(rcinfo->cval1) {
           memcpy((void*) buffer+buflen, &cval1,  sizeof(hep_chunk_uint16_t));
           buflen += sizeof(hep_chunk_uint16_t);
    }
    
    /* CVAL2 CHUNK */
    if(rcinfo->cval2) {
           memcpy((void*) buffer+buflen, &cval2,  sizeof(hep_chunk_uint16_t));
           buflen += sizeof(hep_chunk_uint16_t);
    }    

    /* PAYLOAD CHUNK */
    memcpy((void*) buffer+buflen, &payload_chunk,  sizeof(struct hep_chunk));
    buflen +=  sizeof(struct hep_chunk);

    /* Now copying payload self */
    memcpy((void*) buffer+buflen, data, len);
    buflen+=len;

    /* send this packet out of our socket */
    send_data(buffer, buflen, idx);
       

    if(hg) free(hg);

    return 1;
}


int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int idx) {

    void* buffer;
    struct hep_hdr hdr;
    struct hep_timehdr hep_time;
    struct hep_iphdr hep_ipheader;
    unsigned int totlen=0, buflen=0;

#ifdef USE_IPv6
    struct hep_ip6hdr hep_ip6header;
#endif /* USE IPV6 */

    /* Version && proto */
    hdr.hp_v = profile_transport[idx].version;
    hdr.hp_f = rcinfo->ip_family;
    hdr.hp_p = rcinfo->ip_proto;
    hdr.hp_sport = htons(rcinfo->src_port); /* src port */
    hdr.hp_dport = htons(rcinfo->dst_port); /* dst port */

    /* IP version */
    switch (hdr.hp_f) {
                case AF_INET:
                    totlen  = sizeof(struct hep_iphdr);
                    break;
#ifdef USE_IPv6
                case AF_INET6:
                    totlen = sizeof(struct hep_ip6hdr);
                    break;
#endif /* USE IPV6 */

    }

    hdr.hp_l = totlen + sizeof(struct hep_hdr);

    /* COMPLETE LEN */
    totlen += sizeof(struct hep_hdr);
    totlen += len;

    if(profile_transport[idx].version == 2) {
        totlen += sizeof(struct hep_timehdr);
        hep_time.tv_sec = rcinfo->time_sec;
        hep_time.tv_usec = rcinfo->time_usec;
        hep_time.captid = profile_transport[idx].capt_id;
    }

    /*buffer for ethernet frame*/
    buffer = (void*)malloc(totlen);
    if (buffer==0){
        LERR("ERROR: out of memory");
        goto error;
    }

    /* copy hep_hdr */
    memcpy((void*) buffer, &hdr, sizeof(struct hep_hdr));
    buflen = sizeof(struct hep_hdr);

    switch (hdr.hp_f) {

        case AF_INET:
                /* Source && Destination ipaddresses*/
                inet_pton(AF_INET, rcinfo->src_ip, &hep_ipheader.hp_src);
                inet_pton(AF_INET, rcinfo->dst_ip, &hep_ipheader.hp_dst);

                /* copy hep ipheader */
                memcpy((void*)buffer + buflen, &hep_ipheader, sizeof(struct hep_iphdr));
                buflen += sizeof(struct hep_iphdr);

                break;
#ifdef USE_IPv6
        case AF_INET6:

                inet_pton(AF_INET6, rcinfo->src_ip, &hep_ip6header.hp6_src);
                inet_pton(AF_INET6, rcinfo->dst_ip, &hep_ip6header.hp6_dst);

                /* copy hep6 ipheader */
                memcpy((void*)buffer + buflen, &hep_ip6header, sizeof(struct hep_ip6hdr));
                buflen += sizeof(struct hep_ip6hdr);
                break;
#endif /* USE_IPv6 */
     }

     /* Version 2 has timestamp, captnode ID */
     if(profile_transport[idx].version == 2) {
        /* TIMING  */
        memcpy((void*)buffer + buflen, &hep_time, sizeof(struct hep_timehdr));
        buflen += sizeof(struct hep_timehdr);
     }

     memcpy((void *)(buffer + buflen) , (void*)(data), len);
     buflen +=len;

     /* send this packet out of our socket */
     send_data(buffer, buflen, idx);

     return 1;

error:
     if(buffer) free(buffer);
     return 0;
}

#if UV_VERSION_MAJOR == 0                         
uv_buf_t  _buffer_alloc_callback(uv_handle_t *handle, size_t suggested)
{
        char *chunk = malloc(suggested);
        printf("in allocate, allocating %lu bytes into pointer %p\n", (unsigned long)suggested, chunk);
        memset(chunk, 0, suggested);
        return uv_buf_init(chunk, suggested);
        
}
#else
void _buffer_alloc_callback(uv_handle_t *handle, size_t suggested, uv_buf_t *dst) {
      char *chunk = malloc(suggested);
      printf("in allocate, allocating %lu bytes into pointer %p\n", (unsigned long)suggested, chunk);
      memset(chunk, 0, suggested);
      *dst = uv_buf_init(chunk, suggested);
}

#endif    

#if UV_VERSION_MAJOR == 0                         
void _udp_recv_callback(uv_udp_t *handle, ssize_t nread, uv_buf_t *buf, struct sockaddr *addr, unsigned int flags)
#else
void _udp_recv_callback(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned int flags)
#endif    
{
  printf("DATA RECV BACK\n");
  if(buf && buf->base) {
      free(buf->base);
  }

  return;
}


int send_data (void *buf, unsigned int len, unsigned int idx) {

        /* send this packet out of our socket */
        
	send_message(&hep_connection_s[idx], (unsigned char *)buf, len, hep_connection_s[idx].type == 1 ? SEND_UDP_REQUEST : SEND_TCP_REQUEST);

        stats.send_packets_total++;

        /* RESET ERRORS COUNTER */
        return 0;
}

/****** LIBUV *********************/

int send_message(hep_connection_t *conn, unsigned char *message, size_t len, hep_request_type_t type)
{

  hep_request_t *req = malloc(sizeof(hep_request_t));
  
  req->message = message;
  req->len = len;
  req->request_type = type;
  req->conn = conn;
   
  uv_mutex_lock(&conn->mutex);

  conn->async_handle.data = req;
  
  uv_async_send(&conn->async_handle);

  uv_sem_wait(&conn->sem);
  
  uv_mutex_unlock(&conn->mutex);
  
  
  return 0;
}

#if UV_VERSION_MAJOR == 0                         
uv_buf_t on_alloc(uv_handle_t* client, size_t suggested) {
        char *chunk = malloc(suggested);
        memset(chunk, 0, suggested);
        return uv_buf_init(chunk, suggested);   
}

#else 
void on_alloc(uv_handle_t* client, size_t suggested, uv_buf_t* buf) {
    
        char *chunk = malloc(suggested);
        memset(chunk, 0, suggested);
        *buf = uv_buf_init(chunk, suggested);
}
#endif

void on_tcp_close(uv_handle_t* handle)
{
#if UV_VERSION_MAJOR == 0                         
        /* need implement it */
        hep_connection_t* hep_conn = handle->loop->data;        
#else
        hep_connection_t* hep_conn = uv_key_get(&hep_conn_key);        
#endif        
        assert(hep_conn != NULL);
        set_conn_state(hep_conn, STATE_CLOSED);

}

void on_send_udp_request(uv_udp_send_t* req, int status) 
{
        if (status == 0 && req) {
                free(req->data);
                free(req); 
                req = NULL;
        }        
}

void on_send_tcp_request(uv_write_t* req, int status) 
{

        if (status == 0 && req) {
                free(req->data);
                free(req); 
                req = NULL;
        }

#if UV_VERSION_MAJOR != 0                         

	hep_connection_t* hep_conn = uv_key_get(&hep_conn_key);

        assert(hep_conn != NULL);        

        if ((status != 0) && (hep_conn->conn_state == STATE_CONNECTED)) {
            LERR("tcp send failed! err=%d", status);
            uv_close((uv_handle_t*)&hep_conn->tcp_handle, NULL);
            if (uv_is_active((uv_handle_t*)(req->handle))) {
                set_conn_state(hep_conn, STATE_CLOSING);
                uv_close((uv_handle_t*)(req->handle), on_tcp_close);
            }
            else
                set_conn_state(hep_conn, STATE_CLOSED);
        }    
#endif   
	
}       
   
int _handle_send_udp_request(hep_connection_t *conn, unsigned char *message, size_t len)
{

  uv_buf_t buf;
  uv_udp_send_t *send_req;

  buf.base = (char *)message;
  buf.len = len;
  send_req = malloc(sizeof(uv_udp_send_t));
  send_req->data = message;
 
#if UV_VERSION_MAJOR == 0       
        uv_udp_send(send_req, &conn->udp_handle, &buf, 1, conn->send_addr, on_send_udp_request);
#else
        uv_udp_send(send_req, &conn->udp_handle, &buf, 1, (const struct sockaddr*) &conn->send_addr, on_send_udp_request);
#endif

  return 0;
}

int _handle_send_tcp_request(hep_connection_t *conn, unsigned char *message, size_t len)
{

  uv_buf_t buf;
  uv_write_t *write_req;

  buf.base = (char *)message;
  buf.len = len;

  write_req = malloc(sizeof(uv_write_t));
  write_req->data = message;

  uv_write(write_req, conn->connect.handle, &buf, 1, on_send_tcp_request);

  return 0;
}


#if UV_VERSION_MAJOR == 0                            
  void _async_callback(uv_async_t *async, int status)
#else
  void _async_callback(uv_async_t *async)
#endif
{
  hep_connection_t *conn;
  hep_request_t *request;
  int result = 0;

  request = (struct hep_request *)async->data;

  if(!request) return;

  conn = request->conn;

  switch (request->request_type) {
    case SEND_UDP_REQUEST:
        result = _handle_send_udp_request(conn, request->message, request->len);
        break;
    case SEND_TCP_REQUEST:
        result = _handle_send_tcp_request(conn, request->message, request->len);
        break;
    case QUIT_REQUEST:
        result = _handle_quit(conn);
        break;
  }
   
  uv_sem_post(&conn->sem);

  if (result != 0) {
    LDEBUG("Request %p, of type %d, failed with error code %d\n", (void *)request, (int)request->request_type, result);
  }
   
  if(request) {    
    free(request); 
    request = NULL;
  }       
}         

int homer_close(hep_connection_t *conn)
{  
  hep_request_t *request = calloc(1, sizeof(hep_request_t));

  LDEBUG("closing connection\n");

  request->conn = conn;
  request->request_type = QUIT_REQUEST;

  uv_mutex_lock(&conn->mutex);

  conn->async_handle.data = request;

  if (conn->type == 2)
    set_conn_state(conn, STATE_SHUTTING_DOWN);
  
  uv_async_send(&conn->async_handle);

  uv_sem_wait(&conn->sem);
  uv_mutex_unlock(&conn->mutex);
   
  uv_thread_join(conn->thread);

  if (conn->type == 2)
    set_conn_state(conn, STATE_SHUT_DOWN);

  return 0;
}


void homer_free(hep_connection_t *conn)
{

  LDEBUG("freeing connection\n");

  if (conn == NULL) {
    return;
  }

#if UV_VERSION_MAJOR == 0

	homer_close(conn);	
        uv_loop_delete(conn->loop);  

#else

	if (uv_loop_alive(conn->loop)) {
		homer_close(conn);
	}

	uv_stop(conn->loop);
	int closed = uv_loop_close(conn->loop);

	while(closed == UV_EBUSY) {
		closed = uv_loop_close(conn->loop);
	}

#endif
   
	uv_sem_destroy(&conn->sem);
	uv_mutex_destroy(&conn->mutex);
	free(conn->loop);  
	free(conn->thread);
}

int _handle_quit(hep_connection_t *conn)
{
   if(conn->type == 1)  {
	  uv_udp_recv_stop(&conn->udp_handle);
	  /* close all the handles */
	  uv_close((uv_handle_t*)&conn->udp_handle, NULL);
   }
   else {
      if (uv_is_active((uv_handle_t*)&conn->tcp_handle)) {
        set_conn_state(conn, STATE_CLOSING);
        uv_close((uv_handle_t*)&conn->tcp_handle, on_tcp_close);
      }
   }

   uv_close((uv_handle_t*)&conn->async_handle, NULL);

   return 0;
}

void _run_uv_loop(void *arg){

      hep_connection_t *conn = (hep_connection_t *)arg;

#if UV_VERSION_MAJOR == 0
        conn->loop->data = conn;
#else               
        uv_key_set(&hep_conn_key, conn);
#endif
                        
      uv_run(conn->loop, UV_RUN_DEFAULT);   
}

/*ASYNC*/

int homer_alloc(hep_connection_t *conn)
{

      //conn = malloc(sizeof(hep_connection_t));      
      
      memset(conn, 0, sizeof(hep_connection_t));      
                
#if UV_VERSION_MAJOR == 0
      conn->loop = uv_loop_new();
#else               
      conn->loop = malloc(sizeof(uv_loop_t));
      uv_loop_init(conn->loop);            
#endif

      uv_sem_init(&conn->sem, 0);
      uv_mutex_init(&conn->mutex);
      conn->thread = malloc(sizeof(uv_thread_t));  
            
  return 1;   
}

int init_udp_socket(hep_connection_t *conn, char *host, int port) {

        struct sockaddr_in v4addr;
        int status = 0;
        struct addrinfo hints[1] = {{ 0 }};            
        struct addrinfo *ai;
        char cport[15];
                  
        hints->ai_family = AF_UNSPEC;        
        hints->ai_socktype = SOCK_DGRAM;
        hints->ai_protocol = IPPROTO_UDP;
        hints->ai_flags = 0;
                
        snprintf(cport, sizeof(cport), "%d", port);

        if ((status = getaddrinfo(host, cport, hints, &ai)) != 0) {
                LERR( "capture: getaddrinfo: %s", gai_strerror(status));
                return 0;   
        }
	
	/* copy structure */
        memcpy(&conn->send_addr, ai->ai_addr, sizeof(struct sockaddr));                                        
        
        uv_async_init(conn->loop, &conn->async_handle, _async_callback);
        uv_udp_init(conn->loop, &conn->udp_handle);  
        
#if UV_VERSION_MAJOR == 0                         
        v4addr = uv_ip4_addr("0.0.0.0", 0);
#else    
        status = uv_ip4_addr("0.0.0.0", 0, &v4addr);
#endif
            
#if UV_VERSION_MAJOR == 0                         
        status = uv_udp_bind(&conn->udp_handle, v4addr,0);
#else    
        status = uv_udp_bind(&conn->udp_handle, (struct sockaddr*)&v4addr, UV_UDP_REUSEADDR);
              
#endif        
        uv_udp_set_broadcast(&conn->udp_handle, 1);
             
        conn->udp_handle.data = conn;
      
        conn->type = 1;

	status = uv_thread_create(conn->thread, _run_uv_loop, conn);
	
        return status;
}

void on_tcp_connect(uv_connect_t* connection, int status)
{
        LDEBUG("connected [%d]\n", status);

#if UV_VERSION_MAJOR == 0                         
        hep_connection_t* hep_conn = connection->handle->loop->data;
#else

        hep_connection_t* hep_conn = uv_key_get(&hep_conn_key);
#endif   
        assert(hep_conn != NULL);        
	
        if (status == 0)
            set_conn_state(hep_conn, STATE_CONNECTED);
        else {
            uv_close((uv_handle_t*)connection->handle, NULL);
            set_conn_state(hep_conn, STATE_ERROR);
        }

        
}

int init_tcp_socket(hep_connection_t *conn, char *host, int port) {

        struct sockaddr_in v4addr;
        int status;
	int err;
	struct addrinfo hints[1] = {{ 0 }};	    
        struct addrinfo *ai;
        char cport[15];
                
        hints->ai_family = AF_UNSPEC;        
        hints->ai_socktype = SOCK_STREAM;
        hints->ai_protocol = IPPROTO_TCP;
        hints->ai_flags = 0;

        snprintf(cport, sizeof(cport), "%d", port);

        if ((status = getaddrinfo(host, cport, hints, &ai)) != 0) {
                LERR( "capture: getaddrinfo: %s", gai_strerror(status));
                return 0;   
        }
	
        uv_async_init(conn->loop, &conn->async_handle, _async_callback);
	err = uv_tcp_init(conn->loop, &conn->tcp_handle);
	if (err) return err;  

        /* copy structure */
        memcpy(&v4addr, (struct sockaddr_in*) ai->ai_addr, sizeof(struct sockaddr_in));
   
	uv_tcp_keepalive(&conn->tcp_handle, 1, 60);

#if UV_VERSION_MAJOR == 0                         
        /* v4addr = uv_ip4_addr(host, port);*/            
#endif

        set_conn_state(conn, STATE_CONNECTING);

        conn->type = 2;
      
#if UV_VERSION_MAJOR == 0                         
        status = uv_tcp_connect(&conn->connect, &conn->tcp_handle, v4addr, on_tcp_connect);
#else    
        status = uv_tcp_connect(&conn->connect, &conn->tcp_handle, (struct sockaddr*)&v4addr, on_tcp_connect);                
#endif

        if(status < 0)
        {
                LERR( "capture: bind error");
                return 2;
        }

	err = uv_thread_create(conn->thread, _run_uv_loop, conn);

        return 0;
}

int sigPipe(void)
{
    signal(SIGPIPE, SIG_IGN);

	return 1;
}

int load_module_xml_config() {

	char module_config_name[500];
	xml_node *next;
	int i = 0;

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, module_name);

	if ((module_xml_config = xml_parse(module_config_name)) == NULL) {
		LERR("Unable to open configuration file: %s", module_config_name);
		return -1;
	}

	/* check if this module is our */
	next = xml_get("module", module_xml_config, 1);

	if (next == NULL) {
		LERR("wrong config for module: %s", module_name);
		return -2;
	}

	for (i = 0; next->attr[i]; i++) {
			if (!strncmp(next->attr[i], "name", 4)) {
				if (strncmp(next->attr[i + 1], module_name, strlen(module_name))) {
					return -3;
				}
			}
			else if (!strncmp(next->attr[i], "serial", 6)) {
				module_serial = atol(next->attr[i + 1]);
			}
			else if (!strncmp(next->attr[i], "description", 11)) {
				module_description = next->attr[i + 1];
			}
	}

	return 1;
}

void free_module_xml_config() {

	/* now we are free */
	if(module_xml_config) xml_free(module_xml_config);
}


/* modules external API */

static int load_module(xml_node *config) {
	xml_node *params, *profile, *settings, *condition, *action;
	char *key, *value = NULL;
	unsigned int i = 0;
	char module_api_name[256];

	LNOTICE("Loaded %s", module_name);

#if UV_VERSION_MAJOR == 0                         
        /* not implemented */
#else    
	uv_key_create(&hep_conn_key);
#endif
                

	load_module_xml_config();
	/* READ CONFIG */
	profile = module_xml_config;

	/* reset profile */
	profile_size = 0;

    sigPipe();

	while (profile) {

		profile = xml_get("profile", profile, 1);

		if (profile == NULL)
			break;

		if(!profile->attr[4] || strncmp(profile->attr[4], "enable", 6)) {
			goto nextprofile;
		}

		/* if not equals "true" */
		if(!profile->attr[5] || strncmp(profile->attr[5], "true", 4)) {
			goto nextprofile;
		}

		/* set values */
		profile_transport[profile_size].name = strdup(profile->attr[1]);
		profile_transport[profile_size].description = strdup(profile->attr[3]);
		profile_transport[profile_size].serial = atoi(profile->attr[7]);
		profile_transport[profile_size].statistic_pipe = NULL;

		/* SETTINGS */
		settings = xml_get("settings", profile, 1);

		if (settings != NULL) {

			params = settings;

			while (params) {

				params = xml_get("param", params, 1);
				if (params == NULL) break;

				if (params->attr[0] != NULL) {

					/* bad parser */
					if (strncmp(params->attr[0], "name", 4)) {
						LERR("bad keys in the config");
						goto nextparam;
					}

					key = params->attr[1];

					if(params->attr[2] && params->attr[3] && !strncmp(params->attr[2], "value", 5)) {
							value = params->attr[3];
					}
					else {
						value = params->child->value;
					}

					if (key == NULL || value == NULL) {
						LERR("bad values in the config");
						goto nextparam;

					}

					if(!strncmp(key, "capture-host", 10)) profile_transport[profile_size].capt_host = strdup(value);
					else if(!strncmp(key, "capture-port", 13)) profile_transport[profile_size].capt_port = strdup(value);
					else if(!strncmp(key, "capture-proto", 14)) profile_transport[profile_size].capt_proto = strdup(value);
					else if(!strncmp(key, "capture-password", 17)) profile_transport[profile_size].capt_password = strdup(value);
					else if(!strncmp(key, "capture-id", 11)) profile_transport[profile_size].capt_id = atoi(value);
					else if(!strncmp(key, "payload-compression", 19) && !strncmp(value, "true", 5)) profile_transport[profile_size].compression = 1;
					else if(!strncmp(key, "version", 7)) profile_transport[profile_size].version = atoi(value);


					//if (!strncmp(key, "ignore", 6))
					//	profile_transport[profile_size].ignore = value;
				}

				nextparam:
					params = params->next;

			}
		}


		/* STATS */

		condition = xml_get("statistic", profile, 1);

		while (condition) {

			condition = xml_get("condition", condition, 1);

			if (condition == NULL)	break;

			if (condition->attr[0] != NULL && condition->attr[2] != NULL) {

						/* bad parser */
						if (strncmp(condition->attr[0], "field", 5) || strncmp(condition->attr[2], "expression", 10)) {
							LERR("bad keys in the config");
							goto nextstatistic;
						}

						key = condition->attr[1];
						value = condition->attr[3];

						if (key == NULL || value == NULL) {
							LERR("bad values in the config");
							goto nextstatistic;
						}

						action = condition->child;
						if (action && !strncmp(action->key, "action", 6)) {
							for (i = 0; action->attr[i]; i++) {
								if (!strncmp(action->attr[i], "application", 4)) {
									profile_transport[profile_size].statistic_pipe = strdup(action->attr[i + 1]);
								}
								else if (!strncmp(action->attr[i], "profile", 7)) {
									profile_transport[profile_size].statistic_profile = strdup(action->attr[i + 1]);
								}
							}
						}
			}

			nextstatistic: condition = condition->next;
		}

		profile_size++;

		nextprofile:
			profile = profile->next;
	}

	/* free it */
	free_module_xml_config();


	for (i = 0; i < profile_size; i++) {

#ifndef USE_ZLIB
			if(profile_transport[i].compression) {
				printf("The captagent has not compiled with zlib. Please reconfigure with --enable-compression\n");
				LERR("The captagent has not compiled with zlib. Please reconfigure with --enable-compression");
			}
#endif /* USE_ZLIB */
			homer_alloc(&hep_connection_s[i]);
			
			if(!strncmp(profile_transport[i].capt_proto, "udp", 3))
			{
				init_udp_socket(&hep_connection_s[i], profile_transport[i].capt_host, atoi(profile_transport[i].capt_port));
			}
			else 
{				init_tcp_socket(&hep_connection_s[i], profile_transport[i].capt_host, atoi(profile_transport[i].capt_port));
			}

			if(profile_transport[i].statistic_pipe) {
				snprintf(module_api_name, 256, "%s_bind_api", profile_transport[i].statistic_pipe);
			}
	}

	return 0;
}

static int unload_module(void)
{
	unsigned int i = 0;

	LNOTICE("unloaded module transport_hep");

	for (i = 0; i < profile_size; i++) {

			free_profile(i);
	}

#if UV_VERSION_MAJOR == 0                         
        /* not implemented */
#else    
	uv_key_delete(&hep_conn_key);
#endif
              
    return 0;
}

static uint64_t serial_module(void)
{
	 return module_serial;
}

static int free_profile(unsigned int idx) {

	/*free profile chars **/

	if (profile_transport[idx].name)	 free(profile_transport[idx].name);
	if (profile_transport[idx].description) free(profile_transport[idx].description);
	if (profile_transport[idx].capt_host) free(profile_transport[idx].capt_host);
	if (profile_transport[idx].capt_port) free(profile_transport[idx].capt_port);
	if (profile_transport[idx].capt_proto) free(profile_transport[idx].capt_proto);
	if (profile_transport[idx].capt_password) free(profile_transport[idx].capt_password);
	if (profile_transport[idx].statistic_pipe) free(profile_transport[idx].statistic_pipe);
	if (profile_transport[idx].statistic_profile) free(profile_transport[idx].statistic_profile);

	return 1;
}


static int description(char *descr)
{
       LNOTICE("Loaded description");
       descr = module_description;
       return 1;
}

static int statistic(char *buf, size_t len)
{
	int ret = 0;

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.received_packets_total);
	ret += snprintf(buf+ret, len-ret, "Reconnect total: [%" PRId64 "]\r\n", stats.reconnect_total);
	ret += snprintf(buf+ret, len-ret, "Errors total: [%" PRId64 "]\r\n", stats.errors_total);
	ret += snprintf(buf+ret, len-ret, "Compressed total: [%" PRId64 "]\r\n", stats.compressed_total);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets_total);


	return 1;

}

static void reconnect(int idx)
{
    time_t cur_time = time(NULL);

    // Don't reconnect more then every 2 secs.
    if (cur_time - hep_connection_s[idx].conn_state_changed_time < 2)
        return;

    homer_close(&hep_connection_s[idx]);

    init_tcp_socket(&hep_connection_s[idx], profile_transport[idx].capt_host, atoi(profile_transport[idx].capt_port));
}

static const char* 	get_state_label(conn_state_type_t state)
{
	switch (state)
	{
		case STATE_INIT:
			return "INIT";
		case STATE_CONNECTING:
			return "CONNECTING";
		case STATE_CONNECTED:
			return "CONNECTED";
		case STATE_CLOSING:
			return "CLOSING";
		case STATE_CLOSED:
			return "CLOSED";
		case STATE_SHUTTING_DOWN:
			return "SHUTTING_DOWN";
		case STATE_SHUT_DOWN:
			return "SHUT_DOWN";
		case STATE_ERROR:
			return "ERROR";
		default:
			return "UNKNOWN";
	}
}

static void set_conn_state(hep_connection_t* conn, conn_state_type_t new_conn_state)
{
	if (conn->conn_state == new_conn_state)
		return;

	conn_state_type_t old_state = conn->conn_state;
	conn->conn_state = new_conn_state; 
	conn->conn_state_changed_time = time(NULL);

	LNOTICE("Connection state change: %s => %s", get_state_label(old_state), get_state_label(new_conn_state));
}
