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

bind_statistic_module_api_t stats_bind_api;
unsigned int sslInit = 0;
unsigned int profile_size = 0;

static cmd_export_t cmds[] = {
        {"transport_hep_bind_api",  (cmd_function)bind_usrloc,   1, 0, 0, 0},
        { "send_hep", (cmd_function) w_send_hep_api, 1, 0, 0, 0 },
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

int bind_usrloc(transport_module_api_t *api)
{
		api->send_f = send_hep;
		api->reload_f = reload_config;
		api->module_name = module_name;

        return 0;
}

int w_send_hep_api(msg_t *_m, char *param1) 
{
    
    int ret = 0;

    _m->profile_name = param1;
        
    ret =  send_hep(_m);    
    
    return ret;
}

int w_send_hep_proto(msg_t *_m, char *param1, char *param2) 
{
    
    int ret = 0;

    _m->profile_name = param1;
    _m->rcinfo.proto_type = atoi(param2);
        
    ret =  send_hep(_m);    
    
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

int send_hep (msg_t *msg) {

        unsigned char *zipData = NULL;
        rc_info_t *rcinfo = NULL;
        int sendzip = 0;
        unsigned int idx = 0;
        int ret = 0;

        idx = get_profile_index_by_name(msg->profile_name);
        rcinfo = &msg->rcinfo;

        stats.recieved_packets_total++;

#ifdef USE_ZLIB
        int status = 0;
        unsigned long dlen;

        if(pl_compress && hep_version == 3) {
                //dlen = len/1000+len*len+13;

                dlen = compressBound(len);

                zipData  = malloc(dlen); /* give a little bit memmory */

                /* do compress */
                status = compress( zipData, &dlen, data, len );
                if( status != Z_OK ){
                	  LERR("data couldn't be compressed");
                      sendzip = 0;
                      if(zipData) free(zipData); /* release */
                }
                else {
                        sendzip = 1;
                        len = dlen;
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

        if(msg->data.mfree == 1) free(msg->data);
        if(pl_compress && zipData) free(zipData);

#endif /* USE_ZLIB */

        return ret;
}


int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int sendzip, unsigned int idx) {

    struct hep_generic *hg=NULL;
    void* buffer;
    unsigned int buflen=0, iplen=0,tlen=0;
    hep_chunk_ip4_t src_ip4, dst_ip4;
#ifdef USE_IPV6
    hep_chunk_ip6_t src_ip6, dst_ip6;
#endif
    hep_chunk_t payload_chunk;
    hep_chunk_t authkey_chunk;
    hep_chunk_t correlation_chunk;
    static int errors = 0;

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
#ifdef USE_IPV6
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
    hg->capt_id.data = htons(profile_transport[idx].capt_id);
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

    /* total */
    hg->header.length = htons(tlen);

    buffer = (void*)malloc(tlen);
    if (buffer==0){
        LERR("ERROR: out of memory");
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
#ifdef USE_IPV6
      /* IPv6 */
    else if(rcinfo->ip_family == AF_INET6) {
        /* SRC IPv6 */
        memcpy((void*) buffer+buflen, &src_ip4, sizeof(struct hep_chunk_ip6));
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

    /* PAYLOAD CHUNK */
    memcpy((void*) buffer+buflen, &payload_chunk,  sizeof(struct hep_chunk));
    buflen +=  sizeof(struct hep_chunk);

    /* Now copying payload self */
    memcpy((void*) buffer+buflen, data, len);
    buflen+=len;

    /* make sleep after 100 errors */
     if(errors > 50) {
        LERR( "HEP server is down... retrying after sleep...");
        if(!profile_transport[idx].usessl) {
             sleep(2);
             if(init_hepsocket_blocking(idx)) {
            	 profile_transport[idx].initfails++;
             }

             errors=0;
        }
#ifdef USE_SSL
        else {
                sleep(2);

                if(initSSL(idx)) profile_transport[idx].initfails++;

                errors=0;
         }
#endif /* USE SSL */

     }

    /* send this packet out of our socket */
    if(send_data(buffer, buflen, idx)) {
        errors++;
        stats.errors_total++;
    }

    /* FREE */
    if(buffer) free(buffer);
    if(hg) free(hg);

    return 1;
}


int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len, unsigned int idx) {

    void* buffer;
    struct hep_hdr hdr;
    struct hep_timehdr hep_time;
    struct hep_iphdr hep_ipheader;
    unsigned int totlen=0, buflen=0;
    static int errors=0;
#ifdef USE_IPV6
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
#ifdef USE_IPV6
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
#ifdef USE_IPV6
        case AF_INET6:

                inet_pton(AF_INET6, rcinfo->src_ip, &hep_ip6header.hp6_src);
                inet_pton(AF_INET6, rcinfo->dst_ip, &hep_ip6header.hp6_dst);

                /* copy hep6 ipheader */
                memcpy((void*)buffer + buflen, &hep_ip6header, sizeof(struct hep_ip6hdr));
                buflen += sizeof(struct hep_ip6hdr);
                break;
#endif /* USE_IPV6 */
     }

     /* Version 2 has timestamp, captnode ID */
     if(profile_transport[idx].version == 2) {
        /* TIMING  */
        memcpy((void*)buffer + buflen, &hep_time, sizeof(struct hep_timehdr));
        buflen += sizeof(struct hep_timehdr);
     }

     memcpy((void *)(buffer + buflen) , (void*)(data), len);
     buflen +=len;

     /* make sleep after 100 errors*/
     if(errors > 50) {
    	 LERR("HEP server is down... retrying after sleep...");
        if(!profile_transport[idx].usessl) {
             sleep(2);
             if(init_hepsocket_blocking(idx)) profile_transport[idx].initfails++;
             errors=0;
        }
#ifdef USE_SSL
        else {
            sleep(2);
            if(initSSL(idx)) profile_transport[idx].initfails++;
            errors=0;
        }
#endif /* USE SSL */

     }

     /* send this packet out of our socket */
     if(send_data(buffer, buflen, idx)) {
             errors++;
             stats.errors_total++;
     }

     /* FREE */
     if(buffer) free(buffer);

     return 1;

error:
     if(buffer) free(buffer);
     return 0;
}

int send_data (void *buf, unsigned int len, unsigned int idx) {

        /* send this packet out of our socket */
        void * p = buf;
        int sentbytes = 0;

        if(!profile_transport[idx].usessl) {
                size_t sendlen = send(profile_transport[idx].socket, p, len, 0);
                if(sendlen == -1) {
                	LERR("HEP send error.");
                    return -1;
                }
        }
#ifdef USE_SSL
        else {
            if(SSL_write(profile_transport[idx].ssl, buf, len) < 0) {
            	LERR("capture: couldn't re-init ssl socket");
                return -1;
            }
        }
#endif

        stats.send_packets_total++;

        /* RESET ERRORS COUNTER */
        return 0;
}



int init_hepsocket (unsigned int idx) {

    struct timeval tv;
    socklen_t lon;
    long arg;
    fd_set myset;
    int valopt, res, ret = 0, s;
    struct addrinfo *ai;
    struct addrinfo hints[1] = {{ 0 }};

    if(profile_transport[idx].socket) close(profile_transport[idx].socket);

    if ((s = getaddrinfo(profile_transport[idx].capt_host, profile_transport[idx].capt_port, hints, &ai)) != 0) {
            LERR("capture: getaddrinfo: %s", gai_strerror(s));
            return 2;
    }

    if((profile_transport[idx].socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
             LERR("Sender socket creation failed: %s", strerror(errno));
             return 1;
    }

    // Set non-blocking
    if((arg = fcntl(profile_transport[idx].socket, F_GETFL, NULL)) < 0) {
        LERR( "Error fcntl(..., F_GETFL) (%s)", strerror(errno));
        close(profile_transport[idx].socket);
        return 1;
    }
    arg |= O_NONBLOCK;
    if( fcntl(profile_transport[idx].socket, F_SETFL, arg) < 0) {
        LERR( "Error fcntl(..., F_SETFL) (%s)", strerror(errno));
        close(profile_transport[idx].socket);
        return 1;
    }

    if((res = connect(profile_transport[idx].socket, ai->ai_addr, (socklen_t)(ai->ai_addrlen))) < 0) {
        if (errno == EINPROGRESS) {
                do {
                   tv.tv_sec = 5;
                   tv.tv_usec = 0;
                   FD_ZERO(&myset);
                   FD_SET(profile_transport[idx].socket, &myset);

                   res = select(profile_transport[idx].socket + 1 , NULL, &myset, NULL, &tv);

                   if (res < 0 && errno != EINTR) {
                      LERR( "Error connecting %d - %s", errno, strerror(errno));
                      close(profile_transport[idx].socket);
                      ret = 1;
                      break;
                   }
                   else if (res > 0) {
                      // Socket selected for write

                      lon = sizeof(int);
                      if (getsockopt(profile_transport[idx].socket, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
                         close(profile_transport[idx].socket);
                         LERR( "Error in getsockopt() %d - %s", errno, strerror(errno));
                         ret = 2;
                      }
                      // Check the value returned...
                      if (valopt) {
                         close(profile_transport[idx].socket);
                         LERR( "Error in delayed connection() %d - %s", valopt, strerror(valopt));
                         ret = 3;
                      }
                      break;
                   }
                   else {
                      close(profile_transport[idx].socket);
                      LERR( "Timeout in select() - Cancelling!");
                      ret = 4;
                      break;
                   }
                } while (1);
        }
    }

    return ret;
}

int init_hepsocket_blocking (unsigned int idx) {

    int s, ret = 0;
    struct timeval tv;
    struct addrinfo *ai;
    struct addrinfo hints[1] = {{ 0 }};

    stats.reconnect_total++;

    hints->ai_flags = AI_NUMERICSERV;
    hints->ai_family = AF_UNSPEC;

    if(!strncmp(profile_transport[idx].capt_proto, "udp", 3)) {
               hints->ai_socktype = SOCK_DGRAM;
               hints->ai_protocol = IPPROTO_UDP;
    }
    else if(!strncmp(profile_transport[idx].capt_proto, "tcp", 3) || !strncmp(profile_transport[idx].capt_proto, "ssl", 3)) {
               hints->ai_socktype = SOCK_STREAM;
               hints->ai_protocol = IPPROTO_TCP;
    }

    if(profile_transport[idx].socket) close(profile_transport[idx].socket);

    if ((s = getaddrinfo(profile_transport[idx].capt_host, profile_transport[idx].capt_port, hints, &ai)) != 0) {
            LERR( "capture: getaddrinfo: %s", gai_strerror(s));
            return 2;
    }

    if((profile_transport[idx].socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
             LERR("Sender socket creation failed: %s", strerror(errno));
             return 1;
    }

    if ((ret = connect(profile_transport[idx].socket, ai->ai_addr, (socklen_t)(ai->ai_addrlen))) == -1) {

         //select(profile_transport[idx].socket + 1 , NULL, &myset, NULL, &tv);
         if (errno != EINPROGRESS) {
             LERR("Sender socket creation failed: %s", strerror(errno));
             return 1;
          }
    }

    return 0;
}


#ifdef USE_SSL
SSL_CTX* initCTX(void) {
        SSL_METHOD *method;
        SSL_CTX *ctx;

        OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
        SSL_load_error_strings();   /* Bring in and register error messages */

        /* we use SSLv3 */
        /* method = SSLv3_client_method();  */
        method = TLSv1_method(); /* Create new client-method instance */

        ctx = SSL_CTX_new(method);   /* Create new context */
        if ( ctx == NULL ) {
                ERR_print_errors_fp(stderr);
                abort();
        }
        return ctx;
}


void showCerts(SSL* ssl) {

        X509 *cert;
        char *line;

        cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
        if ( cert != NULL ) {
                LDEBUG("Server certificates:");
                line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                LDEBUG("Subject: %s", line);
                free(line);       /* free the malloc'ed string */
                line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                LDEBUG("Issuer: %s", line);
                free(line);       /* free the malloc'ed string */
                X509_free(cert);     /* free the malloc'ed certificate copy */
        }
        else
                LERR("No certificates.");
}

int initSSL(unsigned int idx) {

        long ctx_options;

        /* if(ssl) SSL_free(ssl);
        if(ctx) SSL_CTX_free(ctx);
        */

        if(init_hepsocket_blocking(idx)) {
                LERR("capture: couldn't init hep socket");
                return 1;
        }

        profile_transport[idx].ctx = initCTX();

        /* workaround bug openssl */
        ctx_options = SSL_OP_ALL;
        ctx_options |= SSL_OP_NO_SSLv2;
        ctx_options |= SSL_OP_NO_SSLv3;
        SSL_CTX_set_options(profile_transport[idx].ctx, ctx_options);

        /*extra*/
        SSL_CTX_ctrl(profile_transport[idx].ctx, BIO_C_SET_NBIO, 1, NULL);

        /* create new SSL connection state */
        profile_transport[idx].ssl = SSL_new(profile_transport[idx].ctx);

        SSL_set_connect_state(profile_transport[idx].ssl);

        /* attach socket */
        SSL_set_fd(profile_transport[idx].ssl, profile_transport[index].socket);    /* attach the socket descriptor */

        /* perform the connection */
        if ( SSL_connect(profile_transport[idx].ssl) == -1 )  {
              ERR_print_errors_fp(stderr);
              return 1;
        }

        showCerts(profile_transport[idx].ssl);

        return 0;
}

#endif /* use SSL */


int handlerPipe(void) {

        LERR("SIGPIPE... trying to reconnect...");
        return 1;
}


int sigPipe(void)
{

	struct sigaction new_action;

	/* sigation structure */
	new_action.sa_handler = handlerPipe;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	if (sigaction(SIGPIPE, &new_action, NULL) == -1) {
		LERR("Failed to set new Handle");
		return -1;
	}

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

	load_module_xml_config();
	/* READ CONFIG */
	profile = module_xml_config;

	/* reset profile */
	profile_size = 0;

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

			/*TLS || SSL*/
			if(!strncmp(profile_transport[i].capt_proto, "ssl", 3)) {

#ifdef USE_SSL
				profile_transport[i].usessl = 1;
				/* init SSL library */
				if(sslInit == 0) {
					SSL_library_init();
					sslInit = 1;
				}
#else
				printf("The captagent has not compiled with ssl support. Please reconfigure with --enable-ssl\n");
				LERR("The captagent has not compiled with ssl support. Please reconfigure with --enable-ssl");

#endif /* end USE_SSL */
			}

			if(!profile_transport[i].usessl) {
				if(init_hepsocket_blocking(i)) {
					LERR("capture: couldn't init socket");
				}
			}

#ifdef USE_SSL
			else {
				if(initSSL(i)) {
					LERR("capture: couldn't init SSL socket");
				}
			}
#endif /* use SSL */

			if(profile_transport[i].statistic_pipe) {
				snprintf(module_api_name, 256, "%s_bind_api", profile_transport[i].statistic_pipe);
				//stats_bind_api = (bind_statistic_module_api_t) find_export(module_api_name, 1, 0);
				//stats_bind_api(&profile_transport[i].stats_api);
			}
	}

	sigPipe();

	return 0;
}

static int unload_module(void)
{
	unsigned int i = 0;

	LNOTICE("unloaded module transport_hep");

	for (i = 0; i < profile_size; i++) {

			free_profile(i);
	}

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

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.recieved_packets_total);
	ret += snprintf(buf+ret, len-ret, "Reconnect total: [%" PRId64 "]\r\n", stats.reconnect_total);
	ret += snprintf(buf+ret, len-ret, "Errors total: [%" PRId64 "]\r\n", stats.errors_total);
	ret += snprintf(buf+ret, len-ret, "Compressed total: [%" PRId64 "]\r\n", stats.compressed_total);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets_total);


	return 1;

}
                        
