
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
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

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#include <pcap.h>

#include "src/api.h"
#include "core_hep.h"


pthread_t call_thread;   


int send_hep_basic (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

    struct hep_generic *hg=NULL;
    void* buffer;
    unsigned int buflen=0;
            
    hg = malloc(sizeof(struct hep_generic));
    memset(hg, 0, sizeof(struct hep_generic));

    /* header set */
    memcpy(hg->header.id, "\x48\x45\x50\x33", 4);

    /* IP proto */
    hg->ipproto.chunk.vendor_id = htons(0x0000);
    hg->ipproto.chunk.type_id   = htons(0x0001);
    hg->ipproto.data = rcinfo->ipproto;
    hg->ipproto.chunk.length = sizeof(hg->ipproto);
    
    /* Proto ID */
    hg->proto_id.chunk.vendor_id = htons(0x0000);
    hg->proto_id.chunk.type_id   = htons(0x0002);
    hg->proto_id.data = rcinfo->proto_id;
    hg->proto_id.chunk.length = sizeof(hg->proto_id);
    

    /* IPv4 */
    if(rcinfo->ipproto == AF_INET) {
        /* SRC IP */
        hg->src_ip4.chunk.vendor_id = htons(0x0000);
        hg->src_ip4.chunk.type_id   = htons(0x0003);
        //int inet_pton(int af, const char *src, void *dst);        
        inet_pton(AF_INET, rcinfo->src_ip, &hg->src_ip4.data);
        hg->src_ip4.chunk.length = sizeof(hg->src_ip4);
        
        /* DST IP */
        hg->dst_ip4.chunk.vendor_id = htons(0x0000);
        hg->dst_ip4.chunk.type_id   = htons(0x0004);
        inet_pton(AF_INET, rcinfo->dst_ip, &hg->dst_ip4.data);
        
        hg->dst_ip4.chunk.length = sizeof(hg->dst_ip4);
    }
    /* IPv6 */
    else if(rcinfo->ipproto == AF_INET6) {
        /* SRC IPv6 */
        hg->src_ip6.chunk.vendor_id = htons(0x0000);
        hg->src_ip6.chunk.type_id   = htons(0x0005);
        inet_pton(AF_INET6, rcinfo->src_ip, &hg->src_ip6.data);
        hg->src_ip6.chunk.length = sizeof(hg->src_ip6);
        
        /* DST IPv6 */
        hg->dst_ip6.chunk.vendor_id = htons(0x0000);
        hg->dst_ip6.chunk.type_id   = htons(0x0006);
        inet_pton(AF_INET6, rcinfo->dst_ip, &hg->dst_ip6.data);
        hg->dst_ip6.chunk.length = sizeof(hg->dst_ip6);    
    
    }
        
    /* SRC PORT */
    hg->src_port.chunk.vendor_id = htons(0x0000);
    hg->src_port.chunk.type_id   = htons(0x0007);
    hg->src_port.data = htons(rcinfo->src_port);
    hg->src_port.chunk.length = sizeof(hg->src_port);
    
    /* DST PORT */
    hg->dst_port.chunk.vendor_id = htons(0x0000);
    hg->dst_port.chunk.type_id   = htons(0x0008);
    hg->dst_port.data = htons(rcinfo->dst_port);
    hg->dst_port.chunk.length = sizeof(hg->dst_port);
    
    
    /* TIMESTAMP SEC */
    hg->time_sec.chunk.vendor_id = htons(0x0000);
    hg->time_sec.chunk.type_id   = htons(0x0009);
    hg->time_sec.data = htons(rcinfo->time_sec);
    hg->time_sec.chunk.length = sizeof(hg->time_sec);
    

    /* TIMESTAMP USEC */
    hg->time_usec.chunk.vendor_id = htons(0x0000);
    hg->time_usec.chunk.type_id   = htons(0x000a);
    hg->time_usec.data = htons(rcinfo->time_usec);
    hg->time_usec.chunk.length = sizeof(hg->time_usec);
    
    /* Protocol TYPE */
    hg->proto_t.chunk.vendor_id = htons(0x0000);
    hg->proto_t.chunk.type_id   = htons(0x000b);
    hg->proto_t.data = 0x01;
    hg->proto_t.chunk.length = sizeof(hg->proto_t);
    
    /* Capture ID */
    hg->capt_id.chunk.vendor_id = htons(0x0000);
    hg->capt_id.chunk.type_id   = htons(0x000c);
    hg->capt_id.data = htons(0x0001);
    hg->capt_id.chunk.length = sizeof(hg->capt_id);

    /* Payload */
    hg->payload.vendor_id = htons(0x0000);
    hg->payload.type_id   = htons(0x000f);
    hg->payload.length    = htons(len);
                       

    //printf("JA: LEN: %d [%.*s]\n", len, len, data);
   
    /* total */
    hg->header.length = htons(sizeof(struct hep_generic) + len);

    buffer = (void*)malloc(sizeof(struct hep_generic) + len);
    if (buffer==0){
        fprintf(stderr,"ERROR: out of memory\n");
        free(hg);
        return 1;
    }
    
    memcpy((void*) buffer, hg, sizeof(struct hep_generic));
    buflen = sizeof(struct hep_generic);

    /*    
    printf("LEN: %u\n", buflen);    
    printf("LEN HEADER: %lu\n", sizeof(hep_ctrl_t));
    printf("LEN IPPROTO: %lu\n", sizeof(hep_chunk_uint8_t));
    printf("LEN PROTOID: %lu\n", sizeof(hep_chunk_uint8_t));
    printf("LEN SRC: %lu\n", sizeof(hep_chunk_ip4_t));
    printf("LEN DST: %lu\n", sizeof(hep_chunk_ip4_t));
    printf("LEN SRC2: %lu\n", sizeof(hep_chunk_ip6_t));
    printf("LEN DST2: %lu\n", sizeof(hep_chunk_ip6_t));
    printf("LEN PORTS: %lu\n", sizeof(hep_chunk_uint16_t));
    printf("LEN PORTD: %lu\n", sizeof(hep_chunk_uint16_t));
    printf("LEN TIME: %lu\n", sizeof(hep_chunk_uint32_t));
    printf("LEN TIME2: %lu\n", sizeof(hep_chunk_uint32_t));
    printf("LEN PROTO: %lu\n", sizeof(hep_chunk_uint8_t));
    printf("LEN CAPT: %lu\n", sizeof(hep_chunk_uint32_t));
    printf("LEN TM: %lu\n", sizeof(hep_chunk_uint16_t));
    printf("LEN KEY: %lu\n", sizeof(hep_chunk_str_t));
    printf("LEN PAYLOAD: %lu\n", sizeof(hep_chunk_t));

    */

    /* Now copying payload self */
    memcpy((void*) buffer+buflen, data, len);    
    buflen+=len;
    
    
    /* send this packet out of our socket */
    send(sock, buffer, buflen, 0); 
    
    //printf("DUPLICATED [%d] [%.*x]\n", buflen, buflen, buffer);
    
    /* FREE */        
    if(buffer) free(buffer);
    if(hg) free(hg);        
    
    return 1;
}


int unload_module(void)
{
        //return ast_unregister_application(app);
        printf("unloaded module\n");

	 /* Close socket */
        close(sock);
        
        //pthread_join(call_thread, NULL);
                
        return 0;
}


int load_module(xml_node *config)
{
	xml_node *modules;
        int mode;
        struct addrinfo *ai, hints[1] = {{ 0 }};
        char *key, *value;

	/* READ CONFIG */
	modules = config;

	while(1) {
        	if(modules ==  NULL) break;
                modules = xml_get("param", modules, 1 );
                if(modules->attr[0] != NULL && modules->attr[2] != NULL) {
                        
                        /* bad parser */
                        if(strncmp(modules->attr[2], "value", 5) || strncmp(modules->attr[0], "name", 4)) {                        
                            fprintf(stderr, "bad keys in the config\n");
                            goto next;
                        
                        }
                        
                        key =  modules->attr[1];
                        value = modules->attr[3];
                        
                        if(key == NULL || value == NULL) {
                            fprintf(stderr, "bad values in the config\n");
                            goto next;                        
                        
                        }                        

                        if(!strncmp(key, "capture-host", 10)) capt_host = value;
                        else if(!strncmp(key, "capture-port", 13)) capt_port = value;
                        else if(!strncmp(key, "capture-proto", 14)) capt_proto = value;
                        else if(!strncmp(key, "capture-password", 17)) capt_password = value;
                        else if(!strncmp(key, "capture-id", 11)) capt_id = atoi(value);
                        else if(!strncmp(key, "version", 7)) hep_version = atoi(value);
                                	                	                	
		}
next:		
		
                modules = modules->next;
	}

        printf("Loaded load_module\n");
                                           
        hints->ai_flags = AI_NUMERICSERV;
        hints->ai_family = AF_UNSPEC;

        if(!strncmp(capt_proto, "udp", 3)) {
            hints->ai_socktype = SOCK_DGRAM;
            hints->ai_protocol = IPPROTO_UDP;
        }        
        else if(!strncmp(capt_proto, "tcp", 3)) {
            hints->ai_socktype = SOCK_STREAM;
            hints->ai_protocol = IPPROTO_TCP;
        }
        else {        
            printf("Unsupported protocol\n");
            return -1;
        }

        if (getaddrinfo(capt_host, capt_port, hints, &ai)) {
            fprintf(stderr,"capture: getaddrinfo() error");
            return 2;
        }

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
                 fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));
                 return 3;
        }

        mode = fcntl(sock, F_GETFL, 0);
        mode |= O_NDELAY | O_NONBLOCK;
        fcntl(sock, F_SETFL, mode);

        if (connect(sock, ai->ai_addr, (socklen_t)(ai->ai_addrlen)) == -1) {
            if (errno != EINPROGRESS) {
                    fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));
                    return 4;
            }
        }

        return 0;
        //return ast_register_application(app, MYSQL_exec, synopsis, descrip);
}

int usecount(void)
{
        printf("Loaded usecount\n");        
        
        return 1;
        //return ast_register_application(app, MYSQL_exec, synopsis, descrip);
}

char *description(void)
{
        printf("Loaded description\n");
        char *description = "test description";
        
        return description;
        //return ast_register_application(app, MYSQL_exec, synopsis, descrip);
}


