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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
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
#endif
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>

#include <captagent/capture.h>
#include <captagent/globals.h>
#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "socket_pcap.h"
#include <captagent/log.h>
#include <captagent/action.h>
#include "ipreasm.h"
#include "tcpreasm.h"
#include "localapi.h"
#include "sctp_support.h"

#if USE_IPv6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include "uthash.h"
/* ### Declaration of HASH TABLE FOR HANDSHAKE FLOWS ### */
extern struct Hash_Table *HT_Flows;

xml_node *module_xml_config = NULL;

uint8_t link_offset = 14;
uint16_t type_datalink = 0;

char *module_name = "socket_pcap";
uint64_t module_serial = 0;
char *module_description;
int debug_socket_pcap_enable = 0;
int websocket_detection = 0;

static socket_pcap_stats_t stats;
static socket_pcap_user_data_t user_data[MAX_SOCKETS];

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t call_thread[MAX_SOCKETS];
pcap_t *sniffer_proto[MAX_SOCKETS];
pthread_t stat_thread;
bool stats_enable = FALSE;

struct pcap_stat last_stat[MAX_SOCKETS];
struct reasm_ip *reasm[MAX_SOCKETS];
struct tcpreasm_ip *tcpreasm[MAX_SOCKETS];

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static uint64_t serial_module(void);
static int free_profile(unsigned int idx);

bool websocket_header_detection(uint8_t *p_websock, uint32_t posLen, unsigned char *data, uint32_t hdrLen);
bool websocket_pre_decode(uint8_t *p_websock, uint8_t *decoded, msg_t *_msg);

unsigned int profile_size = 0;
int verbose = 0;
int stats_interval = 300;
int drop_limit = 25;
int ipindex = -1;

char ipcheck_in[10][80] =  {{0},{0}};
char ipcheck_out[10][80]=  {{0},{0}};
int port_in[10]         =  {0};
int port_out[10]        =  {0};

bind_protocol_module_api_t proto_bind_api;

static cmd_export_t cmds[] = {
    { "socket_pcap_bind_api", (cmd_function) bind_api,               1, 0, 0, 0 },
    { "socket_pcap_check",    (cmd_function) bind_check_size,        3, 0, 0, 0 },
    { "bind_socket_pcap",     (cmd_function) bind_socket_pcap,       0, 0, 0, 0 },
    { "tzsp_payload_extract", (cmd_function) w_tzsp_payload_extract, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
    "socket_pcap",
    cmds,           /* Exported functions */
    load_module,    /* module initialization function */
    unload_module,
    description,
    statistic,
    serial_module
};


int bind_api(socket_module_api_t* api)
{
    api->reload_f = reload_config;
    api->apply_filter_f = apply_filter;
    api->module_name = module_name;
    return 0;
}

int bind_check_size(msg_t *_m, char *param1, char *param2)
{
    return 0;
}

int apply_filter(filter_msg_t *filter)
{
	return 1;
}

int reload_config(char *erbuf, int erlen) {

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

/**
   Function to check the ports in the pkts to the port(or portrange) defined in filter
   NOTE: this is to trigger correctly the function strip_fcs_end()
   @par filter = the BPF filter
   @par port_arg1 = the source port from pkt
   @par port_arg2 = the destination port from pkt

   @return 0 if port matched; -1 if port NOT matched
 **/
static int check_port_filter(char *filter, int port_arg1, int port_arg2) {
    
    char port_str[10], port_str_1[10], port_str_2[10];
    int len1, ret, port = 0, portrange = 0;
    char *space, *dash, *p, *end;
    
    len1 = strlen(filter);
    end = filter+len1-1;

    p = strstr(filter, "portrange");
    if(p) {
        portrange = 1;
    } else {
        p = strstr(filter, "port");
        if(p) {
            port = 1;
        } else {
            LERR("error - bad BPF here\n");
            return -1;
        }
    }
    
    space = strchr(filter, ' ');
    filter = space + 1;
    memcpy(port_str, filter, end - filter + 1);
    
    if(port == 1) { /* Extract port */       
        int port_int = atoi(port_str);
        if(port_int == port_arg1 || port_int == port_arg2) {
            LDEBUG("Port match!\n");
            ret = 0;
        } else {
            LDEBUG("Port does not match: [%d] vs [%d][%d]\n", port_int, port_arg1, port_arg2);
            ret = -1;
        }
        
    } else if(portrange == 1) { /* Extract portrange */        
        
        dash = strchr(filter, '-');
        memcpy(port_str_1, filter, dash - filter + 1);
        int port_int_1 = atoi(port_str_1);
        filter = dash + 1;
        memcpy(port_str_2, filter, end - filter + 1);
        int port_int_2 = atoi(port_str_2);
        
        if((port_arg1 >= port_int_1 && port_arg1 <= port_int_2) ||
           (port_arg2 >= port_int_1 && port_arg2 <= port_int_2)) {
            LDEBUG("Port match!\n");
            ret = 0;
        } else {
            LDEBUG("Port does not match: [%d][%d] v [%d][%d]\n", port_int_1, port_int_2, port_arg1, port_arg2);
            ret = -1;
        }
    }
    
    return ret;
}

/**
   Function to strip out fcs byte in the end of pkts (if exist)
   @par data = the payload to parse
   @par len  = the len of the payload

   @return the new len of payload stripped
**/
static int strip_fcs_end(unsigned char *data, int len) {
    
    if(data == NULL || len == 0)
        return 0;
    
    do {
        if((data[len-1] == 0x0a && data[len-2] == 0x0d) ||
           data[len-1] == 0x0d) {
            return len;
        } else {
            len--;
        }
    } while(data[len-1] != 0x0a);

    return len;
}

static void websocket_decode(char *dst, const char *src, size_t len, const char mask[4])
{
    int i;
    for(i = 0; i < len; i++) {
        dst[i] = src[i] ^ mask[i % 4];
    }
}

/* Callback function that is passed to pcap_loop() */
void callback_proto(u_char *arg, struct pcap_pkthdr *pkthdr, u_char *packet) {

    msg_t _msg;                 /* MSG to send */
    struct ether_header* eth = NULL;
    struct sll_header*   sll = NULL;
    struct ip*           ip4_pkt = NULL;
    struct ip6_hdr*      ip6_pkt = NULL;
    struct run_act_ctx   ctx;

    char ip_src[INET6_ADDRSTRLEN + 1], ip_dst[INET6_ADDRSTRLEN + 1];
    char mac_src[20] = {0}, mac_dst[20] = {0};

    uint32_t ip_ver;
    int ipip_offset = 0, vlan_count = 0, action_idx = 0;
    uint16_t type_ip = 0;
    uint8_t hdr_preset = 0, hdr_offset = 0, vlan = 0;          
    uint8_t ip_proto = 0, erspan_offset = 0;
    uint8_t tmp_ip_proto = 0, tmp_ip_len = 0;

    unsigned char* ethaddr  = NULL;
    unsigned char* mplsaddr = NULL;
    unsigned char* cooked   = NULL;

    uint8_t loc_index = (uint8_t) *arg;

    /**
       For ERSPAN packets, the "protocol type" field value in the GRE header
       is 0x88BE (ERSPAN type II) or 0x22EB (ERSPAN type III).
    **/

    if(profile_socket[loc_index].erspan == 1) {
        u_char *tmp_pkt = packet;
        memcpy(&tmp_ip_proto, (packet + ETHHDR_SIZE + IPPROTO_OFFSET), 1);
        if(tmp_ip_proto == GRE_PROTO) {            
            memcpy(&tmp_ip_len, (packet + ETHHDR_SIZE), 1);
            tmp_ip_len = (tmp_ip_len & IPLEN_MASK) * 4; // LSB 4 bits: lenght in 32-bit words            
            tmp_pkt = tmp_pkt + ETHHDR_SIZE + tmp_ip_len + 2; // GRE Protocol_type field for ERSPAN version

            if(tmp_pkt[0] == 0x88 && tmp_pkt[1] == 0xbe) {
                erspan_offset = ETHHDR_SIZE + tmp_ip_len + GREHDR_SIZE_II + ERSPAN_II_OFF; // Ethernet + IP + GRE II
            } else if(tmp_pkt[0] == 0x22 && tmp_pkt[1] == 0xeb) {
                erspan_offset = ETHHDR_SIZE + tmp_ip_len + GREHDR_SIZE_III; // Ethernet + IP + GRE III
            } else {
                erspan_offset = ETHHDR_SIZE + tmp_ip_len + GREHDR_SIZE;     // Ethernet + IP + GRE
            }

            pkthdr->len -= erspan_offset;
            pkthdr->caplen -= erspan_offset;
            packet += erspan_offset;
        }
    }

    if(type_datalink == DLT_MTP2) {

        snprintf(mac_src, sizeof(mac_src), "00-01-02-03-04-05");
        snprintf(mac_dst, sizeof(mac_dst), "05-04-03-02-01-00");
        
        snprintf(ip_src, sizeof(ip_src), "127.0.0.1");
        snprintf(ip_dst, sizeof(ip_dst), "127.0.0.2");

        memset(&_msg, 0, sizeof(msg_t));
        memset(&ctx, 0, sizeof(struct run_act_ctx));

        _msg.cap_packet = (void *) packet;
        _msg.cap_header = (void *) pkthdr;        
        _msg.hdr_len = link_offset;
        _msg.rcinfo.src_ip = ip_src;
        _msg.rcinfo.dst_ip = ip_dst;
        _msg.rcinfo.src_mac = mac_src;
        _msg.rcinfo.dst_mac = mac_dst;
        _msg.rcinfo.ip_family = DLT_MTP2;
        _msg.rcinfo.ip_proto = DLT_MTP2;

        _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
        _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
        _msg.tcpflag = 0;
        _msg.parse_it = 1;

        _msg.len = pkthdr->len;
        _msg.data = packet;
        
        action_idx = profile_socket[loc_index].action;
        run_actions(&ctx, main_ct.clist[action_idx], &_msg);
        
        return;
    }

    /** DATALINK LAYER **/
       
    /* NOTE:
     *       This code needs an improvment because this is not the correct way to do it:
     *       should be like: 
     *       ------------------------------------------------------------------- 
     *       uint16_t cooked; 
     *       cooked = ntohs(*(uint16_t*)(packet + link_offset + IPV4_SIZE + 2)); 
     *       -------------------------------------------------------------------
     */    
    memcpy(&cooked, (packet + link_offset + IPV4_SIZE + 2), 2);
    memcpy(&ethaddr, (packet + 12), 2);
    memcpy(&mplsaddr, (packet + 16), 2);

    if (ntohs((uint16_t)*(&ethaddr)) == VLAN) {
        if (ntohs((uint16_t)*(&mplsaddr)) == MPLS_UNI) {
            hdr_offset = 8;
            vlan = 1;
        } else {
            hdr_offset = 4;
            vlan = 2;
        }
    } else if(ntohs((uint16_t)*(&cooked)) == COOKED_INT) {
        /* LINK_OFFSET + IPV4_SIZE + GRE_ERSPAN + ERSPAN INFO */
        hdr_offset = hdr_preset = link_offset + IPV4_SIZE + ERSPANHDR_SIZE ;
        vlan = 3;
    }

    /* Check if ETHER TYPE is Ethernet or Linux Cooked */
    if (type_datalink == DLT_LINUX_SLL) {
        sll = (struct sll_header *)(packet + hdr_preset);
    } else {
        eth = (struct ethhdr *)(packet + hdr_preset);
    }

    if (eth) {
        snprintf(mac_src, sizeof(mac_src), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        snprintf(mac_dst, sizeof(mac_dst), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
        if(vlan == 0) {
            // IP TYPE = 0x86dd (IPv6) or 0x0800 (IPv4)
            type_ip = ntohs(eth->ether_type);
        }
    }
    /* Linux cooked capture show only Source MAC address */
    else if (sll) {
        snprintf(mac_src, sizeof(mac_src), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2], sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
        if(vlan == 0) {
            // IP TYPE = 0x86dd (IPv6) or 0x0800 (IPv4)
            type_ip = ntohs(sll->sll_protocol);
        }
    }

    /** IP LAYER **/
    
 ip_hdr_parse:
    if(type_ip == ETHERTYPE_IP) {
        ip4_pkt = (struct ip *)(packet + link_offset + hdr_offset + ipip_offset);
    } else {
        #if USE_IPv6
        ip6_pkt = (struct ip6_hdr*)(packet + link_offset + hdr_offset + ipip_offset);
        #endif
    }

    uint32_t len = pkthdr->caplen;
    uint32_t ip_hl = 0;
    uint32_t ip_off = 0;
    uint16_t frag_offset = 0;
    uint8_t fragmented = 0, psh = 0;
    unsigned char *data, *datatcp;
    u_char *pack = NULL;

    /* stats */
    stats.received_packets_total++;

    if(profile_socket[loc_index].reasm && reasm[loc_index] != NULL) {
        unsigned new_len;

        u_char *new_p = malloc(len - link_offset - hdr_offset);
        memcpy(new_p, ip4_pkt, len - link_offset - hdr_offset);

        pack = reasm_ip_next(reasm[loc_index], new_p, len - link_offset - hdr_offset,
                             (reasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len);

        if (pack == NULL)
            return;

        len = new_len + link_offset + hdr_offset;
        pkthdr->len = new_len;
        pkthdr->caplen = new_len;

        ip4_pkt = (struct ip *) pack;
        #if USE_IPv6
        ip6_pkt = (struct ip6_hdr*)pack;
        #endif
    }

    ip_ver = ip4_pkt->ip_v;
    
    memset(&_msg, 0, sizeof(msg_t));
    memset(&ctx, 0, sizeof(struct run_act_ctx));

    _msg.cap_packet = (void *) packet;
    _msg.cap_header = (void *) pkthdr;

    switch(ip_ver) {

     case 4: {
         #if defined(AIX)
         #undef ip_hl
         ip_hl = ip4_pkt->ip_ff.ip_fhl * 4;
         #else
         ip_hl = ip4_pkt->ip_hl * 4;
         #endif
         ip_proto = ip4_pkt->ip_p;
         ip_off = ntohs(ip4_pkt->ip_off);
         
         fragmented = ip_off & (IP_MF | IP_OFFMASK);
         frag_offset = (fragmented) ? (ip_off & IP_OFFMASK) * 8 : 0;
         //frag_id = ntohs(ip4_pkt->ip_id);
         
         inet_ntop(AF_INET, (const void *) &ip4_pkt->ip_src, ip_src, sizeof(ip_src));
         inet_ntop(AF_INET, (const void *) &ip4_pkt->ip_dst, ip_dst, sizeof(ip_dst));
     }
         break;
         
         #if USE_IPv6
     case 6: {
         ip_hl = sizeof(struct ip6_hdr);
         ip_proto = ip6_pkt->ip6_nxt;
         
         if (ip_proto == IPPROTO_FRAGMENT) {
             struct ip6_frag *ip6_fraghdr;
             
             ip6_fraghdr = (struct ip6_frag *)((unsigned char *)(ip6_pkt) + ip_hl);
             ip_hl += sizeof(struct ip6_frag);
             ip_proto = ip6_fraghdr->ip6f_nxt;
             
             fragmented = 1;
             frag_offset = ntohs(ip6_fraghdr->ip6f_offlg & IP6F_OFF_MASK);
             //frag_id = ntohl(ip6_fraghdr->ip6f_ident);
         }
         
         inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_src, ip_src, sizeof(ip_src));
         inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_dst, ip_dst, sizeof(ip_dst));
     }
         break;
         #endif
    }
    
    // check IP-to-IP tunnel
    if(ip_proto == 0x04) {
        LDEBUG("IP-to-IP tunnel detected -> parsing inner IP");
        ipip_offset = IPV4_SIZE;
        goto ip_hdr_parse;
    }
    
    switch (ip_proto) {

     case IPPROTO_TCP: {
         
         struct tcphdr *tcp_pkt = (struct tcphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
         
         //uint16_t tcphdr_offset = (frag_offset) ? 0 : (tcp_pkt->th_off * 4);
         uint16_t tcphdr_offset = frag_offset ? 0 : (uint16_t) (tcp_pkt->th_off * 4);
         
         data = (unsigned char *) tcp_pkt + tcphdr_offset;
         
         _msg.hdr_len = link_offset + hdr_offset + ip_hl + tcphdr_offset;
         
         len -= link_offset + hdr_offset + ip_hl + tcphdr_offset;
         
         stats.received_tcp_packets++;
         
         #if USE_IPv6
         /* if (ip_ver == 6)
            {
            len -= ntohs(ip6_pkt->ip6_plen);
            _msg.hdr_len += ntohs(ip6_pkt->ip6_plen);
            }
         */
         #endif
         
         if ((int32_t) len < 0)
             len = 0;
         
         /******************* Check for Websocket layer (skip it) **************************/
         int webLen = link_offset + hdr_offset + ip_hl + tcphdr_offset;
         uint8_t *p_websock = packet + webLen;
         
        if(tcpreasm[loc_index] != NULL &&  (len > 0) && (tcp_pkt->th_flags & TH_ACK)) {
            
            unsigned new_len;
            u_char *new_p_2 = malloc(len + 10);
            memcpy(new_p_2, data, len);
            
            if ((tcp_pkt->th_flags & TH_PUSH))
                psh = 1;
            
            if (debug_socket_pcap_enable)
                LDEBUG("DEFRAG TCP process: LEN:[%d], ACK:[%d], PSH[%d]\n", len, (tcp_pkt->th_flags & TH_ACK), psh);
            
            datatcp = tcpreasm_ip_next_tcp(tcpreasm[loc_index], new_p_2, len,
                                           (tcpreasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len,
                                           &ip4_pkt->ip_src, &ip4_pkt->ip_dst, ntohs(tcp_pkt->th_sport),
                                           ntohs(tcp_pkt->th_dport), psh);
            
            if (datatcp == NULL) {                    
                return;
            }
            
            len = new_len;
            
            if (debug_socket_pcap_enable) {
                LDEBUG("COMPLETE TCP DEFRAG: LEN[%d], PACKET:[%s]\n", len, datatcp);
            }
            
            /* check websocket */
            if(websocket_detection == 1)
            {
                p_websock = datatcp;                            
                char decoded[3000];
                memset(decoded, 0, 3000);
                if(!websocket_header_detection(p_websock, webLen, datatcp, pkthdr->len))
                {
                    /* clear datatcp */         
                    if(datatcp)
                        free(datatcp);
                    goto error;
                }
                /* next position for websock */
                p_websock++;
            }                                
            
            // Full packet
            if (!profile_socket[profile_size].full_packet) {
                
                _msg.len = len;
                
                if( websocket_detection == 1) {
                    char decoded[3000];
                    memset(decoded, 0, 3000);
                    if(!websocket_pre_decode(p_websock, decoded, &_msg)) {
                        _msg.data = sll ?  packet + _msg.hdr_len : datatcp;
                    }                    
                } else {
                    _msg.data = sll ?  packet + _msg.hdr_len : datatcp;
                }
            }
            // Not full packet
            else {
                _msg.len = len;
                if(websocket_detection == 1) {   
                    char decoded[3000];
                    memset(decoded, 0, 3000);
                    if(!websocket_pre_decode(p_websock, decoded, &_msg)) {
                        _msg.data = sll ?  packet + _msg.hdr_len : datatcp;
                    }   
                } else {
                    _msg.data = sll ?  packet + _msg.hdr_len : datatcp;
                }
            }
            
            _msg.rcinfo.src_mac = mac_src;
            _msg.rcinfo.dst_mac = mac_dst;
            _msg.rcinfo.src_ip = ip_src;
            _msg.rcinfo.dst_ip = ip_dst;
            _msg.rcinfo.src_port = ntohs(tcp_pkt->th_sport);
            _msg.rcinfo.dst_port = ntohs(tcp_pkt->th_dport);
            _msg.rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
            _msg.rcinfo.ip_proto = ip_proto;
            _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
            _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
            _msg.tcpflag = tcp_pkt->th_flags;
            _msg.parse_it = 1;
            
            if(ipindex) {
                /* src */
                check_ip_data(_msg.rcinfo.src_ip, &_msg.rcinfo.src_port);
                /* dst */
                check_ip_data(_msg.rcinfo.dst_ip, &_msg.rcinfo.dst_port);
            }

            action_idx = profile_socket[loc_index].action;
            run_actions(&ctx, main_ct.clist[action_idx], &_msg);

            /* clear datatcp */                                
            free(datatcp);
        } else {
            /* detect websocket */            
            if(websocket_detection == 1) {
                if(!websocket_header_detection(p_websock, webLen, data, pkthdr->len)) {
                    /* clear datatcp */         
                    goto error;
                }
                /* next position for websock */
                p_websock++;
            }                         
            // full packet
            if (!profile_socket[profile_size].full_packet) {

                _msg.len = len;
                    
                if(websocket_detection == 1) {
                    char decoded[3000];
                    memset(decoded, 0, 3000);
                    if(!websocket_pre_decode(p_websock, decoded, &_msg)) {                        
                        _msg.data = data;
                    }                    
                } else {
                    _msg.data = data;
                }
            }
            // Not full packet
            else {

                _msg.len = pkthdr->caplen - link_offset - hdr_offset;
                   
                if(websocket_detection == 1) {
                    char decoded[3000];
                    memset(decoded, 0, 3000);
                    if(!websocket_pre_decode(p_websock, decoded, &_msg)) {
                        _msg.data = (packet + link_offset + hdr_offset);
                    }   
                } else {
                    _msg.data = data;
                }                   
            }
                
            _msg.rcinfo.src_mac = mac_src;
            _msg.rcinfo.dst_mac = mac_dst;
            _msg.rcinfo.src_ip = ip_src;
            _msg.rcinfo.dst_ip = ip_dst;
            _msg.rcinfo.src_port = ntohs(tcp_pkt->th_sport);
            _msg.rcinfo.dst_port = ntohs(tcp_pkt->th_dport);
            _msg.rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
            _msg.rcinfo.ip_proto = ip_proto;
            _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
            _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
            _msg.tcpflag = tcp_pkt->th_flags;
            _msg.parse_it = 1;

            if(ipindex) {
                /* src */
                check_ip_data(_msg.rcinfo.src_ip, &_msg.rcinfo.src_port);
                /* dst */
                check_ip_data(_msg.rcinfo.dst_ip, &_msg.rcinfo.dst_port);
            }

            action_idx = profile_socket[loc_index].action;
            run_actions(&ctx, main_ct.clist[action_idx], &_msg);

            stats.send_packets++;            
        }
     }
         break;

     case IPPROTO_UDP: {

        struct udphdr *udp_pkt = (struct udphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
        uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);        
        int ret_check;

        data = (unsigned char *) (udp_pkt) + udphdr_offset;

        _msg.hdr_len = link_offset + ip_hl + hdr_offset + udphdr_offset;

        len -= link_offset + ip_hl + udphdr_offset + hdr_offset;

        #if USE_IPv6
        /*if (ip_ver == 6) {
          len -= ntohs(ip6_pkt->ip6_plen);
          _msg.hdr_len += ntohs(ip6_pkt->ip6_plen);
          }
        */
        #endif

        /* stats */
        stats.received_udp_packets++;

        if ((int32_t) len < 0)
            len = 0;

        _msg.rcinfo.src_port = ntohs(udp_pkt->uh_sport);
        _msg.rcinfo.dst_port = ntohs(udp_pkt->uh_dport);
        _msg.rcinfo.src_ip = ip_src;
        _msg.rcinfo.dst_ip = ip_dst;
        _msg.rcinfo.src_mac = mac_src;
        _msg.rcinfo.dst_mac = mac_dst;
        _msg.rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
        _msg.rcinfo.ip_proto = ip_proto;
        _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
        _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
        _msg.tcpflag = 0;
        _msg.parse_it = 1;

        if(!profile_socket[profile_size].full_packet) {
            int r = strncmp(profile_socket[loc_index].name, "socketspcap_sip", strlen("socketspcap_sip"));
            /* The following checks are only for SIP packet */
            if(r == 0) {
                if(profile_socket[loc_index].filter) {
                    ret_check = check_port_filter(profile_socket[loc_index].filter,
                                                  _msg.rcinfo.src_port,
                                                  _msg.rcinfo.dst_port);
                    if(ret_check == 0) {
                        len = strip_fcs_end(data, len);
                    }
                }
            }
            _msg.data = data;
            _msg.len = len;
        } else {
            _msg.len = pkthdr->caplen - link_offset - hdr_offset;
            _msg.data = (packet + link_offset + hdr_offset);              
        }


        /* replace IP */
        if(ipindex) {
            /* src */
            check_ip_data(_msg.rcinfo.src_ip, &_msg.rcinfo.src_port);
            /* dst */
            check_ip_data(_msg.rcinfo.dst_ip, &_msg.rcinfo.dst_port);
        }

        action_idx = profile_socket[loc_index].action;
        run_actions(&ctx, main_ct.clist[action_idx], &_msg);

        stats.send_packets++;
     }
         break;

     case IPPROTO_SCTP: {
        struct sctp_common_hdr *sctp_hdr;
        uint8_t *chunk_data;
        int plen;
        uint32_t chunk_read = 0;

        /* attempt at input validation */
        if (len <= link_offset + ip_hl + hdr_offset) {
            LDEBUG("sctp: offset handling %zu vs. %zu",
                   len, link_offset + ip_hl + hdr_offset);
            goto error;
        }

        len -= link_offset + ip_hl + hdr_offset;
        sctp_hdr = (struct sctp_common_hdr *) ((uint8_t *)(ip4_pkt) + ip_hl);
        plen = sctp_parse_common(&_msg, (uint8_t *)sctp_hdr, len);

        if (plen < 0)
            goto error;
        len -= plen;

        /* stats */
        stats.received_sctp_packets++;

        /* I don't understand the frag_offset in other protos */

        /* same for the entire package */
        _msg.hdr_len = link_offset + hdr_offset + ip_hl + sizeof(struct sctp_common_hdr);
        _msg.rcinfo.src_ip = ip_src;
        _msg.rcinfo.dst_ip = ip_dst;
        _msg.rcinfo.src_mac = mac_src;
        _msg.rcinfo.dst_mac = mac_dst;
        _msg.rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
        _msg.rcinfo.ip_proto = ip_proto;
        _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
        _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
        _msg.tcpflag = 0;
        _msg.parse_it = 1;

        /* replace IP */
        if(ipindex) {
            /* src */
            check_ip_data(_msg.rcinfo.src_ip, &_msg.rcinfo.src_port);
            /* dst */
            check_ip_data(_msg.rcinfo.dst_ip, &_msg.rcinfo.dst_port);
        }

        /* default the full packet */
        _msg.len = pkthdr->caplen - link_offset - hdr_offset;
        _msg.data = (packet + link_offset + hdr_offset);

        chunk_data = &sctp_hdr->data[0];

        while (chunk_read < len) {
            bool send_data;
            uint8_t padding;

            plen = sctp_parse_chunk(&_msg, chunk_data, len - chunk_read, &send_data);
            if (plen < 0)
                goto error;
            /* a chunk but no data chunk */
            if (!send_data)
                goto next;

            if (!profile_socket[profile_size].full_packet) {
                _msg.len = plen - 16;
                _msg.data = chunk_data + 16;
            }
            action_idx = profile_socket[loc_index].action;
            run_actions(&ctx, main_ct.clist[action_idx], &_msg);

        next:
            padding = (4 - (plen % 4)) & 0x3;
            chunk_read += plen + padding;
            chunk_data += plen + padding;
        }

        stats.send_packets++;
     }
         break;
        
    default:
        break;
    }

 error:
    if(pack != NULL)
        free(pack);
}


bool websocket_header_detection(uint8_t *p_websock, uint32_t posLen, unsigned char *data, uint32_t hdrLen) {
    /**
       NOTE: in our case, the first byte is valid ONLY if the value is 129 (0x81) or 130 (0x82)
       this means the 1st bit FIN == 1 and 4 less-significant bits could be 0x01 (utf-8 text data) or 0x02 (binary data)

       Mask 7   to get the 1st most-significant bit (fin check)
       Mask 0xF to get the 4 less-significant bit (opcode check)
    **/
    
    if ((((*p_websock >> 7) & 1) == 1) && (((*p_websock & 0xF) == 0x01) || ((*p_websock & 0xF) == 0x02))) {

        /* TCP without payload */
        if (hdrLen == posLen) {
            LERR("This is a TCP packet without payload - SKIP IT\n");
            return FALSE;
        }
        /* HTTP pkt */
        if ((strncmp(data, "GET", 3) == 0) || (strncmp(data, "HTTP", 4) == 0)) {
            LERR("This is a HTTP packet - SKIP IT\n");
            return FALSE;
        }

        LDEBUG("websocket detected\r\n");
        return TRUE;
                
    }   // websocket-detection 
    
    
    return FALSE;
}

bool websocket_pre_decode(uint8_t *p_websock, uint8_t *decoded,  msg_t *_msg) {
    
    LDEBUG("WEBSOCKET layer found!\n");
    int skip = 0, ws_len = 0, ret;
    uint8_t mask_key[4] = { 0 };
        
    if (((*p_websock >> 7) & 1) == 0) { // check the MASK bit
        LDEBUG("NULL websocket present\n");
        ws_len = 4;
        p_websock+=3;
    } else {    /* ((*p_websock >> 7) & 1) == 1 MASKING-KEY */
        LDEBUG("masking-key present\n");
        if (p_websock[0] != 0xfe) {     // WS payload len < 126
            ws_len = 6;
            skip = (p_websock[0] - 0x80);
            p_websock++;
            memcpy(mask_key, p_websock, 4);
            p_websock += 4;
            //decoded = calloc(skip + 1, sizeof(uint8_t));
            LINFO("SIP is masked - decoding payload...\n");
            websocket_decode(decoded, p_websock, skip, mask_key);

        } else {        // WS payload len >= 126
            ws_len = 8;
            p_websock++;
            skip = p_websock[1] + (p_websock[0] << 8);
            p_websock += 2;
            memcpy(mask_key, p_websock, 4);
            p_websock += 4;
            //decoded = calloc(skip + 1, sizeof(uint8_t));
            LINFO("SIP is masked - decoding payload...\n");
            websocket_decode(decoded, p_websock, skip, mask_key);
        }
    }
        
    if (ws_len > 0) {
        
        ret = strncmp(decoded, "", 1);
        _msg->data = (ret != 0) ? decoded : p_websock;
        _msg->len -= ws_len;
        return TRUE;
    }        
                
    return FALSE;
}


int init_socket(unsigned int loc_idx) {

	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_expr[FILTER_LEN];
	int len = 0, buffer_size = 0;

	if (profile_socket[loc_idx].device) {

        LDEBUG("Setting device: %s\n", profile_socket[loc_idx].device);

        buffer_size =  1024 * 1024 * profile_socket[loc_idx].ring_buffer;

		if ((sniffer_proto[loc_idx] = pcap_create((char *) profile_socket[loc_idx].device, errbuf)) == NULL) {
			LERR("Failed to open packet sniffer on %s: pcap_create(): %s", (char * )profile_socket[loc_idx].device, errbuf);
			return -1;
		}

		if (pcap_set_promisc(sniffer_proto[loc_idx], profile_socket[loc_idx].promisc) == -1) {
			LERR("Failed to set promisc \"%s\": %s", (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		}

		if (pcap_set_timeout(sniffer_proto[loc_idx], profile_socket[loc_idx].timeout) == -1) {
			LERR("Failed to set timeout \"%s\": %s", (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		}

		if (pcap_set_snaplen(sniffer_proto[loc_idx], profile_socket[loc_idx].snap_len) == -1) {
			LERR("Failed to set snap_len [%u], \"%s\": %s", profile_socket[loc_idx].snap_len, (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		}

		if (pcap_set_buffer_size(sniffer_proto[loc_idx], buffer_size) == -1) {
			LERR("Failed to set buffer_size [%u] \"%s\": %s", buffer_size,  (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		}

		if (pcap_activate(sniffer_proto[loc_idx]) != 0) {
			LERR("Failed to activate  \"%s\": %s", (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		}

        LDEBUG("Activated device [%s] at index [%d] \n", profile_socket[loc_idx].device, loc_idx);

	} else {

        LDEBUG("Reading PCAP File: %s", usefile);
		if ((sniffer_proto[loc_idx] = pcap_open_offline(usefile, errbuf)) == NULL) {
			LERR("%s: Failed to open packet sniffer on %s: pcap_open_offline(): %s", module_name, usefile, errbuf);
			return -1;
		}
	}

	/* create filter string */
	if(profile_socket[loc_idx].filter && strlen(profile_socket[loc_idx].filter) > 0) {
        
		len += snprintf(filter_expr+len, sizeof(filter_expr)-len, "(%s)", profile_socket[loc_idx].filter);
        
		if(user_data[loc_idx].ipv4fragments || user_data[loc_idx].ipv6fragments) {
            
			if (user_data[loc_idx].ipv4fragments) {
				LDEBUG("Reassembling of IPv4 packets is enabled, adding '%s' to filter", BPF_DEFRAGMENTION_FILTER_IPV4);
				len += snprintf(filter_expr+len, sizeof(filter_expr), " or %s", BPF_DEFRAGMENTION_FILTER_IPV4);
			}
			if (user_data[loc_idx].ipv6fragments) {
				LDEBUG("Reassembling of IPv6 packets is enabled, adding '%s' to filter", BPF_DEFRAGMENTION_FILTER_IPV6);
				len += snprintf(filter_expr+len, sizeof(filter_expr), " or %s", BPF_DEFRAGMENTION_FILTER_IPV6);
			}
		}
	}

	if(profile_socket[loc_idx].capture_filter) {

        // Normal RTCP
		if(!strncmp(profile_socket[loc_idx].capture_filter, "rtcp", 4)) {            
			len += snprintf(filter_expr + len, sizeof(filter_expr), "%s %s", len ? " and" : "", RTCP_FILTER);
		}

        // Normal RTP
        else if(!strncmp(profile_socket[loc_idx].capture_filter, "rtp", 3)) {
			len += snprintf(filter_expr + len, sizeof(filter_expr), "%s %s", len ? " and" : "", RTP_FILTER);
		}
        
        // IP-to-IP encapsulation
        else if (!strncmp(profile_socket[loc_idx].capture_filter, "ip_to_ip", strlen("ip_to_ip"))) {
            len += snprintf(filter_expr + len, sizeof(filter_expr), "%s %s", len ? "and" : "", IP_IP_FILTER);
        }
	
        if(len > 0) {
            LDEBUG("Filter for index [%d]: [%s]", loc_idx, filter_expr);
        } else {
            LERR("Filter for index [%d] has LEN = 0", loc_idx);
        }
    }

    LDEBUG("BPF Filter => Index: [%d], Expression: [%s], Reasm: [%d]", loc_idx, filter_expr, profile_socket[loc_idx].reasm);
	/* compile filter expression (global constant, see above) */
	if (pcap_compile(sniffer_proto[loc_idx], &filter, filter_expr, 1, 0) == -1) {
		LERR("Failed to compile filter \"%s\": %s", filter_expr, pcap_geterr(sniffer_proto[loc_idx]));
		return -1;
	}

	/* install filter on sniffer session */
	if (pcap_setfilter(sniffer_proto[loc_idx], &filter)) {
		LERR("Failed to install filter: %s", pcap_geterr(sniffer_proto[loc_idx]));
		return -1;
	}
	
	pcap_freecode(&filter);

	return 1;
}

pcap_t* get_pcap_handler(unsigned int loc_idx) {

    if(loc_idx >= MAX_SOCKETS || sniffer_proto[loc_idx] == NULL) return NULL;
    return sniffer_proto[loc_idx];
}


int set_raw_filter(unsigned int loc_idx, char *filter) {

    struct bpf_program raw_filter;
    //uint16_t snaplen = 65535;
    int linktype;
    //struct pcap_t *aa;
    int fd = -1;

    LERR("APPLY FILTER [%u]\n", loc_idx);
    if(loc_idx >= MAX_SOCKETS || sniffer_proto[loc_idx] == NULL) return 0;

    fd = pcap_get_selectable_fd(sniffer_proto[loc_idx]);

    linktype  = profile_socket[loc_idx].link_type ? profile_socket[loc_idx].link_type : DLT_EN10MB;

    if (pcap_compile_nopcap(profile_socket[loc_idx].snap_len ? profile_socket[loc_idx].snap_len : 0xffff, linktype, &raw_filter, filter, 1, 0) == -1) {
        LERR("Failed to compile filter '%s'", filter);
        return -1;
    }

    #if ( defined (OS_LINUX) || defined (OS_SOLARIS) )
    if(setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &raw_filter, sizeof(raw_filter)) < 0 ) {
        LERR(" setsockopt filter: [%s] [%d]", strerror(errno), errno);
        return -1;
    }
    #endif

    //free(BPF_code);
    pcap_freecode( (struct bpf_program *) &raw_filter);

    return 1;

}


void* proto_collect(void *arg) {

	unsigned int loc_idx = *((unsigned int *)arg);
	int ret = 0, is_file = 0;

    LDEBUG("Index in proto_collect(): index: [%u]", loc_idx);
	
	type_datalink = pcap_datalink(sniffer_proto[loc_idx]);
	
	/* detect link_offset */
	switch (type_datalink) {
    case DLT_EN10MB:
        link_offset = ETHHDR_SIZE;
        break;

    case DLT_IEEE802:
		link_offset = TOKENRING_SIZE;
		break;

    case DLT_FDDI:
        link_offset = FDDIHDR_SIZE;
        break;

    case DLT_SLIP:
        link_offset = SLIPHDR_SIZE;
        break;

    case DLT_PPP:
        link_offset = PPPHDR_SIZE;
        break;

    case DLT_LOOP:
    case DLT_NULL:
        link_offset = LOOPHDR_SIZE;
        break;

    case DLT_RAW:
        link_offset = RAWHDR_SIZE;
        break;

    case DLT_LINUX_SLL:
        link_offset = ISDNHDR_SIZE;
        break;

    case DLT_IEEE802_11:
        link_offset = IEEE80211HDR_SIZE;
        break;
		
    case DLT_MTP2:
        link_offset = RAWHDR_SIZE;
        break;
         
    default:
        LERR("fatal: unsupported interface type [%u]", type_datalink);
        exit(-1);
	} // switch

	LDEBUG("Link offset interface type [%u] [%u]", type_datalink, link_offset);

	while(1) {

		ret = pcap_loop(sniffer_proto[loc_idx], 0, (pcap_handler) callback_proto, (u_char *) &loc_idx);

        if (ret == 0 && usefile) {
			LDEBUG("loop stopped by EOF");
            is_file = 1;
			pcap_close(sniffer_proto[loc_idx]);
			break;
		} else if (ret == -2) {
			LDEBUG("loop stopped by breakloop");
			pcap_close(sniffer_proto[loc_idx]);
			break;
		}
        
	}

    if (is_file) {
        LDEBUG("Process, pid=%d\n", getpid());
        kill(getpid(), SIGTERM);
    }

	pthread_exit(0); // exit the thread signalling normal return

	return NULL;
}


static void stat_collect(void* arg) {

    LDEBUG("STARTING STATS....");
    int i = 0;

    while (1)
    {
        for (i = 0; i < profile_size; i++) {
            /* statistics */
            uint8_t pcap_drop = 0, interface_drop = 0;
            struct pcap_stat stat;

            if(pcap_stats(sniffer_proto[i], &stat) == 0)
            {
                if(stat.ps_recv >= last_stat[i].ps_recv) {

                    if(stat.ps_drop > last_stat[i].ps_drop) pcap_drop = 1;
                    if(stat.ps_ifdrop > last_stat[i].ps_ifdrop && (stat.ps_ifdrop - last_stat[i].ps_ifdrop) > (stat.ps_recv - last_stat[i].ps_recv) * drop_limit / 100)
                    {
                        interface_drop = true;
                    }
                    if(pcap_drop == 1 || interface_drop == 1) {
                        LERR("Packet drops on interface [%s], index: [%d], received: [%d]", profile_socket[i].device, i,
                             (stat.ps_recv - last_stat[i].ps_recv));
                        if(pcap_drop) {
                            LERR("pcap drop: [%d] = [%d]%%", (stat.ps_drop - last_stat[i].ps_drop),
                                 ((double)(stat.ps_drop - last_stat[i].ps_drop) / (stat.ps_recv - last_stat[i].ps_recv) * 100));
                        }
                        if(interface_drop) {
                            LERR("interface drop: [%d] = [%d]%%", (stat.ps_ifdrop - last_stat[i].ps_ifdrop),
                                 ((double)(stat.ps_ifdrop - last_stat[i].ps_ifdrop) / (stat.ps_recv - last_stat[i].ps_recv) * 100));
                        }
                    }
                    else {
                        LNOTICE("No packet drops on interface [%s], index: [%d], received: [%d]", profile_socket[i].device, i, (stat.ps_recv - last_stat[i].ps_recv));
                    }
                }

                last_stat[i] = stat;
            }
            else {
                LERR("Couldn't get stats on interface [%s], index [%d]", profile_socket[i].device, i);
            }
        }

        sleep(stats_interval);
    }

    LDEBUG("EXIT stats");
    pthread_exit(0); // exit the thread signalling normal return
    return;
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

static uint64_t serial_module(void)
{
    return module_serial;
}

static int load_module(xml_node *config) {

	char errbuf[PCAP_ERRBUF_SIZE];
	xml_node *params, *profile=NULL, *settings;
	char *key, *value = NULL;
	unsigned int i = 0;
	char loadplan[1024];
    FILE* cfg_stream;

	LNOTICE("Loaded %s", module_name);

	load_module_xml_config();

	/* READ CONFIG */
	profile = module_xml_config;

	/* reset profile */
	profile_size = 0;

	memset(sniffer_proto, 0, sizeof sniffer_proto);


	//global_scripts_path


	while (profile) {

		profile = xml_get("profile", profile, 1);

		if (profile == NULL)
			break;

		if (!profile->attr[4] || strncmp(profile->attr[4], "enable", 6)) {
			goto nextprofile;
		}

		/* if not equals "true" */
		if (!profile->attr[5] || strncmp(profile->attr[5], "true", 4)) {
			goto nextprofile;
		}

		if(profile_size == MAX_SOCKETS) {
			break;
		}

		memset(&profile_socket[profile_size], 0, sizeof(profile_socket_t));
		memset(&user_data[profile_size], 0, sizeof(socket_pcap_user_data_t));

		/* set values */
		profile_socket[profile_size].name = strdup(profile->attr[1]);
		profile_socket[profile_size].description = strdup(profile->attr[3]);
		profile_socket[profile_size].serial = atoi(profile->attr[7]);
		profile_socket[profile_size].capture_plan = NULL;
		profile_socket[profile_size].capture_filter = NULL;
		profile_socket[profile_size].action = -1;
		profile_socket[profile_size].ring_buffer = 12;
		profile_socket[profile_size].snap_len = 3200;
		profile_socket[profile_size].promisc = 0;
		profile_socket[profile_size].timeout = 100;
		profile_socket[profile_size].full_packet = 0;
		profile_socket[profile_size].reasm = 0;
		profile_socket[profile_size].erspan = 0;

		/* SETTINGS */
		settings = xml_get("settings", profile, 1);

		if (settings != NULL) {

			params = settings;

			while (params) {

				params = xml_get("param", params, 1);
				if (params == NULL)
					break;

				if (params->attr[0] != NULL) {

					/* bad parser */
					if (strncmp(params->attr[0], "name", 4)) {
						LERR("bad keys in the config");
						goto nextparam;
					}

					key = params->attr[1];

					if (params->attr[2] && params->attr[3] && !strncmp(params->attr[2], "value", 5)) {
						value = params->attr[3];
					} else {
						value = params->child->value;
					}

					if (key == NULL || value == NULL) {
						LERR("bad values in the config");
						goto nextparam;
					}


					if (!usefile && !strncmp(key, "dev", 3))
						profile_socket[profile_size].device = strdup(value);
					else if (!strncmp(key, "reasm", 5) && !strncmp(value, "true", 4))
						profile_socket[profile_size].reasm |= REASM_UDP;
                    else if (!strncmp(key, "ipv4fragments", 13) && !strncmp(value, "true", 4))
						user_data[profile_size].ipv4fragments = 1;
                    else if (!strncmp(key, "ipv6fragments", 13) && !strncmp(value, "true", 4))
						user_data[profile_size].ipv6fragments = 1;
                    else if (!strncmp(key, "websocket-detection", strlen("websocket-detection")) && !strncmp(value, "true", 4))
                        websocket_detection = 1;
                    else if(!strncmp(key, "tcpdefrag", 9) && !strncmp(value, "true", 4))
                        profile_socket[profile_size].reasm |= REASM_TCP;
					else if (!strncmp(key, "ring-buffer", 11))
						profile_socket[profile_size].ring_buffer = atoi(value);
					else if (!strncmp(key, "full-packet",11) && !strncmp(value, "true", 4))
						profile_socket[profile_size].full_packet = 1;
					else if (!strncmp(key, "timeout", 7))
						profile_socket[profile_size].timeout = atoi(value);
					else if (!strncmp(key, "snap-len", 8))
						profile_socket[profile_size].snap_len = atoi(value);
					else if (!strncmp(key, "promisc", 7) && !strncmp(value, "true", 4))
						profile_socket[profile_size].promisc = 1;
					else if (!strncmp(key, "filter", 6))
						profile_socket[profile_size].filter = strdup(value);
					else if (!strncmp(key, "capture-plan", 12))
						profile_socket[profile_size].capture_plan = strdup(value);
                    else if (!strncmp(key, "capture-filter", 14))
						profile_socket[profile_size].capture_filter = strdup(value);
					else if(!strncmp(key, "debug", 5) && !strncmp(value, "true", 4))
                        debug_socket_pcap_enable = 1;
					else if (!strncmp(key, "erspan", 6) && !strncmp(value, "true", 4))
						profile_socket[profile_size].erspan = 1;
					else if (!strncmp(key, "stats-enable", strlen("stats-enable")) && !strncmp(value, "true", 4))
						stats_enable = TRUE;						
					else if (!strncmp(key, "stats-interval", 14))
						stats_interval = atoi(value);
					else if (!strncmp(key, "ip-replace", 10))
					{
                        load_ip_data(value);
                    }
				}

            nextparam: params = params->next;

			}
		}

		profile_size++;

    nextprofile: profile = profile->next;
	}

	/* free */
	free_module_xml_config();

	for (i = 0; i < profile_size; i++) {

		unsigned int *arg = malloc(sizeof(arg));

		*arg = i;

		/* DEV || FILE */
		if (!usefile) {
			if (!profile_socket[i].device)
				profile_socket[i].device = pcap_lookupdev(errbuf);
			if (!profile_socket[i].device) {
				perror(errbuf);
				exit(-1);
			}
		}

		// start thread
		if (!init_socket(i)) {
			LERR("couldn't init pcap");
			return -1;
		}

        /* REASM */
        if (profile_socket[i].reasm & REASM_UDP) {
            reasm[i] = reasm_ip_new();
            reasm_ip_set_timeout(reasm[i], 30000000);
        }
        else reasm[i] = NULL;

        /* TCPREASM */
        if (profile_socket[i].reasm & REASM_TCP) {
            tcpreasm[i] = tcpreasm_ip_new ();
            tcpreasm_ip_set_timeout(tcpreasm[i], 30000000);
        }
        else tcpreasm[i] = NULL;

		if(profile_socket[i].capture_plan != NULL)
		{

			snprintf(loadplan, sizeof(loadplan), "%s/%s", global_capture_plan_path, profile_socket[i].capture_plan);

            cfg_stream=fopen (loadplan, "r");
			if (cfg_stream==0){
                fprintf(stderr, "ERROR: loading config file(%s): %s\n", loadplan, strerror(errno));
			}

			yyin=cfg_stream;
			if ((yyparse()!=0)||(cfg_errors)){
                fprintf(stderr, "ERROR: bad config file (%d errors)\n", cfg_errors);
                //goto error;
			}

			profile_socket[i].action = main_ct.idx;

		}

		pthread_create(&call_thread[i], NULL, proto_collect, arg);
	}

	if(stats_enable) pthread_create(&stat_thread, NULL, stat_collect, i);

	return 0;
}

static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);

	if(stats_enable) pthread_cancel(stat_thread);

	for (i = 0; i < profile_size; i++) {

		if(sniffer_proto[i]) {
  		    pcap_breakloop(sniffer_proto[i]);
  		    pthread_cancel(call_thread[i]);
  		    pthread_join(call_thread[i],NULL);
		}

		if (reasm[i] != NULL) {
            reasm_ip_free(reasm[i]);
            reasm[i] = NULL;
        }

        if (tcpreasm[i] != NULL) {
            tcpreasm_ip_free(tcpreasm[i]);
            tcpreasm[i] = NULL;
        }


		free_profile(i);
	}
	/* Close socket */
	//pcap_close(sniffer_proto);
	return 0;
}

static int free_profile(unsigned int idx) {

	/*free profile chars **/
	if (profile_socket[idx].name)	 free(profile_socket[idx].name);
	if (profile_socket[idx].description) free(profile_socket[idx].description);
	if (profile_socket[idx].device) free(profile_socket[idx].device);
	if (profile_socket[idx].filter) free(profile_socket[idx].filter);
	if (profile_socket[idx].capture_plan) free(profile_socket[idx].capture_plan);
	if (profile_socket[idx].capture_filter) free(profile_socket[idx].capture_filter);

	return 1;
}

static int description(char *descr) {
	LNOTICE("Loaded description of %s", module_name);
	descr = module_description;
	return 1;
}

static int statistic(char *buf, size_t len) {

	int ret = 0;

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.received_packets_total);
	ret += snprintf(buf+ret, len-ret, "TCP received: [%" PRId64 "]\r\n", stats.received_tcp_packets);
	ret += snprintf(buf+ret, len-ret, "UDP received: [%" PRId64 "]\r\n", stats.received_udp_packets);
	ret += snprintf(buf+ret, len-ret, "SCTP received: [%" PRId64 "]\r\n", stats.received_sctp_packets);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets);


	return 1;
}


/* TZSP */
static inline const char* name_tag(int tag, const char * const names[], int names_len) {
    
    if (tag >= 0 && tag < names_len) {
        return names[tag];
    } else {
        return "<UNKNOWN>";
    }
}

static inline int max(int x, int y) {
    return (x > y) ? x : y;
}


int w_tzsp_payload_extract(msg_t *_m)
{
    int readsz = 0;
    char *recv_buffer = NULL;


    recv_buffer = _m->data;
    readsz = _m->len;

    char *end = recv_buffer + readsz;
    char *p = recv_buffer;

    if (p + sizeof(struct tzsp_header) > end)
    {
        LERR("Malformed packet (truncated header)");
        return -1;
    }

	struct tzsp_header *hdr = (struct tzsp_header *) recv_buffer;
	p += sizeof(struct tzsp_header);

	char got_end_tag = 0;
	if (hdr->version == 1 && hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST)
	{
		while (p < end)
		{
			struct tzsp_tag *tag = (struct tzsp_tag *) p;

			if (verbose) LERR("\ttag { type = %s(%u) }", name_tag(tag->type, tzsp_tag_names, ARRAYSZ(tzsp_tag_names)), tag->type);

			if (tag->type == TZSP_TAG_END)
			{
				got_end_tag = 1;
				p++;
				break;
			}
			else if (tag->type == TZSP_TAG_PADDING) {
				p++;
			}
			else {
				if (p + sizeof(struct tzsp_tag) > end || p + sizeof(struct tzsp_tag) + tag->length > end)
				{
					LERR("Malformed packet (truncated tag)");
					return -1;
				}
				p += sizeof(struct tzsp_tag) + tag->length;
			}
		}
	}
	else {
		LERR("Packet format not understood");
		return -1;
	}

	if (!got_end_tag) {
		LERR("Packet truncated (no END tag)");
		return -1;
	}

	if (verbose) {
		LERR("\tpacket data begins at offset 0x%.4lx, length 0x%.4lx\n",(p - recv_buffer),readsz - (p - recv_buffer));
	}

	// packet remains starting at p
	struct pcap_pkthdr pcap_hdr = {
		.caplen = readsz - (p - recv_buffer),
		.len = readsz - (p - recv_buffer),
	};
	gettimeofday(&pcap_hdr.ts, NULL);

	proccess_packet(_m,  &pcap_hdr, (unsigned char *) p);

    return 1;
}


void proccess_packet(msg_t *_m, struct pcap_pkthdr *pkthdr, u_char *packet) {

	uint8_t hdr_offset = 0;
	uint16_t ethaddr;
	uint16_t mplsaddr;

	/* Pat Callahan's patch for MPLS */
	memcpy(&ethaddr, (packet + 12), 2);
    memcpy(&mplsaddr, (packet + 16), 2);

    if (ntohs(ethaddr) == 0x8100) {
        if (ntohs(mplsaddr) == 0x8847) {
            hdr_offset = 8;
        } else {
            hdr_offset = 4;
        }
    }

    struct ether_header *eth = (struct ether_header *)packet;

    struct ip      *ip4_pkt = (struct ip *)    (packet + link_offset + hdr_offset);
    #if USE_IPv6
    struct ip6_hdr *ip6_pkt = (struct ip6_hdr*)(packet + link_offset + hdr_offset);
    #endif

    char ip_src[INET6_ADDRSTRLEN + 1], ip_dst[INET6_ADDRSTRLEN + 1];
	char mac_src[20], mac_dst[20];
    unsigned char *data = NULL;
	uint32_t ip_ver, ip_hl = 0, ip_off = 0;
    uint32_t len = pkthdr->caplen;
    uint16_t frag_offset = 0;
	uint8_t ip_proto = 0, fragmented = 0;

	ip_ver = ip4_pkt->ip_v;

    snprintf(mac_src, sizeof(mac_src), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5]);
    snprintf(mac_dst, sizeof(mac_dst), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5]);

    _m->cap_packet = (void *) packet;
    _m->cap_header = (void *) pkthdr;

	switch (ip_ver) {

    case 4: {
        #if defined(AIX)
        #undef ip_hl
        ip_hl = ip4_pkt->ip_ff.ip_fhl * 4;
        #else
        ip_hl = ip4_pkt->ip_hl * 4;
        #endif
        ip_proto = ip4_pkt->ip_p;
        ip_off = ntohs(ip4_pkt->ip_off);

        fragmented = ip_off & (IP_MF | IP_OFFMASK);
        frag_offset = (fragmented) ? (ip_off & IP_OFFMASK) * 8 : 0;
        //frag_id = ntohs(ip4_pkt->ip_id);

        inet_ntop(AF_INET, (const void *) &ip4_pkt->ip_src, ip_src, sizeof(ip_src));
        inet_ntop(AF_INET, (const void *) &ip4_pkt->ip_dst, ip_dst, sizeof(ip_dst));
    }
		break;

        #if USE_IPv6
    case 6: {
        ip_hl = sizeof(struct ip6_hdr);
        ip_proto = ip6_pkt->ip6_nxt;

        if (ip_proto == IPPROTO_FRAGMENT) {
            struct ip6_frag *ip6_fraghdr;
            ip6_fraghdr = (struct ip6_frag *)((unsigned char *)(ip6_pkt) + ip_hl);
            ip_hl += sizeof(struct ip6_frag);
            ip_proto = ip6_fraghdr->ip6f_nxt;
            fragmented = 1;
            frag_offset = ntohs(ip6_fraghdr->ip6f_offlg & IP6F_OFF_MASK);
            //frag_id = ntohl(ip6_fraghdr->ip6f_ident);
        }

        inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_src, ip_src, sizeof(ip_src));
        inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_dst, ip_dst, sizeof(ip_dst));
    }
        break;
        #endif
	}

	switch (ip_proto) {

    case IPPROTO_TCP: {
        struct tcphdr *tcp_pkt = (struct tcphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
        uint16_t tcphdr_offset = frag_offset ? 0 : (uint16_t) (tcp_pkt->th_off * 4);
        //data = (unsigned char *) tcp_pkt + tcphdr_offset;
        _m->hdr_len = link_offset + hdr_offset + ip_hl + tcphdr_offset;
        len -= link_offset + hdr_offset + ip_hl + tcphdr_offset;

        if ((int32_t) len < 0) len = 0;

        _m->len = pkthdr->caplen - link_offset - hdr_offset;
        _m->data = (packet + link_offset + hdr_offset);

        _m->rcinfo.src_port = ntohs(tcp_pkt->th_sport);
        _m->rcinfo.dst_port = ntohs(tcp_pkt->th_dport);
        _m->rcinfo.src_ip = ip_src;
        _m->rcinfo.dst_ip = ip_dst;
        _m->rcinfo.src_mac = mac_src;
        _m->rcinfo.dst_mac = mac_dst;
        _m->rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
        _m->rcinfo.ip_proto = ip_proto;
        //_m->rcinfo.time_sec = pkthdr->ts.tv_sec;
        //_m->rcinfo.time_usec = pkthdr->ts.tv_usec;
        _m->tcpflag = tcp_pkt->th_flags;
        _m->parse_it = 1;
    }
        break;

    case IPPROTO_UDP: {
        struct udphdr *udp_pkt = (struct udphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
        uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);
        data = (unsigned char *) (udp_pkt) + udphdr_offset;

        _m->hdr_len = link_offset + ip_hl + hdr_offset + udphdr_offset;

        len -= link_offset + ip_hl + udphdr_offset + hdr_offset;

        /* stats */
        if ((int32_t) len < 0)
            len = 0;

        _m->data = data;
        _m->len = len;

        _m->rcinfo.src_port = ntohs(udp_pkt->uh_sport);
        _m->rcinfo.dst_port = ntohs(udp_pkt->uh_dport);
        _m->rcinfo.src_ip = ip_src;
        _m->rcinfo.dst_ip = ip_dst;
        _m->rcinfo.src_mac = mac_src;
        _m->rcinfo.dst_mac = mac_dst;
        _m->rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
        _m->rcinfo.ip_proto = ip_proto;
        //_m->rcinfo.time_sec = pkthdr->ts.tv_sec;
        //_m->rcinfo.time_usec = pkthdr->ts.tv_usec;
        _m->tcpflag = 0;
        _m->parse_it = 1;
    }
		break;

    default:
        break;
    }

	return;
}

char** str_split(char* a_str, const char a_delim, int up)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    count += last_comma < (a_str + strlen(a_str) - 1);

    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}

void load_ip_data(char *ips)
{
    char **tokens1, **tokens2, **tokens3;

    tokens1 = str_split(ips, ';', 0);

    if (tokens1) {
        int i;
        for (i = 0; *(tokens1 + i); i++)
        {
            tokens2 = str_split(*(tokens1 + i), '-', 1);
            if (tokens2)
            {
                int j;
                for (j = 0; *(tokens2 + j); j++)
                {
                    tokens3 = str_split(*(tokens2 + j), ':', 1);
                    if (tokens3)
                    {
                        int z;
                        for (z = 0; *(tokens3 + z); z++)
                        {
                            if(j == 0) {
                                if(z == 0) {
                                    ipindex++;
                                    snprintf(ipcheck_in[ipindex], 80, "%s", *(tokens3 + z));
                                }
                                else {
                                    port_in[ipindex] = atoi(*(tokens3 + z));
                                }
                            }
                            else if(j == 1) {
                                if(z == 0) {
                                    snprintf(ipcheck_out[ipindex], 80, "%s", *(tokens3 + z));
                                }
                                else {
                                    port_out[ipindex] = atoi(*(tokens3 + z));
                                }
                            }

                            free(*(tokens3 + z));
                        }
                        free(tokens3);
                    }

                    free(*(tokens2 + j));
                }

                free(tokens2);
            }

            free(*(tokens1 + i));
        }
        free(tokens1);
    }

    return;
}

int check_ip_data(char *ip, uint16_t *port)
{

    int j = 0,len=0;

    len = strlen(ip);

    for (j = 0; j < 10; j++)
    {
        if(strlen(ipcheck_in[j]) == 0) break;

        if((strncmp(ipcheck_in[j], ip, len) == 0) && (port_in[j] == *port || port_in[j] == 0)) {
            *port = port_out[j];
            len = snprintf(ip, 80, "%s", ipcheck_out[j]);
            return len;
        }
    }

    return 0;
}
