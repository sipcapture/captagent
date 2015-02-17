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
#include <pthread.h>
#include <inttypes.h>


#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#include <pcap.h>

/* reasambling */
#include "ipreasm.h"
#include "tcpreasm.h"

#include "src/api.h"
#include "src/log.h"
#include "proto_uni.h"
#include "sipparse.h"
#include "captarray.h"
#include "capthash.h"

uint8_t link_offset = 14;

pcap_t *sniffer_proto;
pthread_t call_thread;   

unsigned char* ethaddr = NULL;
unsigned char* mplsaddr = NULL;

/* Callback function that is passed to pcap_loop() */ 
void callback_proto(u_char *useless, struct pcap_pkthdr *pkthdr, u_char *packet) 
{
	uint8_t hdr_offset = 0;

	/* Pat Callahan's patch for MPLS */
	memcpy(&ethaddr, (packet + 12), 2);
        memcpy(&mplsaddr, (packet + 16), 2);

        if (ntohs((uint16_t)*(&ethaddr)) == 0x8100) {
          if (ntohs((uint16_t)*(&mplsaddr)) == 0x8847) {
             hdr_offset = 8;
          } else {
             hdr_offset = 4;
          }
        }

        struct ip      *ip4_pkt = (struct ip *)    (packet + link_offset + hdr_offset);
#if USE_IPv6
        struct ip6_hdr *ip6_pkt = (struct ip6_hdr*)(packet + link_offset + ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4: 0) );
#endif

	uint32_t ip_ver;
	uint8_t  ip_proto = 0;
	uint32_t ip_hl    = 0;
	uint32_t ip_off   = 0;
	uint8_t  fragmented  = 0;
	uint16_t frag_offset = 0;
	uint32_t frag_id     = 0;
	char ip_src[INET6_ADDRSTRLEN + 1],
		ip_dst[INET6_ADDRSTRLEN + 1];

        unsigned char *data, *datatcp;
        u_char *pack = NULL;
	    
	uint32_t len = pkthdr->caplen;
        uint8_t  psh = 0;
	int ret;

        if(debug_proto_uni_enable) LDEBUG("GOT Message: LEN:[%d]\n", len);

	if (reasm != NULL && reasm_enable) {
		unsigned new_len;
        	u_char *new_p = malloc(len - link_offset - ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4:0));
		memcpy(new_p, ip4_pkt, len - link_offset - ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4:0));
	        pack = reasm_ip_next(reasm, new_p, len - link_offset - ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4:0), (reasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len);
        	if (pack == NULL) return;
	        len = new_len + link_offset + ((ntohs((uint16_t)*(pack + 12)) == 0x8100)? 4:0);
        	pkthdr->len = new_len;
	        pkthdr->caplen = new_len;
	
	        ip4_pkt = (struct ip *)  pack;
#if USE_IPv6
	        ip6_pkt = (struct ip6_hdr*)pack;
#endif
	}

	ip_ver = ip4_pkt->ip_v;

	switch (ip_ver) {

	        case 4: {
#if defined(AIX)
#undef ip_hl
        	    ip_hl       = ip4_pkt->ip_ff.ip_fhl * 4;
#else
	            ip_hl       = ip4_pkt->ip_hl * 4;
#endif
        	    ip_proto    = ip4_pkt->ip_p;
	            ip_off      = ntohs(ip4_pkt->ip_off);

        	    fragmented  = ip_off & (IP_MF | IP_OFFMASK);
	            frag_offset = (fragmented) ? (ip_off & IP_OFFMASK) * 8 : 0;
        	    frag_id     = ntohs(ip4_pkt->ip_id);

		    if(debug_proto_uni_enable) LDEBUG("Message IPV4: LEN:[%d]\n", len);

	            inet_ntop(AF_INET, (const void *)&ip4_pkt->ip_src, ip_src, sizeof(ip_src));
	            inet_ntop(AF_INET, (const void *)&ip4_pkt->ip_dst, ip_dst, sizeof(ip_dst));
        	} break;

#if USE_IPv6
	        case 6: {
        	    ip_hl    = sizeof(struct ip6_hdr);
	            ip_proto = ip6_pkt->ip6_nxt;

        	    if (ip_proto == IPPROTO_FRAGMENT) {
                	struct ip6_frag *ip6_fraghdr;

	                ip6_fraghdr = (struct ip6_frag *)((unsigned char *)(ip6_pkt) + ip_hl);
        	        ip_hl      += sizeof(struct ip6_frag);
	                ip_proto    = ip6_fraghdr->ip6f_nxt;

        	        fragmented  = 1;
                	frag_offset = ntohs(ip6_fraghdr->ip6f_offlg & IP6F_OFF_MASK);
	                frag_id     = ntohl(ip6_fraghdr->ip6f_ident);
        	    }

		    if(debug_proto_uni_enable) LDEBUG("Message IPV6: LEN:[%d]\n", len);

	            inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_src, ip_src, sizeof(ip_src));
        	    inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_dst, ip_dst, sizeof(ip_dst));
	        } break;
#endif
	}       

	switch (ip_proto) {
                case IPPROTO_TCP: {
                    struct tcphdr *tcp_pkt = (struct tcphdr *)((unsigned char *)(ip4_pkt) + ip_hl);

                    //uint16_t tcphdr_offset = (frag_offset) ? 0 : (tcp_pkt->th_off * 4);
                    uint16_t tcphdr_offset = frag_offset ? 0 : (uint16_t) (tcp_pkt->th_off * 4);

                    data = (unsigned char *)(tcp_pkt) + tcphdr_offset;
                    
                    len -= link_offset + ip_hl + tcphdr_offset + hdr_offset;

#if USE_IPv6
                    if (ip_ver == 6)
                        len -= ntohs(ip6_pkt->ip6_plen);
#endif

                    if ((int32_t)len < 0)
                        len = 0;

                    if(debug_proto_uni_enable) LDEBUG("TCP Message: LEN:[%d], [%.*s]\n", len, len, data);

                    if(tcpreasm != NULL && tcpdefrag_enable && (len > 0) && (tcp_pkt->th_flags & TH_ACK)) {

			unsigned new_len;
			u_char *new_p_2 = malloc(len+10);
			memcpy(new_p_2, data, len);
	
			if((tcp_pkt->th_flags & TH_PUSH)) psh = 1;

					
			if(debug_proto_uni_enable)
			        LDEBUG("DEFRAG TCP process: EN:[%d], LEN:[%d], ACK:[%d], PSH[%d]\n", 
			                        tcpdefrag_enable, len, (tcp_pkt->th_flags & TH_ACK), psh);
			
	                datatcp = tcpreasm_ip_next_tcp(tcpreasm, new_p_2, len , (tcpreasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len, &ip4_pkt->ip_src, &ip4_pkt->ip_dst, ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), psh);

        	        if (datatcp == NULL) return;
        	                	        
	                len = new_len;
	                
	                if(debug_proto_uni_enable)
	                        LDEBUG("COMPLETE TCP DEFRAG: LEN[%d], PACKET:[%s]\n", len, datatcp);
	                
	                dump_proto_packet(pkthdr, packet, ip_proto, datatcp, len,
        	                ip_src, ip_dst, ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), tcp_pkt->th_flags,
                	        tcphdr_offset, fragmented, frag_offset, frag_id, ip_ver);

	                /* clear datatcp */
        	        free(datatcp);
                    
                    }
                    else {
                    
                            if(debug_proto_uni_enable)
	                        LDEBUG("NORMAL TCP PACKET: LEN[%d], ACK: [%d], PACKET: [%s]\n", len, (tcp_pkt->th_flags & TH_ACK), data);
                            ret = dump_proto_packet(pkthdr, packet, ip_proto, data, len, ip_src, ip_dst, 
                                    ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), tcp_pkt->th_flags,
                                    tcphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
                    }
                                        
                } break;

                case IPPROTO_UDP: {
                    struct udphdr *udp_pkt = (struct udphdr *)((unsigned char *)(ip4_pkt) + ip_hl);
                    uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);

                    data = (unsigned char *)(udp_pkt) + udphdr_offset;
                    
                    len -= link_offset + ip_hl + udphdr_offset + hdr_offset;
                    
                    if(debug_proto_uni_enable) LDEBUG("UDP Message: LEN:[%d] [.*s]\n", len, len, data);

#if USE_IPv6
                    if (ip_ver == 6)
                        len -= ntohs(ip6_pkt->ip6_plen);
#endif

                    if ((int32_t)len < 0) len = 0;

                     ret = dump_proto_packet(pkthdr, packet, ip_proto, data, len, ip_src, ip_dst,
                        ntohs(udp_pkt->uh_sport), ntohs(udp_pkt->uh_dport), 0,
                        udphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
                   
                        
                                                
        } break;

                default:                 
                        break;
        }
        
        if(pack != NULL) free(pack);
        
}

int dump_proto_packet(struct pcap_pkthdr *pkthdr, u_char *packet, uint8_t proto, unsigned char *data, uint32_t len,
                 const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint8_t flags,
                                  uint16_t hdr_offset, uint8_t frag, uint16_t frag_offset, uint32_t frag_id, uint32_t ip_ver) {

        struct timeval tv;
        time_t curtime;
	char timebuffer[30];	
	//rc_info_t *rcinfo = NULL;
	rc_info_t rcinfo;
        preparsed_sip_t psip;
        miprtcp_t *mp = NULL;                
        int i = 0;
        char ipptmp[256];
        uint32_t bytes_parsed = 0;
        uint32_t newlen;
        int skip_len = 0;
        int loop = 1;
        int count_loop = 0;
                        
        
        gettimeofday(&tv,NULL);

        sendPacketsCount++;

        curtime = tv.tv_sec;
        strftime(timebuffer,30,"%m-%d-%Y  %T.",localtime(&curtime));


        if(len <= 172) {
                //LDEBUG("SIP the message is too small: %d\n", len);
                return -1;
        }

        /* SIP must have alpha */
        if((proto_type == PROTO_SIP && !isalpha(data[0])) || !strncmp((char *)data, "HEP3", 4)) {                
                return -1;
        }
        
        /* gingle XMPP */
        else if(proto_type == PROTO_XMPP && memcmp("<iq", data, 3)) {
                return -1;
        }
                
        newlen =  len;
        
        while(loop) {
                
                count_loop++;
                if(count_loop > 5) {
                	LERR("TOO MANY LOOP LEN [%d] vs NEWLEN: [%"PRIu32"] vs SKIP: [%d] vs PARSED: [%"PRIu32"]\n", len, newlen, skip_len, bytes_parsed);
                	LERR("PACKET [%s]\n", data);
                	loop = 0;
                	break;
                }
                
                /* we can have more SIP message in one buffer */
                if(proto == IPPROTO_TCP && len > 1300) 
                {
                        if(light_parse_message((char*) data+skip_len, (len-skip_len), &bytes_parsed, &psip) == 1) {
                                newlen = psip.len;
                        }
                        else newlen = len-skip_len;
                }
                                
                //if (proto_type == PROTO_SIP && sip_method){
                if (proto_type == PROTO_SIP && sip_parse == 1){

                	//if ((sip_method_not == 1) ? (!sip_is_method((const char*)data, len,sip_method+1)): (sip_is_method ((const char*) data, len,sip_method))){
                    	//LDEBUG("method not matched\n");
                    	//return -1;
                	//}
                	memset(&psip, 0, sizeof(struct preparsed_sip));
        	
                	psip.mrp_size = 0;
                	psip.has_sdp = 0;        	
                	bytes_parsed = 0;
        	
                	//LDEBUG("MESSAGE: [%.*s]\n", len, data);
                	if(parse_message((char*) data+skip_len, newlen, &bytes_parsed, &psip) == 1) {
        	                       	               
                                if(rtcp_tracking == 1 && psip.has_sdp == 1) {        	        
                                
                                        if(psip.mrp_size > 10) {
                                                LERR("Bad MRP size [%d]\n", psip.mrp_size);
                                                psip.mrp_size = 0;
                                        }
                                                        
                        	        for(i=0; i < psip.mrp_size; i++) {                	        
                        	                mp = &psip.mrp[i];        	                        	                        	                
                        	                if(mp->media_ip.len > 0 && mp->media_ip.s) {
                                	                if(mp->rtcp_port == 0 ) mp->rtcp_port = mp->media_port+1;        	                                        	                
                                	                if(mp->rtcp_ip.len ==  0) {
                        	                                mp->rtcp_ip.len = mp->media_ip.len;
        	                                                mp->rtcp_ip.s = mp->media_ip.s;
                                                        }        	                
        	                
                                                        if(mp->rtcp_ip.len > 0 && mp->rtcp_ip.s) {
                                                
                	                                        /* our correlation index */
                                        	                snprintf(ipptmp,sizeof(ipptmp), "%.*s:%d",  mp->rtcp_ip.len, mp->rtcp_ip.s, mp->rtcp_port);        	                        
                                        	                /* put data to hash */
                                        	                if(!find_ipport(ipptmp)) {
                                                                        add_ipport(ipptmp, &psip.callid);
                                                                        add_timer(ipptmp);        	                
                                                                }
                                                        }
                                                }
                                        }
        	                }
        	        
                        }
                        else {
                                LDEBUG("Not Parsed\n");
                        }
        	
                 }
                 //LDEBUG("SIP: [%.*s]\n", len, data);
                 
                if(newlen <= 172) {
        	        //LDEBUG("SIP the message is too small: %d\n", len);
                	break;
        	}
	        /* SIP must have alpha */
        	if((proto_type == PROTO_SIP && !isalpha((data+skip_len)[0])) || !strncmp((char *)(data+skip_len), "HEP3", 4)) {                
                	break;
        	}

                rcinfo.src_port   = sport;
                rcinfo.dst_port   = dport;
                rcinfo.src_ip     = ip_src;
                rcinfo.dst_ip     = ip_dst;
                rcinfo.ip_family  = ip_ver = 4 ? AF_INET : AF_INET6 ;
                rcinfo.ip_proto   = proto;
                rcinfo.time_sec   = pkthdr->ts.tv_sec;
                rcinfo.time_usec  = pkthdr->ts.tv_usec;
                rcinfo.proto_type = proto_type;
                rcinfo.correlation_id.len = 0;
                rcinfo.correlation_id.s = NULL;
                
                if(debug_proto_uni_enable)
                        LDEBUG("SENDING PACKET: Len: [%d]\n", newlen);                        
        
        	/* Duplcate */
        	if(send_enable) {
        	        if(!send_message(&rcinfo, data+skip_len, (unsigned int) newlen)) {
        	                 LDEBUG("Not duplicated\n");
                        }        
                }

                //if(rcinfo) free(rcinfo);
                
                skip_len += newlen;
                
                if(skip_len >= len || newlen >= len || newlen == 0 || bytes_parsed == 0 ) {
                        loop = 0;
                        break;
                }                
        }

        return 1;        
}


void* proto_collect( void* device ) {

        struct bpf_program filter;
        char errbuf[PCAP_ERRBUF_SIZE];
        char *filter_expr;
        uint16_t snaplen = 65535, timeout = 100, len = 200, ret = 0;        

        if(device) {
            if((sniffer_proto = pcap_open_live((char *)device, snaplen, promisc, timeout, errbuf)) == NULL) {
                LERR("Failed to open packet sniffer on %s: pcap_open_live(): %s\n", (char *)device, errbuf);
                return NULL;
            }
        } else  {
            if((sniffer_proto = pcap_open_offline(usefile, errbuf)) == NULL) {
                LERR("Failed to open packet sniffer on %s: pcap_open_offline(): %s\n", usefile, errbuf);
                return NULL;
            }
        }

        len += (portrange != NULL) ? strlen(portrange) : 10;        
        len += (ip_proto != NULL) ? strlen(ip_proto) : 0;
        len += (userfilter != NULL) ? strlen(userfilter) : 0;
        len += (reasm_enable && buildin_reasm_filter) ? strlen(BPF_DEFRAGMENTION_FILTER) : 0;
        
        filter_expr = malloc(sizeof(char) * len);
        
        /* REASM */
        if(reasm_enable && buildin_reasm_filter) ret += snprintf(filter_expr, len, BPF_DEFRAGMENTION_FILTER);
        
        /* FILTER VLAN */        
        if(vlan) { 
        	ret += snprintf(filter_expr+ret, (len - ret), ret ? " or  (vlan " : "(vlan ");
        	if(portrange != NULL) ret += snprintf(filter_expr+ret, (len - ret), "and portrange %s ) ", portrange);
        	else if(port > 0) ret += snprintf(filter_expr+ret, (len - ret), "and port %d ) ", port);
        }
        else {
	        /* FILTER */
        	if(portrange != NULL) ret += snprintf(filter_expr+ret, (len - ret), "%s portrange %s ", ret ? " or": "", portrange);
        	else if(port > 0) ret += snprintf(filter_expr+ret, (len - ret), "%s port %d ", ret ? " or": "", port);
        }        

        /* PROTO */
        if(ip_proto != NULL) ret += snprintf(filter_expr+ret, (len - ret), "%s %s ", ret ? " and": "", ip_proto);
        
        /* CUSTOM FILTER */
        if(userfilter != NULL) ret += snprintf(filter_expr+ret, (len - ret), " %s", userfilter);
        
        /* create filter string */

        //((ip[6:2] & 0x3fff != 0))
        LDEBUG("FILTER: [%s]\n", filter_expr);

        /* compile filter expression (global constant, see above) */
        if (pcap_compile(sniffer_proto, &filter, filter_expr, 1, 0) == -1) {
                LERR("Failed to compile filter \"%s\": %s\n", filter_expr, pcap_geterr(sniffer_proto));
                if(filter_expr) free(filter_expr);
                return NULL;
        }

        /* install filter on sniffer session */
        if (pcap_setfilter(sniffer_proto, &filter)) {
                LERR("Failed to install filter: %s\n", pcap_geterr(sniffer_proto));
                if(filter_expr) free(filter_expr);
                return NULL;
        }

        if(filter_expr) free(filter_expr);
        
        /* detect link_offset. Thanks ngrep for this. */
        switch(pcap_datalink(sniffer_proto)) {
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

                default:
                    LERR( "fatal: unsupported interface type %u\n", pcap_datalink(sniffer_proto));
                    exit(-1);
        }

        /* REASM */
        if(reasm_enable) {
                reasm = reasm_ip_new ();
                reasm_ip_set_timeout (reasm, 30000000);
        }                                
        
        if(tcpdefrag_enable) {
                tcpreasm = tcpreasm_ip_new ();
                tcpreasm_ip_set_timeout (tcpreasm, 30000000);
        }                                

        while (pcap_loop(sniffer_proto, 0, (pcap_handler)callback_proto, 0));


        /* terminate from here */
        handler(1);

        return NULL;
}




int unload_module(void)
{
        LNOTICE("unloaded module proto_uni\n");

        if (reasm != NULL) reasm_ip_free(reasm);
        if (tcpreasm != NULL) tcpreasm_ip_free(tcpreasm);
        timer_loop_stop = 0;
                    
	 /* Close socket */
        pcap_close(sniffer_proto);        

        return 0;
}

int load_module(xml_node *config)
{
        char *dev = NULL, *usedev = NULL;
        char errbuf[PCAP_ERRBUF_SIZE];                                
        xml_node *modules;
        char *key, *value = NULL, *local_pt = NULL;
        
        LNOTICE("Loaded proto_uni\n");
                                           
        /* READ CONFIG */
        modules = config;

        while(1) {
                if(modules ==  NULL) break;
                modules = xml_get("param", modules, 1 );
                if(modules->attr[0] != NULL && modules->attr[2] != NULL) {

                        /* bad parser */
                        if(strncmp(modules->attr[2], "value", 5) || strncmp(modules->attr[0], "name", 4)) {
                            LERR( "bad keys in the config\n");
                            goto next;
                        }

                        key =  modules->attr[1];
                        value = modules->attr[3];

                        if(key == NULL || value == NULL) {
                            LERR( "bad values in the config\n");
                            goto next;

                        }

                        if(!strncmp(key, "dev", 3)) usedev = value;                        
                        else if(!strncmp(key, "ip-proto", 8)) ip_proto = value;
                        else if(!strncmp(key, "proto-type", 10)) local_pt = value;
                        else if(!strncmp(key, "portrange", 9)) portrange = value;
                        else if(!strncmp(key, "promisc", 7) && !strncmp(value, "false", 5)) promisc = 0;
                        else if(!strncmp(key, "expire-timer", 12)) {
                                expire_timer_array = atoi(value);
                                if(expire_timer_array <= 10) expire_timer_array = EXPIRE_TIMER_ARRAY;
                        }
                        else if(!strncmp(key, "expire-rtcp", 11)) {
                                expire_hash_value = atoi(value);
                                if(expire_hash_value <= 10) expire_hash_value = EXPIRE_RTCP_HASH;
                        }
                        else if(!strncmp(key, "filter", 6)) userfilter = value;
                        else if(!strncmp(key, "port", 4)) port = atoi(value);
                        else if(!strncmp(key, "sip-parse", 9) && !strncmp(value, "true", 4)) sip_parse = 1;
                        else if(!strncmp(key, "rtcp-tracking", 13) && !strncmp(value, "true", 4)) rtcp_tracking = 1;
                        else if(!strncmp(key, "vlan", 4) && !strncmp(value, "true", 4)) vlan = 1;
                        else if(!strncmp(key, "reasm", 5) && !strncmp(value, "true", 4)) reasm_enable = 1;
                        else if(!strncmp(key, "debug", 5) && !strncmp(value, "true", 4)) debug_proto_uni_enable = 1;
                        else if(!strncmp(key, "buildin-reasm-filter", 20) && !strncmp(value, "true", 4)) buildin_reasm_filter = 1;
                        else if(!strncmp(key, "tcpdefrag", 9) && !strncmp(value, "true", 4)) tcpdefrag_enable = 1;
                        else if(!strncmp(key, "send-message", 9) && !strncmp(value, "false", 5)) send_enable = 0;                                                
                        else if (!strncmp(key, "sip_method", 10)) sip_method = value;
                        
                                      
                }
next:

                modules = modules->next;
        }

        /* DEV || FILE */
        if(!usefile) {
          dev = usedev ? usedev : pcap_lookupdev(errbuf);
          if (!dev) {
              perror(errbuf);
              exit(-1);
          }
        }
       
        /*
        if(port == 0 && portrange == NULL) {        
                LERR( "bad port or portranges in the config\n");
                return -1;
        }
        */

        /* CHECK PROTO */
        if(!strncmp(local_pt, "sip", 3)) proto_type = PROTO_SIP;
        else if(!strncmp(local_pt, "xmpp", 4)) proto_type = PROTO_XMPP;                        
        else {
                LERR( "Unsupported protocol. Switched to SIP\n");
                proto_type = PROTO_SIP;
        }                                        

        /* check sip method */
        if (proto_type == PROTO_SIP && sip_method )
        {
        	if (sip_method[0] == '!'){
        		sip_method_not = 1;
        	}
        }


        /* start timer */
        if(sip_parse && rtcp_tracking) timer_init ();

        // start thread
        pthread_create(&call_thread, NULL, proto_collect, (void *)dev);
        
                                         
        return 0;
}


char *description(void)
{
        LNOTICE("Loaded description\n");
        char *description = "test description";
        
        return description;
}


int statistic(char *buf)
{
        snprintf(buf, 1024, "Statistic of PROTO_UNI module:\r\nSend packets: [%i]\r\n", sendPacketsCount);
        return 1;
}
                        
