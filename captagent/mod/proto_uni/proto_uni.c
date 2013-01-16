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
#include "proto_uni.h"

uint8_t link_offset = 14;

pcap_t *sniffer_proto;
pthread_t call_thread;   


/* Callback function that is passed to pcap_loop() */ 
void callback_proto(u_char *useless, struct pcap_pkthdr *pkthdr, u_char *packet) 
{


	struct ip      *ip4_pkt = (struct ip *)    (packet + link_offset + ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4:0) );
#if USE_IPv6
	struct ip6_hdr *ip6_pkt = (struct ip6_hdr*)(packet + link_offset + ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4:0) );
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

	unsigned char *data;
	uint32_t len = pkthdr->caplen;
	int ret;


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
                    len -= link_offset + ip_hl + tcphdr_offset;

#if USE_IPv6
                    if (ip_ver == 6)
                        len -= ntohs(ip6_pkt->ip6_plen);
#endif

                    if ((int32_t)len < 0)
                        len = 0;

                    ret = dump_proto_packet(pkthdr, packet, ip_proto, data, len, ip_src, ip_dst, 
                            ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), tcp_pkt->th_flags,
                            tcphdr_offset, fragmented, frag_offset, frag_id, ip_ver);
                                        
                } break;

                case IPPROTO_UDP: {
                    struct udphdr *udp_pkt = (struct udphdr *)((unsigned char *)(ip4_pkt) + ip_hl);
                    uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);

                    data = (unsigned char *)(udp_pkt) + udphdr_offset;
                    len -= link_offset + ip_hl + udphdr_offset;
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
        
}


int dump_proto_packet(struct pcap_pkthdr *pkthdr, u_char *packet, uint8_t proto, unsigned char *data, uint32_t len,
                 const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint8_t flags,
                                  uint16_t hdr_offset, uint8_t frag, uint16_t frag_offset, uint32_t frag_id, uint32_t ip_ver) {

        struct timeval tv;
        time_t curtime;
	char timebuffer[30];	
	rc_info_t *rcinfo = NULL;

        gettimeofday(&tv,NULL);

        sendPacketsCount++;

        curtime = tv.tv_sec;
        strftime(timebuffer,30,"%m-%d-%Y  %T.",localtime(&curtime));


        if(len < 100) {
                //printf("SIP the message is too small: %d\n", len);
                return -1;
        }

        /* SIP must have alpha */
        if(proto_type == PROTO_SIP && !isalpha(data[0])) {
                //printf("BAD SIP message: %d\n", len);
                return -1;
        }
        /* gingle XMPP */
        if(proto_type == PROTO_XMPP && memcmp("<iq", data, 3)) {
                //printf("It's not a GINGLE call: %d\n", len);
                return -1;
        }

  //printf("SIP: [%.*s]\n", len, data);

	rcinfo = malloc(sizeof(rc_info_t));
	memset(rcinfo, 0, sizeof(rc_info_t));

        rcinfo->src_port   = sport;
        rcinfo->dst_port   = dport;
        rcinfo->src_ip     = ip_src;
        rcinfo->dst_ip     = ip_dst;
        rcinfo->ip_family  = ip_ver = 4 ? AF_INET : AF_INET6 ;
        rcinfo->ip_proto   = proto;
        rcinfo->time_sec   = pkthdr->ts.tv_sec;
        rcinfo->time_usec  = pkthdr->ts.tv_usec;
        rcinfo->proto_type = proto_type;

	/* Duplcate */
	if(!send_message(rcinfo, data, (unsigned int) len)) {
	         printf("Not duplicated\n");
        }
        
  if(rcinfo) free(rcinfo);

	return 1;
}



void* proto_collect( void* device ) {

        struct bpf_program filter;
        char errbuf[PCAP_ERRBUF_SIZE];
        char filter_expr[FILTER_LEN];
        char filter_port[100], filter_proto[100], filter_user[800];
        uint16_t snaplen = 65535, timeout = 100;        

        if(device) {
            if((sniffer_proto = pcap_open_live((char *)device, snaplen, promisc, timeout, errbuf)) == NULL) {
                fprintf(stderr,"Failed to open packet sniffer on %s: pcap_open_live(): %s\n", (char *)device, errbuf);
                return NULL;
            }
        } else  {
            if((sniffer_proto = pcap_open_offline(usefile, errbuf)) == NULL) {
                fprintf(stderr,"Failed to open packet sniffer on %s: pcap_open_offline(): %s\n", usefile, errbuf);
                return NULL;
            }
        }


        /* FILTER */
        if(portrange != NULL) snprintf(filter_port, 100, "portrange %s", portrange);        
        else snprintf(filter_port, 100, "port %d", port);        

        /* PROTO */
        if(ip_proto != NULL) snprintf(filter_proto, 100, "and %s", ip_proto);

        /* CUSTOM FILTER */
        if(userfilter != NULL) snprintf(filter_user, 800, "and %s", userfilter);
        
               
        snprintf(filter_expr, FILTER_LEN, "%s%s %s %s",vlan?"vlan and ":"", filter_port, ip_proto ? filter_proto : "", userfilter ? userfilter : "");
        
		fprintf(stdout, "expr:%s\n", filter_expr);
        /* create filter string */

        /* compile filter expression (global constant, see above) */
        if (pcap_compile(sniffer_proto, &filter, filter_expr, 1, 0) == -1) {
                fprintf(stderr,"Failed to compile filter \"%s\": %s\n", filter_expr, pcap_geterr(sniffer_proto));
                return NULL;
        }

        /* install filter on sniffer session */
        if (pcap_setfilter(sniffer_proto, &filter)) {
                fprintf(stderr,"Failed to install filter: %s\n", pcap_geterr(sniffer_proto));
                return NULL;
        }
        
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
                    fprintf(stderr, "fatal: unsupported interface type %u\n", pcap_datalink(sniffer_proto));
                    exit(-1);
        }

        while (pcap_loop(sniffer_proto, 0, (pcap_handler)callback_proto, 0));


        /* terminate from here */
        handler(1);

        return NULL;
}




int unload_module(void)
{
        printf("unloaded module proto_uni\n");
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
        
        printf("Loaded proto_uni\n");
                                           
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

                        if(!strncmp(key, "dev", 3)) usedev = value;                        
                        else if(!strncmp(key, "ip-proto", 8)) ip_proto = value;
                        else if(!strncmp(key, "proto-type", 10)) local_pt = value;
                        else if(!strncmp(key, "portrange", 9)) portrange = value;
                        else if(!strncmp(key, "promisc", 7) && !strncmp(value, "false", 5)) promisc = 0;
                        else if(!strncmp(key, "filter", 6)) userfilter = value;
                        else if(!strncmp(key, "port", 4)) port = atoi(value);
                        else if(!strncmp(key, "vlan", 4) && !strncmp(value, "true", 4)) vlan = 1;
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
       
        if(port == 0 && portrange == NULL) {        
                fprintf(stderr, "bad port or portranges in the config\n");
                return -1;
        }

        /* CHECK PROTO */
        if(!strncmp(local_pt, "sip", 3)) proto_type = PROTO_SIP;
        else if(!strncmp(local_pt, "xmpp", 4)) proto_type = PROTO_XMPP;                        
        else {
                fprintf(stderr, "Unsupported protocol. Switched to SIP\n");
		proto_type = PROTO_SIP;
        }                                        

        // start thread
        pthread_create(&call_thread, NULL, proto_collect, (void *)dev);
        
                                         
        return 0;
}


char *description(void)
{
        printf("Loaded description\n");
        char *description = "test description";
        
        return description;
}


char *statistic(void)
{
        char buf[1024];
        snprintf(buf, 1024, "Statistic of PROTO_UNI module:\r\nSend packets: [%i]\r\n", sendPacketsCount);
        return &buf;
}
                        
