/*
 * $Id$
 *
 *  heptester - checker for HEP protocol
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) SipCapture 2016 (http://www.sipcapture.org)
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


#include <pcap.h>
#include <pcap-bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#ifndef __USE_BSD
#define __USE_BSD  
#endif /* __USE_BSD */

#ifndef __FAVOR_BSD
#define __FAVOR_BSD 
#endif /* __FAVOR_BSD */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */
#define __FAVOR_BSD 
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>                                                  
#include <net/if.h>
#include <getopt.h>
#include <unistd.h>         
#include <signal.h>
#include <time.h>

/* Solaris */
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include "core_hep.h"
#include "heptester.h"
//#include "hep.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

/* sender socket */
int sock;
int captid = 0;
int hepversion = 3;
char *capt_password;
uint8_t link_offset = 14;

int hepv3_received(char *buf, unsigned int len);
int parsing_hepv3_message(char *buf, unsigned int len);


void usage(int8_t e) {
    printf("usage: heptester <-hvc> <-D pcap> \n"
           "   -h  is help/usage\n"
           "   -v  is version information\n"
           "   -D  is use specified pcap file\n"           
           "   -c  is checkout\n"
           "");
	exit(e);
}


int main(int argc,char **argv)
{
        int c;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *sniffer;
        char *usefile = NULL;

        while((c=getopt(argc, argv, "vhD:"))!=EOF) {
                switch(c) {
                        case 'D':
                                        usefile = optarg;
                                        break;                                        
                        case 'h':
                                        usage(0);
                                        break;
                        case 'v':
                                        printf("version: %s\n", VERSION);
                                        break;
	                default:
                                        abort();
                }
        }

	/* DEV || FILE */
	if(!usefile) {
  	    fprintf(stderr, "PLEASE SET FILE\n");
            exit(-1);
        }

        if((sniffer = pcap_open_offline(usefile, errbuf)) == NULL) {   
                    fprintf(stderr,"Failed to open packet sniffer on %s: pcap_open_offline(): %s\n", usefile, errbuf);
                    return 6;        
        }                                

        /* detect link_offset. Thanks ngrep for this. */
        switch(pcap_datalink(sniffer)) {
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
                    fprintf(stderr, "fatal: unsupported interface type %u\n", pcap_datalink(sniffer));
                    exit(-1);
        }

        /* install packet handler for sniffer session */
        while (pcap_loop(sniffer, 0, (pcap_handler)callback_proto, 0));

        printf("DONE\n");
        /* we should never get here during normal operation */
        return 0;
}


/* Callback function that is passed to pcap_loop() */ 
void callback_proto(u_char *useless, struct pcap_pkthdr *pkthdr, u_char *packet) 
{


  /* Pat Callahan's patch for MPLS */
  unsigned char ethaddr[3], mplsaddr[3];
          
  memcpy(&ethaddr, (packet + 12), 2);
  memcpy(&mplsaddr, (packet + 16), 2);
                      
  struct ip      *ip4_pkt = (struct ip *)    (packet + link_offset + ((ntohs((uint16_t)*(&ethaddr)) == 0x8100)? (ntohs((uint16_t)*(&mplsaddr)) == 0x8847)? 8:4:0) );
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

	/* this packet is too small to make sense */
        if (pkthdr->len < udp_payload_offset) return;
         

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

                    dump_proto_packet(pkthdr, packet, ip_proto, data, len, ip_src, ip_dst, 
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


                     dump_proto_packet(pkthdr, packet, ip_proto, data, len, ip_src, ip_dst,
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

        curtime = tv.tv_sec;
        strftime(timebuffer,30,"%m-%d-%Y  %T.",localtime(&curtime));

        if(!memcmp(data, "\x48\x45\x50\x33",4)) {
         
                hepv3_received(data, len);                
        }
        else {
        
                printf("NOT HEP3\n");
        }

        return -1;

        /*
	rcinfo = malloc(sizeof(rc_info_t));
	memset(rcinfo, 0, sizeof(rc_info_t));

        rcinfo->src_port   = sport;
        rcinfo->dst_port   = dport;
        rcinfo->src_ip     = (char *) ip_src;
        rcinfo->dst_ip     = (char *) ip_dst;
        rcinfo->ip_family  = ip_ver = 4 ? AF_INET : AF_INET6 ;
        rcinfo->ip_proto   = proto;
        rcinfo->time_sec   = pkthdr->ts.tv_sec;
        rcinfo->time_usec  = pkthdr->ts.tv_usec;
        rcinfo->proto_type = PROTO_SIP;
        
        if(rcinfo) free(rcinfo);
        */

	return 1;
}

int hepv3_received(char *buf, unsigned int len)
{
	if(!parsing_hepv3_message(buf, len)) {
		printf("couldn't parse hepv3 message\n");
        	return -2;
        }

	return -1;
}



int parsing_hepv3_message(char *buf, unsigned int len) {

        rc_info_t ri;
	char *tmp;
	int tmp_len, i;
	char *payload = NULL;
	unsigned int payload_len = 0;
        struct hep_chunk *chunk;	
        struct hep_generic_recv *hg;
        int totelem = 0;
        int chunk_vendor=0, chunk_type=0, chunk_length=0;
        int total_length = 0;
        char *correlation_id = NULL, *authkey = NULL;
        struct hep_timehdr heptime;
        
	hg = (struct hep_generic_recv*)malloc(sizeof(struct hep_generic_recv));
	if(hg==NULL) {
	        fprintf(stderr,"no more pkg memory left for hg\n");
	        return -1;
        }
	                                                 		
	memset(hg, 0, sizeof(struct hep_generic_recv));
	//memset(heptime, 0, sizeof(struct hep_timehdr));	
	        
	/* HEADER */
	hg->header  = (hep_ctrl_t *) (buf);

	/*Packet size */
	total_length = ntohs(hg->header->length);
	ri.src_port = 0;
	ri.dst_port = 0;

	i = sizeof(hep_ctrl_t);	        
	        
	while(i < total_length) {
                
	        /*OUR TMP DATA */                                  
                tmp = buf+i;

                chunk = (struct hep_chunk*) tmp;
                             
                chunk_vendor = ntohs(chunk->vendor_id);                             
                chunk_type = ntohs(chunk->type_id);
                chunk_length = ntohs(chunk->length);
                       
                /* if chunk_length */
                if(chunk_length == 0) {
                        /* BAD LEN we drop this packet */
                        printf("Content-Len exit: LENGHT [%d] vs TOTAL[%d]: chunk_vendor:[%d], chunk_type:[%d], chunk_length:[%d]\n", i, total_length, chunk_vendor, chunk_type, chunk_length);
                        goto error;
                }

                /* SKIP not general Chunks */
                if(chunk_vendor != 0) {
                        printf("SKIP VENDOR: %d\n",chunk_vendor);                        
                        i+=chunk_length;
                }
                else {                                                                                                                               
                        printf("PARSING Lenght current [%d]: vs TOTAL[%d], chunk_vendor:[%d], chunk_type:[%d], chunk_length:[%d]\n", i, total_length, chunk_vendor, chunk_type, chunk_length);
                        switch(chunk_type) {
                                     
                                case 0:
                                        goto error;
                                        break;
                                     
                                case 1:                                                                          
                                        hg->ip_family  = (hep_chunk_uint8_t *) (tmp);
                                        i+=chunk_length;
                                        totelem++;
                                        break;
                                case 2:
                                        hg->ip_proto  = (hep_chunk_uint8_t *) (tmp);
                                        i+=chunk_length;
                                        totelem++;
                                        break;                                                     
                                case 3:
                                        hg->hep_src_ip4  = (hep_chunk_ip4_t *) (tmp);
                                        i+=chunk_length;
                                        //src_ip.af=AF_INET;
				        //src_ip.len=4;
				        //src_ip.u.addr32[0] = hg->hep_src_ip4->data.s_addr;
				        totelem++;
				        break;
                                case 4:
                                        hg->hep_dst_ip4  = (hep_chunk_ip4_t *) (tmp);
                                        i+=chunk_length;                                                     
					//dst_ip.af=AF_INET;
				        //dst_ip.len=4;
				        //dst_ip.u.addr32[0] = hg->hep_dst_ip4->data.s_addr;
                                        totelem++;

                                        break;
                                case 5:
                                        hg->hep_src_ip6  = (hep_chunk_ip6_t *) (tmp);
                                        i+=chunk_length;
                                        //src_ip.af=AF_INET6;
				        //src_ip.len=16;
				        //memcpy(src_ip.u.addr, &hg->hep_src_ip6->data, 16);
				        totelem++;
                                        break;
                                case 6:
                                        hg->hep_dst_ip6  = (hep_chunk_ip6_t *) (tmp);
                                        i+=chunk_length;                                                     
                                        //dst_ip.af=AF_INET6;
				        //dst_ip.len=16;
				        //memcpy(dst_ip.u.addr, &hg->hep_dst_ip6->data, 16);
				        totelem++;
                                        break;
        
                                case 7:
                                        hg->src_port  = (hep_chunk_uint16_t *) (tmp);
                                        ri.src_port = ntohs(hg->src_port->data);
                                        i+=chunk_length;                      
                                        totelem++;
                                        break;

                                case 8:
                                        hg->dst_port  = (hep_chunk_uint16_t *) (tmp);
                                        ri.dst_port = ntohs(hg->dst_port->data);
                                        i+=chunk_length;
                                        totelem++;
                                        break;
                                case 9:
                                        hg->time_sec  = (hep_chunk_uint32_t *) (tmp);
                                        hg->time_sec->data = ntohl(hg->time_sec->data);
                                        heptime.tv_sec = hg->time_sec->data;
                                        i+=chunk_length;
                                        totelem++;
                                        break;                                                     
                                                     
                                case 10:
                                        hg->time_usec  = (hep_chunk_uint32_t *) (tmp);
                                        hg->time_usec->data = ntohl(hg->time_usec->data);
                                        heptime.tv_usec = hg->time_usec->data;
                                        i+=chunk_length;
                                        totelem++;
                                        break;      

                                case 11:
                                        hg->proto_t  = (hep_chunk_uint8_t *) (tmp);
                                        i+=chunk_length;
                                        totelem++;
                                        break;                                                                                                                                                         

                                case 12:
                                        hg->capt_id  = (hep_chunk_uint32_t *) (tmp);
                                        i+=chunk_length;
                                        heptime.captid = ntohs(hg->capt_id->data);
                                        totelem++;
                                        break;

                                case 13:
                                        hg->keep_tm  = (hep_chunk_uint16_t *) (tmp);
                                        i+=chunk_length;
                                        break;                                                     

                                case 14:
                                        authkey = (char *) tmp + sizeof(hep_chunk_t);
                                        i+=chunk_length;                                                                             
                                        break;
                                                     
                                case 15:
                                        hg->payload_chunk  = (hep_chunk_t *) (tmp);
                                        payload = (char *) tmp+sizeof(hep_chunk_t);
                                        payload_len = chunk_length - sizeof(hep_chunk_t);
                                        i+=chunk_length;
                                        totelem++;
                                        break;
                                case 17:
                                
                                        correlation_id = (char *) tmp + sizeof(hep_chunk_t);
                                        i+=chunk_length;                                                                            
					break;

                                                     
                                default:
                                        i+=chunk_length;
                                        break;
                        }                                        
                }
        }	                                                                                                          
                        
        /* CHECK how much elements */
        if(totelem < 9) {                        
                fprintf(stderr,"Not all elements [%d]\n", totelem);                        
                goto done;
        }                 

        printf("PACKET HEP DONE\n");
                        
done:
        if(hg) free(hg);                     

        return 1;
        
error:

        if(hg) free(hg);                
        printf("ERROR! Exit\n");
        exit(0);
}