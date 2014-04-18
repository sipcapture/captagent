/*
 * $Id$
 *
 *  captagent - Homer capture agent. 
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) QSC AG  2005-2011 (http://www.qsc.de)
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
#include "minIni/minIni.h"
#include "captagent.h"

/* sender socket */
int sock;
char* pid_file = DEFAULT_PIDFILE; 
int captid = 0;
int hepversion = 3;
char *capt_password;
uint8_t link_offset = 14;


void usage(int8_t e) {
#ifdef USE_CONFFILE
    printf("usage: captagent <-mvhnc> <-d dev> <-s host> <-p port>\n"
           "             <-P pid file> <-r port|portrange> <-f filter file>\n"
           "             <-i id> <-H 1|2|3> --config=<file>\n"
           "      -h  is help/usage\n"
           "      -v  is version information\n"
           "      -m  is don't go into promiscuous mode\n"
           "      -n  is don't go into background\n"
           "      -d  is use specified device instead of the pcap default\n"
           "      -D  is use specified pcap file instead of a device\n"
           "      -s  is the capture server\n"
           "      -p  is use specified port of capture server. i.e. 9060\n"
           "      -r  is open specified capturing port or portrange instead of the default (%s)\n"
           "      -P  is open specified pid file instead of the default (%s)\n"
           "      -f  is the file with specific pcap filter\n"
           "      -c  is checkout\n"
           "      -i  is capture identifity. Must be a 16-bit number. I.e: 101\n"
           "      -H  is HEP protocol version [1|2|3]. By default we use HEP version 3\n"
           "--config  is config file to use to specify some options. Default location is [%s]\n"
           "", DEFAULT_PORT, DEFAULT_PIDFILE, DEFAULT_CONFIG);
	exit(e);
#else
    printf("usage: captagent <-mvhnc> <-d dev> <-s host> <-p port>\n"
           "             <-P pid file> <-r port|portrange> <-f filter file>\n"
           "             <-i id> <-H 1|2>\n"
           "   -h  is help/usage\n"
           "   -v  is version information\n"
           "   -m  is don't go into promiscuous mode\n"
           "   -n  is don't go into background\n"
           "   -d  is use specified device instead of the pcap default\n"
           "   -D  is use specified pcap file instead of a device\n"           
           "   -s  is the capture server\n"
           "   -p  is use specified port of capture server. i.e. 9060\n"
           "   -r  is open specified capturing port or portrange instead of the default (%s)\n"
           "   -P  is open specified pid file instead of the default (%s)\n"
           "   -f  is the file with specific pcap filter\n"
           "   -c  is checkout\n"
           "   -i  is capture identifity. Must be a 16-bit number. I.e: 101\n"
           "   -H  is HEP protocol version [1|2|3]. By default we use HEP version 3\n"
           "", DEFAULT_PORT, DEFAULT_PIDFILE);
	exit(e);

#endif
}


void handler(int value)
{
	fprintf(stderr, "The agent has been terminated\n");
	if(sock) close(sock);
        if (pid_file) unlink(pid_file);             
        exit(0);
}



int daemonize(int nofork)
{

	FILE *pid_stream;
        pid_t pid;
        int p;
	struct sigaction new_action;


	 if (!nofork) {

                if ((pid=fork())<0){
                        fprintf(stderr,"Cannot fork:%s\n", strerror(errno));
                        goto error;
                }else if (pid!=0){
                        exit(0);
                }
	}

        if (pid_file!=0){
                if ((pid_stream=fopen(pid_file, "r"))!=NULL){
                        if (fscanf(pid_stream, "%d", &p) < 0) {
                                fprintf(stderr,"could not parse pid file %s\n", pid_file);
                        }
                        fclose(pid_stream);
                        if (p==-1){
                                fprintf(stderr,"pid file %s exists, but doesn't contain a valid"
                                        " pid number\n", pid_file);
                                goto error;
                        }
                        if (kill((pid_t)p, 0)==0 || errno==EPERM){
                                fprintf(stderr,"running process found in the pid file %s\n",
                                        pid_file);
                                goto error;
                        }else{
                               fprintf(stderr,"pid file contains old pid, replacing pid\n");
                        }
                }
                pid=getpid();
                if ((pid_stream=fopen(pid_file, "w"))==NULL){
                        printf("unable to create pid file %s: %s\n",
                                pid_file, strerror(errno));
                        goto error;
                }else{
                        fprintf(pid_stream, "%i\n", (int)pid);
                        fclose(pid_stream);
                }
        }

	/* sigation structure */
	new_action.sa_handler = handler;
        sigemptyset (&new_action.sa_mask);
        new_action.sa_flags = 0;

	if( sigaction (SIGINT, &new_action, NULL) == -1) {
		perror("Failed to set new Handle");
		return -1;
	}
	if( sigaction (SIGTERM, &new_action, NULL) == -1) {
		perror("Failed to set new Handle");
		return -1;
	}

	return 0;
error:
        return -1;

}


int main(int argc,char **argv)
{
        int mode, c, nofork=0, checkout=0, heps=0;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *sniffer;
        struct bpf_program filter;
        struct addrinfo *ai, hints[1] = {{ 0 }};
        char *dev=NULL, *portrange=DEFAULT_PORT, *capt_host = NULL;
        char *capt_port = NULL, *usedev = NULL, *usefile = NULL;
        char* filter_file = NULL;
	char filter_string[800] = {0};      
        FILE *filter_stream;  
	uint16_t snaplen = 65535, promisc = 1, to = 100;
	pid_t creator_pid = (pid_t) -1;

	creator_pid = getpid();

#ifdef USE_CONFFILE

        #define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

        char *conffile = NULL;

        static struct option long_options[] = {
                {"config", optional_argument, 0, 'C'},
                {0, 0, 0, 0}
        };
	

        
        while((c=getopt_long(argc, argv, "mvhncp:s:d:D:c:P:r:f:i:H:C:", long_options, NULL))!=-1) {
#else
        while((c=getopt(argc, argv, "mvhncp:s:d:D:c:P:r:f:i:H:C:"))!=EOF) {
#endif
                switch(c) {
#ifdef USE_CONFFILE
                        case 'C':
                                        conffile = optarg ? optarg : DEFAULT_CONFIG;
                                        break;
#endif
                        case 'd':
                                        usedev = optarg;
                                        break;
                        case 'D':
                                        usefile = optarg;
                                        break;                                        
                        case 's':
                                        capt_host = optarg;
                                        break;
                        case 'p':
                                        capt_port = optarg;
                                        break;
                        case 'r':
                                        portrange = optarg;
                                        break;
                        case 'h':
                                        usage(0);
                                        break;
                        case 'n':
                                        nofork=1;
                                        break;                                        
                        case 'c':
                                        checkout=1;
                                        nofork=1;
                                        break;                                                                                
                        case 'm':
					promisc = 0;
                                        break;
                        case 'v':
                                        printf("version: %s\n", VERSION);
#ifdef USE_HEP2
                                        printf("HEP2 is enabled\n");
#endif                                        
					exit(0);
                                        break;
                        case 'P':
                                        pid_file = optarg;
                                        break;

                        case 'f':
                                        filter_file = optarg;
                                        break;             
                        case 'i':
                                        captid = atoi(optarg);
                                        break;             
                        case 'H':
                                        hepversion = atoi(optarg);
					heps=1;
                                        break;                                                     
	                default:
                                        abort();
                }
        }

#ifdef USE_CONFFILE

        long n;
        char ini[100];
        char usedev_ini[100];
        char captport_ini[100];
        char captportr_ini[100];
        char filter_ini[255];
        char captid_ini[10];
        char hep_ini[2];

	if(heps == 0) {
		n = ini_gets("main", "hep", "dummy", hep_ini, sizearray(hep_ini), conffile);
		if(strcmp(hep_ini, "dummy") != 0) {
			 hepversion=atoi(hep_ini);
		}

		if(hepversion == 0)
			hepversion = 1;
	}

        if(captid == 0) {
                n = ini_gets("main", "identifier", "dummy", captid_ini, sizearray(captid_ini), conffile);
                if(strcmp(captid_ini, "dummy") != 0) {
                         captid=atoi(captid_ini);
                }
        }

        if(capt_host == NULL) {
                n = ini_gets("main", "capture_server", "dummy", ini, sizearray(ini), conffile);
                if(strcmp(ini, "dummy") != 0) {
                         capt_host=ini;
                }
        }

        if(capt_port == NULL) {
                n = ini_gets("main", "capture_server_port", "dummy", captport_ini, sizearray(captport_ini), conffile);
                if(strcmp(captport_ini, "dummy") != 0) {
                         capt_port=captport_ini;
                }
        }

        if(portrange == NULL) {
                n = ini_gets("main", "capture_server_portrange", "dummy", captportr_ini, sizearray(captportr_ini), conffile);
                if(strcmp(captportr_ini, "dummy") != 0) {
                         portrange=captportr_ini;
                }
        }

        if(filter_file == NULL) {
                n = ini_gets("main", "filter_file", "dummy", filter_ini, sizearray(filter_ini), conffile);
                if(strcmp(filter_ini, "dummy") != 0) {
                         filter_file=filter_ini;
                }
        }


        if(usedev == NULL) {
                n = ini_gets("main", "device", "dummy", usedev_ini, sizearray(usedev_ini), conffile);
                if(strcmp(usedev_ini, "dummy") != 0) {
                         usedev=usedev_ini;
                }
        }

#endif

	if(capt_host == NULL || capt_port == NULL) {
	        fprintf(stderr,"capture server and capture port must be defined!\n");
		usage(-1);
	}

	/* DEV || FILE */
	if(!usefile) {

            dev = usedev ? usedev : pcap_lookupdev(errbuf);
            if (!dev) {
                perror(errbuf);
                exit(-1);
            }

        }

        if(hepversion < 1 && hepversion > 3) {
            fprintf(stderr,"unsupported HEP version. Must be 1,2 or 3, but you have defined as [%i]!\n", hepversion);
            return 1;
        }

        if(filter_file!=0) {
		filter_stream = fopen(filter_file, "r");
		if (!filter_stream  || !fgets(filter_string, sizeof(filter_string)-1, filter_stream)){
			fprintf(stderr, "Can't get filter from %s (%s)\n", filter_file, strerror(errno));
			exit(1);
		}		
		fclose(filter_stream);
        }

	if(daemonize(nofork) != 0){
		fprintf(stderr,"Daemoniize failed: %s\n", strerror(errno));
		exit(-1);
	}

	hints->ai_flags = AI_NUMERICSERV;
        hints->ai_family = AF_UNSPEC;
        hints->ai_socktype = SOCK_DGRAM;
        hints->ai_protocol = IPPROTO_UDP;

        if (getaddrinfo(capt_host, capt_port, hints, &ai)) {
            fprintf(stderr,"capture: getaddrinfo() error");
            return 2;
        }

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {                        
                 fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));
                 return 3;
        }

        /* not blocking */
        mode = fcntl(sock, F_GETFL, 0);
        mode |= O_NDELAY | O_NONBLOCK;
        fcntl(sock, F_SETFL, mode);

        if (connect(sock, ai->ai_addr, (socklen_t)(ai->ai_addrlen)) == -1) {
            if (errno != EINPROGRESS) {
                    fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));                    
                    return 4;
            }
        }
        
        if(dev) {        
            if((sniffer = pcap_open_live(dev, snaplen, promisc, to, errbuf)) == NULL) {
                    fprintf(stderr,"Failed to open packet sniffer on %s: pcap_open_live(): %s\n", dev, errbuf);
                    return 5;
            }
        } else {
            
            if((sniffer = pcap_open_offline(usefile, errbuf)) == NULL) {   
                    fprintf(stderr,"Failed to open packet sniffer on %s: pcap_open_offline(): %s\n", usefile, errbuf);
                    return 6;        
            }                
        }        

        /* create filter string */
        /* snprintf(filter_expr, 1024, "udp port%s %s and not dst host %s %s", strchr(portrange,'-') ? "range": "" , portrange, capt_host, filter_string); */        
        /* please use the capture port not from SIP range. I.e. 9060 */
        snprintf(filter_expr, 1024, "udp port%s %s and not dst port %s %s", strchr(portrange,'-') ? "range": "" , portrange, capt_port, filter_string);

        /* compile filter expression (global constant, see above) */
        if (pcap_compile(sniffer, &filter, filter_expr, 0, 0) == -1) {
                fprintf(stderr,"Failed to compile filter \"%s\": %s\n", filter_expr, pcap_geterr(sniffer));
                return 6;
        }

        /* install filter on sniffer session */
        if (pcap_setfilter(sniffer, &filter)) {
                fprintf(stderr,"Failed to install filter: %s\n", pcap_geterr(sniffer));                
                return 7;
        }
        
        if(checkout) {
                fprintf(stdout,"Version     : [%s]\n", VERSION);
                fprintf(stdout,"Device      : [%s]\n", dev);
                fprintf(stdout,"File        : [%s]\n", usefile);
                fprintf(stdout,"Port range  : [%s]\n", portrange);
                fprintf(stdout,"Capture host: [%s]\n", capt_host);
                fprintf(stdout,"Capture port: [%s]\n", capt_port);
                fprintf(stdout,"Pid file    : [%s]\n", pid_file);
                fprintf(stdout,"Filter file : [%s]\n", filter_file);
                fprintf(stdout,"Fork        : [%i]\n", nofork);
                fprintf(stdout,"Promisc     : [%i]\n", promisc);
                fprintf(stdout,"Capture ID  : [%i]\n", captid);
                fprintf(stdout,"HEP version : [%i]\n", hepversion);
                fprintf(stdout,"Filter      : [%s]\n", filter_expr);
#ifdef USE_CONFFILE
                fprintf(stdout,"Config file : [%s]\n", conffile);
#endif
                return 0;
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
        

        handler(1);
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
	int ret;

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

        curtime = tv.tv_sec;
        strftime(timebuffer,30,"%m-%d-%Y  %T.",localtime(&curtime));


        if(len < 100) {
                //printf("SIP the message is too small: %d\n", len);
                return -1;
        }

        /* SIP must have alpha */
        if(!isalpha(data[0])) {
                return -1;
        }

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
        rcinfo->proto_type = PROTO_SIP;

	/* Duplcate */
	if(!send_hep_basic(rcinfo, data, (unsigned int) len)) {
	         printf("Not duplicated\n");
        }
        
        if(rcinfo) free(rcinfo);

	return 1;
}



int send_hep_basic (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

        switch(hepversion) {
        
            case 3:
		return send_hepv3(rcinfo, data , len);
                break;
                
            case 2:            
            case 1:        
                return send_hepv2(rcinfo, data, len);                    
                break;
                
            default:
                fprintf(stderr, "Unsupported HEP version [%d]\n", hepversion);                
                break;
        }

        return 0;
}

int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

    struct hep_generic *hg=NULL;
    void* buffer;
    unsigned int buflen=0, iplen=0,tlen=0;
    hep_chunk_ip4_t src_ip4, dst_ip4;
#ifdef USE_IPV6
    hep_chunk_ip6_t src_ip6, dst_ip6;    
#endif            
    hep_chunk_t payload_chunk;
    hep_chunk_t authkey_chunk;
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
        src_ip6.chunk.length = htonl(sizeof(src_ip6));
        
        /* DST IPv6 */
        dst_ip6.chunk.vendor_id = htons(0x0000);
        dst_ip6.chunk.type_id   = htons(0x0006);
        inet_pton(AF_INET6, rcinfo->dst_ip, &dst_ip6.data);
        dst_ip6.chunk.length = htonl(sizeof(dst_ip6));    
        
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
    hg->capt_id.data = htons(captid);
    hg->capt_id.chunk.length = htons(sizeof(hg->capt_id));

    /* Payload */
    payload_chunk.vendor_id = htons(0x0000);
    payload_chunk.type_id   = htons(0x000f);
    payload_chunk.length    = htons(sizeof(payload_chunk) + len);
    
    tlen = sizeof(struct hep_generic) + len + iplen + sizeof(hep_chunk_t);

    /* auth key */
    if(capt_password != NULL) {

          tlen += sizeof(hep_chunk_t);
          /* Auth key */
          authkey_chunk.vendor_id = htons(0x0000);
          authkey_chunk.type_id   = htons(0x000e);
          authkey_chunk.length    = htons(sizeof(authkey_chunk) + strlen(capt_password));
          tlen += strlen(capt_password);
    }

    /* total */
    hg->header.length = htons(tlen);

    buffer = (void*)malloc(tlen);
    if (buffer==0){
        fprintf(stderr,"ERROR: out of memory\n");
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
    if(capt_password != NULL) {

        memcpy((void*) buffer+buflen, &authkey_chunk,  sizeof(struct hep_chunk));
        buflen += sizeof(struct hep_chunk);

        /* Now copying payload self */
        memcpy((void*) buffer+buflen, capt_password, strlen(capt_password));
        buflen+=strlen(capt_password);
    }

    /* PAYLOAD CHUNK */
    memcpy((void*) buffer+buflen, &payload_chunk,  sizeof(struct hep_chunk));
    buflen +=  sizeof(struct hep_chunk);            

    /* Now copying payload self */
    memcpy((void*) buffer+buflen, data, len);    
    buflen+=len;    

    /* send this packet out of our socket */
    send(sock, buffer, buflen, 0); 
            
    /* FREE */        
    if(buffer) free(buffer);
    if(hg) free(hg);        
    
    return 1;
}


int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len) {

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
    hdr.hp_v = hepversion;
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

    if(hepversion == 2) {
    	totlen += sizeof(struct hep_timehdr);
        hep_time.tv_sec = rcinfo->time_sec;
        hep_time.tv_usec = rcinfo->time_usec;
        hep_time.captid = captid;
    }

    /*buffer for ethernet frame*/
    buffer = (void*)malloc(totlen);
    if (buffer==0){
    	fprintf(stderr,"ERROR: out of memory\n");
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
     if(hepversion == 2) {
     	/* TIMING  */
        memcpy((void*)buffer + buflen, &hep_time, sizeof(struct hep_timehdr));
        buflen += sizeof(struct hep_timehdr);
     }

     memcpy((void *)(buffer + buflen) , (void*)(data), len);
     buflen +=len;

     send(sock, buffer, buflen, 0); 
          
     /* FREE */
     if(buffer) free(buffer);

     return 1;

error:
     if(buffer) free(buffer);
     return 0;                     
}
