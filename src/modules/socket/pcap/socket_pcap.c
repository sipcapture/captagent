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


#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */
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

char *module_name="socket_pcap";
uint64_t module_serial = 0;
char *module_description;
int debug_socket_pcap_enable = 0;

static socket_pcap_stats_t stats;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t call_thread[MAX_SOCKETS];
pcap_t *sniffer_proto[MAX_SOCKETS];
struct reasm_ip *reasm[MAX_SOCKETS];
struct tcpreasm_ip *tcpreasm[MAX_SOCKETS];

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static uint64_t serial_module(void);
static int free_profile(unsigned int idx);

unsigned int profile_size = 0;
int verbose = 0;

bind_protocol_module_api_t proto_bind_api;

static cmd_export_t cmds[] = { 
        { "socket_pcap_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 }, 
        { "socket_pcap_check", (cmd_function) bind_check_size, 3, 0, 0, 0 }, 
        { "bind_socket_pcap",  (cmd_function)bind_socket_pcap,  0, 0, 0, 0}, 
        {"tzsp_payload_extract", (cmd_function) w_tzsp_payload_extract, 0, 0, 0, 0 },                                   
        { 0, 0, 0, 0, 0, 0 } 
};

struct module_exports exports = {
        "protocol_sip",
        cmds,        /* Exported functions */
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

int apply_filter (filter_msg_t *filter) {

	return 1;
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

/* Callback function that is passed to pcap_loop() */
void callback_proto(u_char *useless, struct pcap_pkthdr *pkthdr, u_char *packet) {

  int vlan_count = 0, mpls_count = 0;

  // define MPLS struct
  union mpls mpls;
  
  uint8_t hdr_offset = 0; // offset for VLAN or MPLS
  u_int16_t type = 0, vlan_id;
  
  uint8_t erspan_offset = 0;
  uint8_t tmp_ip_proto = 0;
  uint8_t tmp_ip_len = 0;
  
  uint8_t loc_index = (uint8_t) *useless;
  
  if (profile_socket[loc_index].erspan == 1) {
    memcpy(&tmp_ip_proto, (packet + ETHHDR_SIZE + IPPROTO_OFFSET), 1);
    if (tmp_ip_proto == GRE_PROTO) {
      memcpy(&tmp_ip_len, (packet + ETHHDR_SIZE), 1);
      tmp_ip_len = (tmp_ip_len & IPLEN_MASK) * 4; // LSB 4 bits: length in 32-bit words
      //printf("ip.proto: %d, ip header len: %d\n", tmp_ip_proto, tmp_ip_len);
      erspan_offset = ETHHDR_SIZE + tmp_ip_len + GREHDR_SIZE; // Ethernet + IP + GRE
      pkthdr->len -= erspan_offset;
      pkthdr->caplen -= erspan_offset;
      packet += erspan_offset;
    }
  }
  
  struct run_act_ctx ctx;
  struct ether_header *eth = (struct ether_header *) packet;
  
  /* check for ethernet type */
  
  // VLAN
  if(ntohs(eth->ether_type == VLAN)) {
    vlan_id = ((packet[link_offset] << 8) + packet[link_offset+1]) & 0xFFF;
    type = (packet[link_offset+2] << 8) + packet[link_offset+3];
    hdr_offset += 4;
    vlan_count++;
    // double tagging for 802.1Q
    if(type == VLAN) {
      vlan_id = ((packet[link_offset+hdr_offset] << 8) +
		 packet[link_offset+hdr_offset+1]) & 0xFFF;
      type = (packet[link_offset+hdr_offset+2] << 8) +
	packet[link_offset+hdr_offset+3];
      hdr_offset += 4;
    }
  }
  // MPLS
  else if(ntohs(eth->ether_type == MPLS_UNI) ||
	  ntohs(eth->ether_type == MPLS_MULTI)) {

    mpls.u32 = *((uint32_t *) &packet[link_offset]);
    mpls.u32 = ntohl(mpls.u32);
    hdr_offset += 4;
    mpls_count++;

    // in case of multiples MPLS fields (s == 0) 
    while(mpls.mpls.s == 0) {
      mpls.u32 = *((uint32_t *) &packet[link_offset+hdr_offset]);
      mpls.u32 = ntohl(mpls.u32);
      hdr_offset += 4;
    }
  }
  // IP
  struct ip      *ip4_pkt = (struct ip *)(packet + link_offset + hdr_offset);
#if USE_IPv6
  struct ip6_hdr *ip6_pkt = (struct ip6_hdr*)(packet + link_offset + hdr_offset);
#endif

  msg_t _msg;
  uint32_t ip_ver;
  uint8_t ip_proto = 0;
  uint32_t ip_hl = 0;
  uint32_t ip_off = 0;
  uint8_t fragmented = 0;
  uint16_t frag_offset = 0;
  //uint32_t frag_id = 0;
  char ip_src[INET6_ADDRSTRLEN + 1], ip_dst[INET6_ADDRSTRLEN + 1];
  char mac_src[20], mac_dst[20];
  u_char *pack = NULL;
  unsigned char *data, *datatcp;	        
  int action_idx = 0;	
  uint32_t len = pkthdr->caplen;
  uint8_t  psh = 0;
	        
  /* stats */
  stats.received_packets_total++;

  if (profile_socket[loc_index].reasm == 1 && reasm[loc_index] != NULL) {
    unsigned new_len;

    u_char *new_p = malloc(len - link_offset - hdr_offset);
    memcpy(new_p, ip4_pkt, len - link_offset - hdr_offset);

    pack = reasm_ip_next(reasm[loc_index], new_p, len - link_offset - hdr_offset,
			 (reasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len);

    if (pack == NULL) return;

    len = new_len + link_offset + hdr_offset;
    pkthdr->len = new_len;
    pkthdr->caplen = new_len;

    ip4_pkt = (struct ip *) pack;
#if USE_IPv6
    ip6_pkt = (struct ip6_hdr*)pack;
#endif
  }

  ip_ver = ip4_pkt->ip_v;

  //BSD
  snprintf(mac_src, sizeof(mac_src), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->ether_shost[0] , eth->ether_shost[1] , eth->ether_shost[2] , eth->ether_shost[3] , eth->ether_shost[4] , eth->ether_shost[5]);
  snprintf(mac_dst, sizeof(mac_dst), "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",eth->ether_dhost[0] , eth->ether_dhost[1] , eth->ether_dhost[2] , eth->ether_dhost[3] , eth->ether_dhost[4] , eth->ether_dhost[5]);
        
  memset(&_msg, 0, sizeof(msg_t));
  memset(&ctx, 0, sizeof(struct run_act_ctx));
        
  _msg.cap_packet = (void *) packet;
  _msg.cap_header = (void *) pkthdr;                

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
  }break;
#endif
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

    if ((int32_t) len < 0) len = 0;

    if(tcpreasm[loc_index] != NULL &&  (len > 0) && (tcp_pkt->th_flags & TH_ACK)) {

      unsigned new_len;
      u_char *new_p_2 = malloc(len+10);
      memcpy(new_p_2, data, len);
        
      if((tcp_pkt->th_flags & TH_PUSH)) psh = 1;

                                        
      if(debug_socket_pcap_enable) LDEBUG("DEFRAG TCP process: LEN:[%d], ACK:[%d], PSH[%d]\n", len, (tcp_pkt->th_flags & TH_ACK), psh);
                        
      datatcp = tcpreasm_ip_next_tcp(tcpreasm[loc_index], new_p_2, len , (tcpreasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len, &ip4_pkt->ip_src, &ip4_pkt->ip_dst, ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), psh);

      if (datatcp == NULL) return;
                                                
      len = new_len;
                        
      if(debug_socket_pcap_enable)
	LDEBUG("COMPLETE TCP DEFRAG: LEN[%d], PACKET:[%s]\n", len, datatcp);
                        

      if(!profile_socket[profile_size].full_packet) {
	_msg.data = datatcp;
	_msg.len = len;
      }
      else {
	// _msg.len = pkthdr->caplen - link_offset;
	// _msg.data = (packet + link_offset);
	_msg.data = datatcp;
	_msg.len = len;		        
      }

      _msg.rcinfo.src_port = ntohs(tcp_pkt->th_sport);
      _msg.rcinfo.dst_port = ntohs(tcp_pkt->th_dport);
      _msg.rcinfo.src_ip = ip_src;
      _msg.rcinfo.dst_ip = ip_dst;
      _msg.rcinfo.src_mac = mac_src;
      _msg.rcinfo.dst_mac = mac_dst;
      _msg.rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
      _msg.rcinfo.ip_proto = ip_proto;
      _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
      _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
      _msg.tcpflag = tcp_pkt->th_flags;
      _msg.parse_it = 1;

      action_idx = profile_socket[loc_index].action;		
      run_actions(&ctx, main_ct.clist[action_idx], &_msg);
			
      /**
	 hook to function process_packet:
	 in process_packet I have to prepare the Key
	 and the Handshake for Hashtable 
      */
			
      /* clear datatcp */
      free(datatcp);                    
    }
    else {

      if(!profile_socket[profile_size].full_packet) {
	_msg.data = data;
	_msg.len = len;
      }
      else {
	_msg.len = pkthdr->caplen - link_offset - hdr_offset;
	_msg.data = (packet + link_offset + hdr_offset);
      }

      _msg.rcinfo.src_port = ntohs(tcp_pkt->th_sport);
      _msg.rcinfo.dst_port = ntohs(tcp_pkt->th_dport);
      _msg.rcinfo.src_ip = ip_src;
      _msg.rcinfo.dst_ip = ip_dst;
      _msg.rcinfo.src_mac = mac_src;
      _msg.rcinfo.dst_mac = mac_dst;
      _msg.rcinfo.ip_family = ip_ver == 4 ? AF_INET : AF_INET6;
      _msg.rcinfo.ip_proto = ip_proto;
      _msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
      _msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
      _msg.tcpflag = tcp_pkt->th_flags;
      _msg.parse_it = 1;

      action_idx = profile_socket[loc_index].action;		
      run_actions(&ctx, main_ct.clist[action_idx], &_msg);
		        
      stats.send_packets++;

    }

  }
    break;

  case IPPROTO_UDP: {
    struct udphdr *udp_pkt = (struct udphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
    uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);

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

    if ((int32_t) len < 0) len = 0;

    if(!profile_socket[profile_size].full_packet) {
      _msg.data = data;
      _msg.len = len;
    }
    else {
      _msg.len = pkthdr->caplen - link_offset - hdr_offset;
      _msg.data = (packet + link_offset + hdr_offset);
		        
    }
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
  if(pack != NULL) free(pack);
}

int init_socket(unsigned int loc_idx) {

	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_expr[FILTER_LEN];
	int len=0, buffer_size = 0;

	LDEBUG("Activating device: %s\n", profile_socket[loc_idx].device);
        
	if (profile_socket[loc_idx].device) {
	
	        buffer_size =  1024 * 1024 * profile_socket[loc_idx].ring_buffer;
	
		if ((sniffer_proto[loc_idx] = pcap_create((char *) profile_socket[loc_idx].device, errbuf)) == NULL) {
			LERR("Failed to open packet sniffer on %s: pcap_create(): %s", (char * )profile_socket[loc_idx].device, errbuf);
			return -1;
		};
		
		if (pcap_set_promisc(sniffer_proto[loc_idx], profile_socket[loc_idx].promisc) == -1) {
			LERR("Failed to set promisc \"%s\": %s", (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		};
		
		if (pcap_set_timeout(sniffer_proto[loc_idx], profile_socket[loc_idx].timeout) == -1) {
			LERR("Failed to set timeout \"%s\": %s", (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;
		};
		
		if (pcap_set_snaplen(sniffer_proto[loc_idx], profile_socket[loc_idx].snap_len) == -1) {
			LERR("Failed to set snap_len [%d], \"%s\": %s", profile_socket[loc_idx].snap_len, (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;						
		};
		
		if (pcap_set_buffer_size(sniffer_proto[loc_idx], buffer_size) == -1) {
			LERR("Failed to set buffer_size [%d] \"%s\": %s", buffer_size,  (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;									
		};
		
		if (pcap_activate(sniffer_proto[loc_idx]) != 0) {
			LERR("Failed to activate  \"%s\": %s", (char *) profile_socket[loc_idx].device, pcap_geterr(sniffer_proto[loc_idx]));
			return -1;									
		};
		
		LDEBUG("Activated device: [%s]\n", profile_socket[loc_idx].device);
						
	} else {

		if ((sniffer_proto[loc_idx] = pcap_open_offline(usefile, errbuf)) == NULL) {
			LERR("%s: Failed to open packet sniffer on %s: pcap_open_offline(): %s", module_name, usefile, errbuf);
			return -1;
		}
		
		LNOTICE("Sending file: %s", usefile);
	}

	/* create filter string */
	if(profile_socket[loc_idx].filter && strlen(profile_socket[loc_idx].filter) > 0)
	{
		len += snprintf(filter_expr+len, sizeof(filter_expr)-len, "(%s)", profile_socket[loc_idx].filter);

		if(ipv4fragments || ipv6fragments)
		{
			if (ipv4fragments)
			{
				LDEBUG("Reassembling of IPv4 packets is enabled, adding '%s' to filter", BPF_DEFRAGMENTION_FILTER_IPV4);
				len += snprintf(filter_expr+len, sizeof(filter_expr), " or %s", BPF_DEFRAGMENTION_FILTER_IPV4);
			}
			if (ipv6fragments)
			{
				LDEBUG("Reassembling of IPv6 packets is enabled, adding '%s' to filter", BPF_DEFRAGMENTION_FILTER_IPV6);
				len += snprintf(filter_expr+len, sizeof(filter_expr), " or %s", BPF_DEFRAGMENTION_FILTER_IPV6);
			}
		}
	}

	if(profile_socket[loc_idx].capture_filter)
	{
		if(!strncmp(profile_socket[loc_idx].capture_filter, "rtcp", 4))
		{
			len += snprintf(filter_expr+len, sizeof(filter_expr), "%s %s", len ? " and" : "", RTCP_FILTER);
		}
		else if(!strncmp(profile_socket[loc_idx].capture_filter, "rtp", 3))
		{
			len += snprintf(filter_expr+len, sizeof(filter_expr), "%s %s", len ? " and" : "", RTP_FILTER);
		}
	}

	LNOTICE("Using filter: %s", filter_expr);
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
	
	//disabled temporaly
	//pcap_freecode(&filter);

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
                
        LERR("APPLY FILTER [%d]\n", loc_idx);        
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

	unsigned int loc_idx = *((int *)arg);
	int ret = 0, dl = 0;

	dl = pcap_datalink(sniffer_proto[loc_idx]);
	/* detect link_offset. Thanks ngrep for this. */
	switch (dl) {
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
		LERR("fatal: unsupported interface type [%u] [%d]", dl, dl);
		exit(-1);
	}

	LDEBUG("Link offset interface type [%u] [%d] [%d]", dl, dl, link_offset);

	while(1) {
		ret = pcap_loop(sniffer_proto[loc_idx], 0, (pcap_handler) callback_proto, (u_char *) &loc_idx);
		if (ret == 0)
		{
			LDEBUG("loop stopped by EOF");
			pcap_close(sniffer_proto[loc_idx]);
			break;
		} else if (ret == -2)
		{
			LDEBUG("loop stopped by breakloop");
			pcap_close(sniffer_proto[loc_idx]);	
			break;
		}
	}

	//printf("------- OUT OF CALLBACK PROTO ------\n");


	/* free arg */
	//if(arg) free(arg);

	//pthread_t id = pthread_self();
	//printf("\n First thread processing done: %d\n", id);
	//int ret1  = 100;
	//pthread_exit(&ret1);

	/* terminate from here */
	//if (usefile) sleep(10);
	//handler(1);

	LDEBUG("exit loop");
	
	return NULL;
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
						profile_socket[profile_size].reasm = +1;
                                        else if (!strncmp(key, "ipv4fragments", 13) && !strncmp(value, "true", 4))
						ipv4fragments = 1;
                                        else if (!strncmp(key, "ipv6fragments", 13) && !strncmp(value, "true", 4))
						ipv6fragments = 1;
                                        else if(!strncmp(key, "tcpdefrag", 9) && !strncmp(value, "true", 4))
                                                profile_socket[profile_size].reasm +=2;                                                    						
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
                if (profile_socket[i].reasm == 1 || profile_socket[i].reasm == 3) {
                        reasm[i] = reasm_ip_new();
                        reasm_ip_set_timeout(reasm[i], 30000000);
                }
                else reasm[i] = NULL;

                /* TCPREASM */
                if (profile_socket[i].reasm == 2 || profile_socket[i].reasm == 3) {
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

	return 0;
}

static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);

	for (i = 0; i < profile_size; i++) {

		if(sniffer_proto[i]) {
  		    pcap_breakloop(sniffer_proto[i]);
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


/*TZSP */
static inline const char* name_tag(int tag,
                                   const char * const names[],
                                   int names_len) {
        if (tag >= 0 && tag < names_len) {
                return names[tag];
        }
        else {
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

	uint32_t ip_ver;
	uint8_t ip_proto = 0;
	uint32_t ip_hl = 0;
	uint32_t ip_off = 0;
	uint8_t fragmented = 0;
	uint16_t frag_offset = 0;
	char ip_src[INET6_ADDRSTRLEN + 1], ip_dst[INET6_ADDRSTRLEN + 1];
	char mac_src[20], mac_dst[20];
	uint32_t len = pkthdr->caplen;
	unsigned char *data = NULL;
	        
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
        		if ((int32_t) len < 0) len = 0;

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
