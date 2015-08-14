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

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

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
#include "ipreasm.h"

xml_node *module_xml_config = NULL;

uint8_t link_offset = 14;

char *module_name="socket_pcap";
uint64_t module_serial = 0;
char *module_description;

static socket_pcap_stats_t stats;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t call_thread;
pcap_t *sniffer_proto[MAX_SOCKETS];
struct reasm_ip *reasm[MAX_SOCKETS];

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static uint64_t serial_module(void);
static int free_profile(unsigned int idx);

unsigned int profile_size = 0;

bind_protocol_module_api_t proto_bind_api;

static cmd_export_t cmds[] = { 
        { "socket_pcap_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 }, 
        { "socket_pcap_check", (cmd_function) bind_check_size, 3, 0, 0, 0 }, 
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

	struct ip *ip4_pkt = (struct ip *) (packet + link_offset);
#if USE_IPv6
	struct ip6_hdr *ip6_pkt = (struct ip6_hdr*)(packet + link_offset);
#endif

	uint8_t loc_index = (uint8_t *) useless;
	msg_t _msg;
	uint32_t ip_ver;
	uint8_t ip_proto = 0;
	uint32_t ip_hl = 0;
	uint32_t ip_off = 0;
	uint8_t fragmented = 0;
	uint16_t frag_offset = 0;
	uint32_t frag_id = 0;
	char ip_src[INET6_ADDRSTRLEN + 1], ip_dst[INET6_ADDRSTRLEN + 1];
	u_char *pack = NULL;
	int action_idx = 0;

	char *data;
	uint32_t len = pkthdr->caplen;


	/* stats */
	stats.recieved_packets_total++;

	if (profile_socket[loc_index].reasm == 1 && reasm[loc_index] != NULL) {
		unsigned new_len;

		u_char *new_p = malloc(len - link_offset - ((ntohs((uint16_t) *(packet + 12)) == 0x8100) ? 4 : 0));
		memcpy(new_p, ip4_pkt, len - link_offset - ((ntohs((uint16_t) *(packet + 12)) == 0x8100) ? 4 : 0));

		pack = reasm_ip_next(reasm[loc_index], new_p, len - link_offset - ((ntohs((uint16_t)*(packet + 12)) == 0x8100)? 4:0),
				(reasm_time_t) 1000000UL * pkthdr->ts.tv_sec + pkthdr->ts.tv_usec, &new_len);

		if (pack == NULL) return;

		len = new_len + link_offset + ((ntohs((uint16_t) *(packet + 12)) == 0x8100) ? 4 : 0);
		pkthdr->len = new_len;
		pkthdr->caplen = new_len;

		ip4_pkt = (struct ip *) pack;
#if USE_IPv6
		ip6_pkt = (struct ip6_hdr*)pack;
#endif
	}

	ip_ver = ip4_pkt->ip_v;

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
		frag_id = ntohs(ip4_pkt->ip_id);

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
				frag_id = ntohl(ip6_fraghdr->ip6f_ident);
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

		data = (char *) (tcp_pkt) + tcphdr_offset;
		len -= link_offset + ip_hl + tcphdr_offset;

		stats.recieved_tcp_packets++;

#if USE_IPv6
		if (ip_ver == 6)
		len -= ntohs(ip6_pkt->ip6_plen);
#endif

		if ((int32_t) len < 0)
			len = 0;

		memset(&_msg, 0, sizeof(msg_t));

		_msg.data = data;
		_msg.len = len;

		_msg.rcinfo.src_port = ntohs(tcp_pkt->th_sport);
		_msg.rcinfo.dst_port = ntohs(tcp_pkt->th_dport);
		_msg.rcinfo.src_ip = ip_src;
		_msg.rcinfo.dst_ip = ip_dst;
		_msg.rcinfo.ip_family = ip_ver = 4 ? AF_INET : AF_INET6;
		_msg.rcinfo.ip_proto = ip_proto;
		_msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
		_msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
		_msg.tcpflag = tcp_pkt->th_flags;
		_msg.parse_it = 1;

		action_idx = profile_socket[loc_index].action;
		run_actions(main_ct.clist[action_idx], &_msg);
		        
		stats.send_packets++;


	}
		break;

	case IPPROTO_UDP: {
		struct udphdr *udp_pkt = (struct udphdr *) ((unsigned char *) (ip4_pkt) + ip_hl);
		uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);

		data = (char *) (udp_pkt) + udphdr_offset;
		len -= link_offset + ip_hl + udphdr_offset;

#if USE_IPv6
		if (ip_ver == 6)
		len -= ntohs(ip6_pkt->ip6_plen);
#endif

		/* stats */
		stats.recieved_udp_packets++;

		if ((int32_t) len < 0)
			len = 0;

		memset(&_msg, 0, sizeof(msg_t));

		_msg.data = data;
		_msg.len = len;
		_msg.rcinfo.src_port = ntohs(udp_pkt->uh_sport);
		_msg.rcinfo.dst_port = ntohs(udp_pkt->uh_dport);
		_msg.rcinfo.src_ip = ip_src;
		_msg.rcinfo.dst_ip = ip_dst;
		_msg.rcinfo.ip_family = ip_ver = 4 ? AF_INET : AF_INET6;
		_msg.rcinfo.ip_proto = ip_proto;
		_msg.rcinfo.time_sec = pkthdr->ts.tv_sec;
		_msg.rcinfo.time_usec = pkthdr->ts.tv_usec;
		_msg.tcpflag = 0;
		_msg.parse_it = 1;

		action_idx = profile_socket[loc_index].action;
		run_actions(main_ct.clist[action_idx], &_msg);


		stats.send_packets++;

	}
		break;

	default:
		break;
	}

	if(pack != NULL) free(pack);
}

int init_socket(unsigned int loc_idx) {

	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_expr[FILTER_LEN];
	uint16_t snaplen = 65535, timeout = 100;

	if (profile_socket[loc_idx].device) {
		if ((sniffer_proto[loc_idx] = pcap_open_live((char *) profile_socket[loc_idx].device, snaplen, profile_socket[loc_idx].promisc,
				timeout, errbuf)) == NULL) {
			LERR("Failed to open packet sniffer on %s: pcap_open_live(): %s", (char * )profile_socket[loc_idx].device, errbuf);
			return -1;
		};
	} else {
		LERR("File : %s", usefile);;
		if ((sniffer_proto[loc_idx] = pcap_open_offline(usefile, errbuf)) == NULL) {
			LERR("%s: Failed to open packet sniffer on %s: pcap_open_offline(): %s", module_name, usefile, errbuf);
			return -1;
		}
	}

	/* create filter string */

	/* compile filter expression (global constant, see above) */
	if (pcap_compile(sniffer_proto[loc_idx], &filter, profile_socket[loc_idx].filter, 1, 0) == -1) {
		LERR("Failed to compile filter \"%s\": %s", filter_expr, pcap_geterr(sniffer_proto[loc_idx]));
		return -1;
	}

	/* install filter on sniffer session */
	if (pcap_setfilter(sniffer_proto[loc_idx], &filter)) {
		LERR("Failed to install filter: %s", pcap_geterr(sniffer_proto[loc_idx]));
		return -1;
	}

	return 1;
}

void* proto_collect(void *arg) {

	unsigned int loc_idx = (int *) arg;
	int ret = 0;



	/* detect link_offset. Thanks ngrep for this. */
	switch (pcap_datalink(sniffer_proto[loc_idx])) {
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
		LERR("fatal: unsupported interface type %u", pcap_datalink(sniffer_proto[loc_idx]));
		exit(-1);
	}

	while(1) {
		ret = pcap_loop(sniffer_proto[loc_idx], 0, (pcap_handler) callback_proto, (u_char*) loc_idx);
		if (ret == -2)
		{
			LDEBUG("loop stopped by breakloop");
			pcap_close(sniffer_proto[loc_idx]);
			break;
		}
	}

	/* free arg */
	if(arg) free(arg);

	/* terminate from here */
	//if (usefile) sleep(10);
	//handler(1);

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
		profile_socket[profile_size].action = -1;

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


					if (!strncmp(key, "dev", 3))
						profile_socket[profile_size].device = strdup(value);
					else if (!strncmp(key, "reasm", 5) && !strncmp(value, "true", 5))
						profile_socket[profile_size].reasm = 1;
					else if (!strncmp(key, "promisc", 7) && !strncmp(value, "false", 5))
						profile_socket[profile_size].promisc = 1;
					else if (!strncmp(key, "filter", 6))
						profile_socket[profile_size].filter = strdup(value);
					else if (!strncmp(key, "capture-plan", 12))
						profile_socket[profile_size].capture_plan = strdup(value);
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

		int *arg = malloc(sizeof(*arg));

		arg = i;

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
		if (profile_socket[i].reasm == 1) {
			reasm[i] = reasm_ip_new();
			reasm_ip_set_timeout(reasm[i], 30000000);
		}


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

		pthread_create(&call_thread, NULL, proto_collect, arg);

	}

	return 0;
}

static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);

	for (i = 0; i < profile_size; i++) {

		if(sniffer_proto[i]) {
  		    pcap_breakloop(sniffer_proto[i]);
  		    pthread_join(call_thread,NULL);
		}

		if (profile_socket[i].reasm == 1 && reasm[i] != NULL) {
			reasm_ip_free(reasm[i]);
			reasm[i] = NULL;
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

	return 1;
}

static int description(char *descr) {
	LNOTICE("Loaded description of %s", module_name);
	descr = module_description;
	return 1;
}

static int statistic(char *buf, size_t len) {

	int ret = 0;

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.recieved_packets_total);
	ret += snprintf(buf+ret, len-ret, "TCP received: [%" PRId64 "]\r\n", stats.recieved_tcp_packets);
	ret += snprintf(buf+ret, len-ret, "UDP received: [%" PRId64 "]\r\n", stats.recieved_udp_packets);
	ret += snprintf(buf+ret, len-ret, "SCTP received: [%" PRId64 "]\r\n", stats.recieved_sctp_packets);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets);


	return 1;
}

