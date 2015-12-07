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

#include <pcap.h>

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#include <captagent/capture.h>
#include <captagent/globals.h>
#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "socket_raw.h"
#include <captagent/log.h>
#include "localapi.h"


xml_node *module_xml_config = NULL;

uint8_t link_offset = 14;

char *module_name="socket_raw";
uint64_t module_serial = 0;
char *module_description;

static socket_raw_stats_t stats;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t raw_thread[MAX_SOCKETS];
int socket_desc[MAX_SOCKETS];

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static uint64_t serial_module(void);
static int free_profile(unsigned int idx);

unsigned int profile_size = 0;

bind_protocol_module_api_t proto_bind_api;

static cmd_export_t cmds[] = { 
        { "socket_raw_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 },
        { "socket_raw_check", (cmd_function) bind_check_size, 3, 0, 0, 0 },
 	    {"bind_socket_raw",  (cmd_function)bind_socket_raw,  0, 0, 0, 0},
        { 0, 0, 0, 0, 0, 0 } 
};

struct module_exports exports = {
        "socket_raw",
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

	LNOTICE("NEW FILTER!");
	return 1;
}

int reload_config (char *erbuf, int erlen) {

	char module_config_name[500];
	xml_node *config;

	LNOTICE("reloading config for [%s]", module_name);

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, module_name);

	if(xml_parse_with_report(module_config_name, erbuf, erlen)) {
		unload_module();
		load_module(config);
		return 1;
	}

	return 0;
}

int init_socket(unsigned int loc_idx) {

	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint16_t snaplen = 65535, timeout = 100;
	char short_ifname[sizeof(int)];
	char filter_expr[FILTER_LEN];
	int ifname_len;
	char* ifname;
	int err, len = 0;

	ifname_len = strlen(profile_socket[loc_idx].device);
	ifname = profile_socket[loc_idx].device;

	LDEBUG("rtp collect device: [%s]", (char * )profile_socket[loc_idx].device);

	//rtp_raw_sock = socket(PF_PACKET, SOCK_RAW, htons(0x0800));
	socket_desc[loc_idx] = socket(PF_PACKET, SOCK_RAW, htons(0x0003));

	LDEBUG("ZZ: SCIO: [%d] [%d]\n", loc_idx, socket_desc[loc_idx]);

	if (socket_desc[loc_idx] == -1)
		goto error;

	if (ifname_len < sizeof(int)) {
		short_ifname[ifname_len] = 0; /* make sure it's zero term */
		ifname_len = sizeof(short_ifname);
		ifname = short_ifname;
	}

	int ifindex = if_nametoindex(ifname);
	if ((err = iface_bind(socket_desc[loc_idx], ifindex)) != 1) {
		LERR("raw_socket: could not bind to %s: %s [%d] [%d]", ifname, strerror(errno), errno);
		goto error;

	}

	/* now set filter */
	LDEBUG("FILTER [%s]", profile_socket[loc_idx].filter);

 	/* create filter string */
        if(profile_socket[loc_idx].capture_filter)
        {
                if(!strncmp(profile_socket[loc_idx].capture_filter, "rtcp", 4))
                { 
                        len = snprintf(filter_expr, sizeof(filter_expr), "%s", RTCP_FILTER);
                }     
                else if(!strncmp(profile_socket[loc_idx].capture_filter, "rtp", 3))
                { 
                        len = snprintf(filter_expr, sizeof(filter_expr), "%s", RTP_FILTER);
                }  
                   
                if(profile_socket[loc_idx].filter && strlen(profile_socket[loc_idx].filter) > 0)
                {   
                        len += snprintf(filter_expr+len, sizeof(filter_expr)-len, " and (%s)", profile_socket[loc_idx].filter);
                }

		if (!set_raw_filter(loc_idx, &filter_expr)) {
			LERR("Couldn't apply filter....");
		}
        }
        else {          
		if (!set_raw_filter(loc_idx, profile_socket[loc_idx].filter)) {
			LERR("Couldn't apply filter....");
		}
                 
        }

	return 1;

	error:

		if (socket_desc[loc_idx]) close(socket_desc[loc_idx]);
		/* terminate from here */
		handler(1);

		return -1;
}

void* proto_collect(void *arg) {

	unsigned int loc_idx = (int *) arg;
	int ret = 0;

	/* free arg */
	free(arg);

	link_offset = ETHHDR_SIZE;

	raw_capture_rcv_loop(loc_idx);

	if(socket_desc[loc_idx]) close(socket_desc[loc_idx]);

	/* terminate from here */
	//if (usefile) sleep(10);
	//handler(1);

	return NULL;
}

int set_raw_filter(unsigned int loc_idx, char *filter) {

        struct bpf_program raw_filter;
        uint16_t snaplen = 65535;
        struct bpf_insn *insn;
        int i, n, linktype;
        struct sock_filter* BPF_code;
        struct sock_fprog pf;

        //return 1;
        linktype  = DEFAULT_DATALINK;

        LDEBUG("Filter expr:[%s]", filter);

        if (pcap_compile_nopcap(snaplen, linktype, &raw_filter, filter, 1, 0) == -1) {
                LERR("Failed to compile filter '%s'", filter);
                return -1;
        }

        n = raw_filter.bf_len;
        insn = raw_filter.bf_insns;

        BPF_code = (struct sock_filter*) malloc(n*sizeof(struct sock_filter));

        for (i = 0; i < n; ++insn, ++i) {
                //printf("{ 0x%x, %d, %d, 0x%08x },\n", insn->code, insn->jt, insn->jf, insn->k);
                BPF_code[i] = (struct sock_filter){(unsigned short)insn->code, insn->jt, insn->jf, insn->k };
        }

        memset(&pf, 0, sizeof(pf));
        pf.len = n;
        pf.filter = BPF_code;

        LDEBUG("SOCKET [%d]\n", socket_desc[loc_idx]);
        /* Attach the filter to the socket */
        if(setsockopt(socket_desc[loc_idx], SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) < 0 ) {
                LERR(" setsockopt filter: [%s] [%d]", strerror(errno), errno);
        }

        free(BPF_code);

        return 1;

}

/* Local raw receive loop */
int raw_capture_rcv_loop(unsigned int loc_idx) {

	static char buf[BUF_SIZE + 1];
	int len;
	struct timeval tv;
	struct ip *iph;
	struct udphdr *udph;
	char* udph_start;
	unsigned short udp_len;
	int offset = 0, orig_len;
	char* end;
	unsigned short dst_port;
	unsigned short src_port;
	char src_ip[250], dst_ip[250];
	msg_t _msg;
	uint32_t ip_ver;
	uint8_t ip_proto = 0;
	uint32_t ip_hl = 0;
	uint32_t ip_off = 0;
	uint8_t fragmented = 0;
	uint16_t frag_offset = 0;
	int result;
	int action_idx = 0;

	for (;;) {

		len = recvfrom(socket_desc[loc_idx], buf, BUF_SIZE, 0x20, 0, 0);

		gettimeofday(&tv, NULL);

		if (len < 0) {
			if (len == -1) {
				LDEBUG("ERROR: raw_capture_rcv_loop:recvfrom: %s [%d]", strerror(errno), errno);
				if ((errno == EINTR) || (errno == EWOULDBLOCK))
					continue;
				if(errno == EBADF)
				{
					break;
					return 0;
				}
			} else {
				LDEBUG("raw_capture_rcv_loop: recvfrom error: %d", len);
				continue;
			}
		}

		end = buf + len;

		offset = ETHHDR_SIZE;
		orig_len = len;

		if (len < (sizeof(struct ip) + sizeof(struct udphdr) + offset)) {
			LDEBUG("received small packet: %d. Ignore it", len);
			continue;
		}

		offset += ((ntohs((uint16_t) *(buf + 12)) == 0x8100) ? 4 : 0);

		iph = (struct ip*) (buf + offset);

		offset += iph->ip_hl * 4;

		udph_start = buf + offset;

		udph = (struct udphdr*) udph_start;
		offset += sizeof(struct udphdr);

		if ((buf + offset) > end) {
			continue;
		}

		udp_len = ntohs(udph->uh_ulen);
		if ((udph_start + udp_len) != end) {
			if ((udph_start + udp_len) > end) {
				continue;
			}
		}

		/* cut off the offset */
		len -= offset;

		if (len < MIN_UDP_PACKET) {
			LDEBUG("probing packet received from: %d\n", len);
			continue;
		}

		/* currently only IPv4 */
		snprintf(src_ip, 250, "%s", inet_ntoa(iph->ip_src));
		snprintf(dst_ip, 250, "%s", inet_ntoa(iph->ip_dst));

		/* fill dst_port && src_port */
		dst_port = ntohs(udph->uh_dport);
		src_port = ntohs(udph->uh_sport);

		/* stats */
		stats.recieved_udp_packets++;
		if ((int32_t) len < 0)
			len = 0;

		memset(&_msg, 0, sizeof(msg_t));

		_msg.data = buf;
		//_msg.data = buf + ETHHDR_SIZE;
		_msg.len = len + offset;
		_msg.rcinfo.src_port = src_port;
		_msg.rcinfo.dst_port = dst_port;
		_msg.rcinfo.src_ip = src_ip;
		_msg.rcinfo.dst_ip = dst_ip;
		_msg.rcinfo.ip_family = ip_ver = 4 ? AF_INET : AF_INET6;
		_msg.rcinfo.ip_proto = ip_proto;
		_msg.rcinfo.time_sec = tv.tv_sec;
		_msg.rcinfo.time_usec = tv.tv_usec;
		_msg.tcpflag = 0;
		_msg.parse_it = 1;

		action_idx = profile_socket[loc_idx].action;
		run_actions(main_ct.clist[action_idx], &_msg);

		stats.send_packets++;

	}

	return 0;
}


int iface_bind(int fd, int ifindex)
{
        struct sockaddr_ll      sll;
        int                     err;
        socklen_t               errlen = sizeof(err);

        memset(&sll, 0, sizeof(sll));
        sll.sll_family          = AF_PACKET;
        sll.sll_ifindex         = ifindex;
        sll.sll_protocol        = htons(ETH_P_ALL);

        if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
                if (errno == ENETDOWN) {
                        LERR("raw_socket: could not bind IFACE_NOT_UP");
                        return -1;
                } else {
                        LERR("raw_socket: could not bind PCAP_ERROR");
                        return 0;
                }
        }

        /* Any pending errors, e.g., network is down? */

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
                LERR("getsockopt: %s", pcap_strerror(errno));
                return 0;
        }

        if (err == ENETDOWN) {
                LERR("raw_socket [1]: could not bind IFACE_NOT_UP");
                return PCAP_ERROR_IFACE_NOT_UP;
        } else if (err > 0) {
                LERR("bind error.");
                return 0;
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

static uint64_t serial_module(void)
{
	 return module_serial;
}

static int load_module(xml_node *config) {

	char errbuf[PCAP_ERRBUF_SIZE];
	xml_node *params, *profile=NULL, *settings, *condition, *action;
	char *key, *value = NULL;
	unsigned int i = 0;
	char module_api_name[256], loadplan[1024];
    int status;
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
                profile_socket[profile_size].capture_filter = NULL;
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
					else if (!strncmp(key, "promisc", 7) && !strncmp(value, "true", 4))
						profile_socket[profile_size].promisc = 1;
					else if (!strncmp(key, "filter", 6))
						profile_socket[profile_size].filter = strdup(value);
					else if (!strncmp(key, "capture-plan", 12))
						profile_socket[profile_size].capture_plan = strdup(value);
					else if (!strncmp(key, "capture-filter", 14))
                                                profile_socket[profile_size].capture_filter = strdup(value);
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
			
			//LERR("INDEX: %d, ENT: [%d]\n", main_ct.idx, main_ct.entries);
		}

		LDEBUG("RTP listening device: [%s]\n", arg);
		pthread_create(&raw_thread[i], NULL, proto_collect, arg);

	}

	return 0;
}

static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);

	for (i = 0; i < profile_size; i++) {

		if(socket_desc[i]) {
			close(socket_desc[i]);
			pthread_join(raw_thread[i],NULL);
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

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.recieved_packets_total);
	ret += snprintf(buf+ret, len-ret, "TCP received: [%" PRId64 "]\r\n", stats.recieved_tcp_packets);
	ret += snprintf(buf+ret, len-ret, "UDP received: [%" PRId64 "]\r\n", stats.recieved_udp_packets);
	ret += snprintf(buf+ret, len-ret, "SCTP received: [%" PRId64 "]\r\n", stats.recieved_sctp_packets);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets);


	return 1;
}

