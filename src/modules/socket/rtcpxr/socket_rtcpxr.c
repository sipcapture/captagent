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


#include <captagent/capture.h>
#include <captagent/globals.h>
#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include "socket_rtcpxr.h"
#include <captagent/modules.h>
#include <captagent/log.h>

profile_socket_t profile_socket[MAX_SOCKETS];

xml_node *module_xml_config = NULL;

uint8_t link_offset = 14;

char *module_name="socket_rtcpxr";
uint64_t module_serial = 0;
char *module_description;

static socket_rtcpxr_stats_t stats;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t call_thread;
struct reasm_ip *reasm[MAX_SOCKETS];

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static uint64_t serial_module(void);
static int free_profile(unsigned int idx);

unsigned int profile_size = 0;

bind_protocol_module_api_t proto_bind_api;
//osip_message_t *sip;

static cmd_export_t cmds[] = {
	{"socket_rtcpxr_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
        "socket_rtcpxr",
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
	api->module_name = module_name;
        return 0;
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

ssize_t read_line(int sockd, void *vptr, size_t maxlen) {
    ssize_t n, rc;
    char    c, *buffer;

    buffer = vptr;

    for ( n = 1; n < maxlen; n++ ) {

        if ( (rc = read(sockd, &c, 1)) == 1 ) {
            *buffer++ = c;
            if ( c == '\n' )
                break;
        }
        else if ( rc == 0 ) {
            if ( n == 1 )
                return 0;
            else
                break;
        }
        else {
            if ( errno == EINTR )
                continue;
            return -1;
        }
    }

    *buffer = 0;
    return n;
}


ssize_t write_line(int sockd, const void *vptr, size_t n) {
    size_t      nleft;
    ssize_t     nwritten;
    const char *buffer;

    buffer = vptr;
    nleft  = n;

    while ( nleft > 0 ) {
        if ( (nwritten = write(sockd, buffer, nleft)) <= 0 ) {
            if ( errno == EINTR )
                nwritten = 0;
            else
                return -1;
        }
        nleft  -= nwritten;
        buffer += nwritten;
    }

    return n;
}

void* proto_collect(void *arg) {

	unsigned int loc_idx = (int *) arg;
	int n = 0;
    char data[3000];
    socklen_t len;
    struct sockaddr_in cliaddr;
	msg_t _msg;
	struct timeval  tv;
	int action_idx = 0;

	uint8_t loc_index = (uint8_t *) arg;

	/* free arg */
	free(arg);

	while(1) {

		memset(&_msg, 0, sizeof(msg_t));

		len = sizeof(cliaddr);
		n = recvfrom(profile_socket[loc_idx].socket ,data, 3000, 0, (struct sockaddr *)&cliaddr, &len);

		data[n] = 0;
		LDEBUG("Received the following:\n");
		LDEBUG("%s",data);

		gettimeofday(&tv, NULL);

		_msg.data = &data;
		_msg.len = n;

		_msg.rcinfo.dst_port = ntohs(cliaddr.sin_port);
		_msg.rcinfo.dst_ip = inet_ntoa(cliaddr.sin_addr);
		_msg.rcinfo.liid = loc_idx;

		_msg.rcinfo.src_port = atoi(profile_socket[loc_idx].port);
		_msg.rcinfo.src_ip = profile_socket[loc_idx].host;

		_msg.rcinfo.ip_family = cliaddr.sin_family = 4 ? AF_INET : AF_INET6;
		_msg.rcinfo.ip_proto = IPPROTO_UDP;
		_msg.rcinfo.proto_type = PROTO_SIP;
		_msg.rcinfo.time_sec = tv.tv_sec;
		_msg.rcinfo.time_usec = tv.tv_usec;
		_msg.tcpflag = 0;
		_msg.parse_it = 0;
		_msg.rcinfo.socket = &profile_socket[loc_idx].socket;

		action_idx = profile_socket[loc_index].action;
		run_actions(main_ct.clist[action_idx], &_msg);

	}

	return NULL;
}

int init_socket(unsigned int loc_idx) {

	int s;
    struct addrinfo *ai;
    struct addrinfo hints[1] = {{ 0 }};
    unsigned int on = 1;

	hints->ai_flags = AI_NUMERICSERV;
	hints->ai_family = AF_INET;
	hints->ai_socktype = SOCK_DGRAM;
	hints->ai_protocol = IPPROTO_UDP;

	if(profile_socket[loc_idx].socket) close(profile_socket[loc_idx].socket);

	if ((s = getaddrinfo(profile_socket[loc_idx].host, profile_socket[loc_idx].port, hints, &ai)) != 0) {
	         LERR( "capture: getaddrinfo: %s", gai_strerror(s));
	            return 2;
	}

	if((profile_socket[loc_idx].socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
	         LERR("Sender socket creation failed: %s", strerror(errno));
	         return 1;
	}

	if (setsockopt(profile_socket[loc_idx].socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	{
		LERR("setsockopt(SO_REUSEADDR) failed");
        return 3;

	}

	if (bind(profile_socket[loc_idx].socket, ai->ai_addr, (socklen_t)(ai->ai_addrlen)) < 0) {
	     if (errno != EINPROGRESS) {
	    	 LERR("BIND socket creation failed: %s\n", strerror(errno));
	         return 1;
	     }
    }

	return 0;
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

	xml_node *params, *profile=NULL, *settings, *condition, *action;
	char *key, *value = NULL;
	unsigned int i = 0;
	char module_api_name[256];
	char loadplan[1024];
    FILE* cfg_stream;

	LNOTICE("Loaded %s", module_name);

	load_module_xml_config();

	/* READ CONFIG */
	profile = module_xml_config;

	/* reset profile */
	profile_size = 0;

	while (profile) {

		profile = xml_get("profile", profile, 1);

		memset(&profile_socket[i], 0, sizeof(profile_socket_t));

		if (profile == NULL)
			break;

		if (!profile->attr[4] || strncmp(profile->attr[4], "enable", 6)) {
			goto nextprofile;
		}

		/* if not equals "true" */
		if (!profile->attr[5] || strncmp(profile->attr[5], "true", 4)) {
			goto nextprofile;
		}

		/* set values */
		profile_socket[profile_size].name = strdup(profile->attr[1]);
		profile_socket[profile_size].description = strdup(profile->attr[3]);
		profile_socket[profile_size].serial = atoi(profile->attr[7]);


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

					if (!strncmp(key, "host", 4))
						profile_socket[profile_size].host = strdup(value);
					else if (!strncmp(key, "port", 4))
						profile_socket[profile_size].port = strdup(value);
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

		if(profile_socket[i].capture_plan != NULL)
		{

			snprintf(loadplan, sizeof(loadplan), "%s/%s", global_capture_plan_path, profile_socket[i].capture_plan);
			cfg_stream=fopen (loadplan, "r");

			fprintf(stderr, "loading config file(%s): %s\n", loadplan, strerror(errno));
			if (cfg_stream==0){
			   fprintf(stderr, "ERROR: loading config file(%s): %s\n", loadplan, strerror(errno));
			}

			yyin=cfg_stream;
			if ((yyparse()!=0)||(cfg_errors)){
			          fprintf(stderr, "ERROR: bad config file (%d errors)\n", cfg_errors);
			}

			profile_socket[i].action = main_ct.idx;
		}

		// start thread
		if (init_socket(i)) {
			LERR("couldn't init rtcpxr");
			return -1;
		}

		pthread_create(&call_thread, NULL, proto_collect, arg);

	}

	return 0;
}

static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);

	for (i = 0; i < profile_size; i++) {

		if (profile_socket[i].socket)
				close(profile_socket[i].socket);

		free_profile(i);
	}
	/* Close socket */
	return 0;
}

static int free_profile(unsigned int idx) {

	/*free profile chars **/
	if (profile_socket[idx].name)	 free(profile_socket[idx].name);
	if (profile_socket[idx].description) free(profile_socket[idx].description);
	if (profile_socket[idx].device) free(profile_socket[idx].device);
	if (profile_socket[idx].host) free(profile_socket[idx].host);
	if (profile_socket[idx].port) free(profile_socket[idx].port);
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

