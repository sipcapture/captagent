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
#include <sys/time.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <net/ethernet.h>
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
#include "socket_tzsp.h"
#include <captagent/modules.h>
#include <captagent/log.h>
#include <captagent/action.h>

profile_socket_t profile_socket[MAX_SOCKETS];

xml_node *module_xml_config = NULL;

uint8_t link_offset = 14;

char *module_name="socket_tzsp";
uint64_t module_serial = 0;
char *module_description;

uv_loop_t *loop;
uv_thread_t runthread;
uv_async_t async_handle;
static uv_udp_t  udp_servers[MAX_SOCKETS];
int reply_to_tzsp = 1;
static socket_tzsp_stats_t stats;
int verbose = 0;
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

static cmd_export_t cmds[] = {
	{"socket_tzsp_bind_api", (cmd_function) bind_api, 1, 0, 0, 0 },
	{ 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
        "socket_tzsp",
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

void on_send(uv_udp_send_t* req, int status) 
{
	if (status == 0 && req) {
		free(req->data);
		free(req); 
		req = NULL;
	}
}
   

#if UV_VERSION_MAJOR == 0                         
void on_recv(uv_udp_t* handle, ssize_t nread, uv_buf_t rcvbuf, struct sockaddr* addr, unsigned flags)
#else
void on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags) 
#endif    
{
       
    msg_t _msg;
    struct timeval  tv;
    int action_idx = 0;
    struct run_act_ctx ctx;
    struct sockaddr_in *cliaddr;
    uint8_t loc_idx = 0;

    if (nread <= 0 || addr == NULL) 
    {
#if UV_VERSION_MAJOR == 0                            
    	free(rcvbuf.base);
#else
        free(rcvbuf->base);
#endif       	
    	return;
    }

    //loc_idx = *((uint8_t *) handle->data);    
    //loc_idx = 0;
    
    gettimeofday(&tv, NULL);

    cliaddr = (struct sockaddr_in*)addr;

    memset(&_msg, 0, sizeof(msg_t));
    memset(&ctx, 0, sizeof(struct run_act_ctx));

#if UV_VERSION_MAJOR == 0                             
    _msg.data = rcvbuf.base;
#else
    _msg.data = rcvbuf->base;
#endif    

    _msg.len = nread;
    
    _msg.rcinfo.dst_port = ntohs(cliaddr->sin_port);
    _msg.rcinfo.dst_ip = inet_ntoa(cliaddr->sin_addr);
    _msg.rcinfo.liid = loc_idx;

    _msg.rcinfo.src_port = atoi(profile_socket[loc_idx].port);
    _msg.rcinfo.src_ip = profile_socket[loc_idx].host;

    _msg.rcinfo.ip_family = addr->sa_family;
    _msg.rcinfo.ip_proto = IPPROTO_UDP;
		
    _msg.rcinfo.proto_type = profile_socket[loc_idx].protocol;
    _msg.rcinfo.time_sec = tv.tv_sec;
    _msg.rcinfo.time_usec = tv.tv_usec;
    _msg.tcpflag = 0;
    _msg.parse_it = 0;
    _msg.rcinfo.socket = &profile_socket[loc_idx].socket;

    _msg.var = (void *) addr;
    _msg.flag[5] = loc_idx;

    if(nread > 150)
    {
            action_idx = profile_socket[loc_idx].action;
            run_actions(&ctx, main_ct.clist[action_idx], &_msg);		                        
    }
    
#if UV_VERSION_MAJOR == 0                            
    	free(rcvbuf.base);
#else
        free(rcvbuf->base);
#endif       	
}
 
#if UV_VERSION_MAJOR == 0                         
uv_buf_t on_alloc(uv_handle_t* client, size_t suggested) {
	char *chunk = malloc(suggested);
	memset(chunk, 0, suggested);
	return uv_buf_init(chunk, suggested);     	        
}

#else 
void on_alloc(uv_handle_t* client, size_t suggested, uv_buf_t* buf) {
    
	char *chunk = malloc(suggested);
	memset(chunk, 0, suggested);
	*buf = uv_buf_init(chunk, suggested);	      
}
#endif

#if UV_VERSION_MAJOR == 0
  void _async_callback(uv_async_t *async, int status)
#else
  void _async_callback(uv_async_t *async)
#endif
{
    LDEBUG("In async callback socket tzsp exit");
}


void _run_uv_loop(void *arg)
{
     uv_loop_t * myloop = (uv_loop_t *)arg;
     uv_run(myloop, UV_RUN_DEFAULT);
}
                 
int close_socket(unsigned int loc_idx) {         
	
	uv_udp_recv_stop(&udp_servers[loc_idx]);	  
	uv_close((uv_handle_t*)&udp_servers[loc_idx], NULL);	  
	return 0;
}
         
int init_socket(unsigned int loc_idx) {

	struct sockaddr_in v4addr;
	int status;

	status = uv_udp_init(loop,&udp_servers[loc_idx]);

#if UV_VERSION_MAJOR == 0                         
	v4addr = uv_ip4_addr(profile_socket[loc_idx].host, atoi(profile_socket[loc_idx].port));

#else    
      	status = uv_ip4_addr(profile_socket[loc_idx].host, atoi(profile_socket[loc_idx].port), &v4addr);
#endif
      
#if UV_VERSION_MAJOR == 0                         
	status = uv_udp_bind(&udp_servers[loc_idx], v4addr,0);
#else    
	status = uv_udp_bind(&udp_servers[loc_idx], (struct sockaddr*)&v4addr, UV_UDP_REUSEADDR);
	      
#endif
	if(status < 0) 
	{
		LERR( "capture: bind error");
	        return 2;
	}


	udp_servers[loc_idx].data = (void *) &loc_idx;

	status = uv_udp_recv_start(&udp_servers[loc_idx], on_alloc, on_recv);

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

	xml_node *params, *profile=NULL, *settings;
	char *key, *value = NULL;
	unsigned int i = 0;
	//char module_api_name[256];
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
		memset(&profile_socket[profile_size], 0, sizeof(profile_socket_t));
		profile_socket[profile_size].name = strdup(profile->attr[1]);
		profile_socket[profile_size].description = strdup(profile->attr[3]);
		profile_socket[profile_size].serial = atoi(profile->attr[7]);
		profile_socket[profile_size].protocol = PROTO_SIP; //we extract SIP and send as SIP packet
		profile_socket[profile_size].port = TZSP_PORT;
		profile_socket[profile_size].host = TZSP_HOST;
		
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
					else if (!strncmp(key, "protocol-type", 13))
						profile_socket[profile_size].protocol = atoi(value);						
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

#if UV_VERSION_MAJOR == 0
    loop = uv_loop_new();
#else               
    loop = malloc(sizeof *loop);
    uv_loop_init(loop);
#endif

	for (i = 0; i < profile_size; i++) {

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
			}

			profile_socket[i].action = main_ct.idx;
		}

		// start thread
		if (init_socket(i)) {
			LERR("couldn't init tzsp");
			return -1;
		}

		//pthread_create(&call_thread, NULL, proto_collect, arg);

	}
	
	uv_async_init(loop, &async_handle, _async_callback);
	uv_thread_create(&runthread, _run_uv_loop, loop);

	return 0;
}

static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);

	for (i = 0; i < profile_size; i++) {

		close_socket(i);
		free_profile(i);
	}
	
	                 
#if UV_VERSION_MAJOR == 0
	uv_async_send(&async_handle);
	uv_loop_delete(loop);
#else

	if (uv_loop_alive(loop)) {
        	uv_async_send(&async_handle);
	}
   
	uv_stop(loop);
	uv_loop_close(loop);
	free(loop);
#endif
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

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.received_packets_total);
	ret += snprintf(buf+ret, len-ret, "TCP received: [%" PRId64 "]\r\n", stats.received_tcp_packets);
	ret += snprintf(buf+ret, len-ret, "UDP received: [%" PRId64 "]\r\n", stats.received_udp_packets);
	ret += snprintf(buf+ret, len-ret, "SCTP received: [%" PRId64 "]\r\n", stats.received_sctp_packets);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets);


	return 1;
}

