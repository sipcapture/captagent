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

#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "database_hash.h"
#include <captagent/log.h>
#include "localapi.h"
#include "captarray.h"

pthread_rwlock_t ipport_lock;

unsigned int profile_size = 0;

xml_node *module_xml_config = NULL;
char *module_name="database_hash";
uint64_t module_serial = 0;
char *module_description = NULL;

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int reload_config (char *erbuf, int erlen);
static uint64_t serial_module(void);


static cmd_export_t cmds[] = {
		 {"database_hash_bind_api",  (cmd_function)bind_api,   1, 0, 0, 0},
		 {"check_rtcp_ipport", (cmd_function) w_check_rtcp_ipport, 0, 0, 0, 0 },
		 {"is_rtcp_exist", (cmd_function) w_is_rtcp_exists, 0, 0, 0, 0 },
		 {"bind_database_has",  (cmd_function)bind_database_hash,  0, 0, 0, 0},
         /* ================================ */
         {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
		"database_hash",
        cmds,        /* Exported functions */
        load_module,    /* module initialization function */
        unload_module,
        description,
        statistic,
        serial_module
};

int bind_api(database_module_api_t* api)
{
		api->reload_f = reload_config;
		api->module_name = module_name;

        return 0;
}

int w_check_rtcp_ipport(msg_t *msg)
{

	int i = 0;
	miprtcp_t *mp = NULL;
	char ipptmp[256];
	char callid[256];


	snprintf(callid, sizeof(callid), "%.*s", msg->sip.callId.len, msg->sip.callId.s);

	for (i = 0; i < msg->sip.mrp_size; i++) {
		mp = &msg->sip.mrp[i];

		if (mp->rtcp_ip.len > 0 && mp->rtcp_ip.s) {
			snprintf(ipptmp, sizeof(ipptmp), "%.*s:%d", mp->rtcp_ip.len, mp->rtcp_ip.s, mp->rtcp_port);			
			LDEBUG("RTCP CALLID: %.*s", msg->sip.callId.len, msg->sip.callId.s);
			LDEBUG("RTCP IP PORT: %s", ipptmp);

			/* one pair = one timer */
			if(find_ipport_key(ipptmp) != NULL) add_timer(ipptmp);			
                        add_ipport(ipptmp, callid);
		}
	}

	return 1;
}

int w_is_rtcp_exists(msg_t *msg)
{
	struct ipport_items *ipport = NULL;

	LDEBUG("IP PORT: %s:%i", msg->rcinfo.src_ip, msg->rcinfo.src_port);

        ipport = find_ipport(msg->rcinfo.src_ip, msg->rcinfo.src_port);
        if(!ipport) {
               ipport = find_ipport( msg->rcinfo.dst_ip, msg->rcinfo.dst_port);
               if(!ipport) return -1;
               msg->rcinfo.direction = 0;
               ipport->modify_ts = (unsigned)time(NULL);
        }	

        LDEBUG("SESSION ID: %s", ipport->sessionid);
        
        ipport->modify_ts = (unsigned)time(NULL);
        msg->rcinfo.correlation_id.s = ipport->sessionid;
        msg->rcinfo.correlation_id.len = strlen(ipport->sessionid);
        msg->var = (void *) ipport;

        return 1;
}


/* ADD IPPPORT  */
void add_ipport(char *key, char *callid) {

        struct ipport_items *ipport;

        ipport = (struct ipport_items*)malloc(sizeof(struct ipport_items));

        snprintf(ipport->name, sizeof(ipport->name), "%s",  key);
        snprintf(ipport->sessionid, sizeof(ipport->sessionid), "%s", callid);

        ipport->modify_ts = (unsigned)time(NULL);

        if (pthread_rwlock_wrlock(&ipport_lock) != 0) {
                fprintf(stderr,"can't acquire write lock");
                exit(-1);
        }

        HASH_ADD_STR(ipports, name, ipport);

        pthread_rwlock_unlock(&ipport_lock);

}

int find_and_update(char *callid, const char *srcip, int srcport, const char *dstip, int dstport) {

        ipport_items_t *ipport;
        int ret = 0;
        char name[300];

        snprintf(name, sizeof(name), "%s:%d",  srcip, srcport);

        if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
                fprintf(stderr,"can't acquire write lock");
                exit(-1);
        }

        HASH_FIND_STR( ipports, name, ipport);

        if(!ipport) {
             snprintf(name, sizeof(name), "%s:%d",  dstip, dstport);
             HASH_FIND_STR( ipports, name, ipport);
        }

        if(ipport) {
                snprintf(callid, sizeof(ipport->sessionid), "%s", ipport->sessionid);
                ipport->modify_ts = (unsigned)time(NULL);
                ret = 1;
        }

        pthread_rwlock_unlock(&ipport_lock);

        return ret;
}


struct ipport_items *find_ipport_key(char *key) {

	struct ipport_items *ipport = NULL;

    if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
             LERR("can't acquire write lock");
             exit(-1);
    }

    HASH_FIND_STR( ipports, key, ipport);

    pthread_rwlock_unlock(&ipport_lock);

    return ipport;
}


struct ipport_items *find_ipport(char *ip, int port) {

        
        char name[400];
        snprintf(name, 400, "%s:%i",  ip, port);
        
        LDEBUG("IP PORT: [%s]", name);
        
        return find_ipport_key(name);
}

int clear_ipport(struct ipport_items *ipport ) {

        if(ipport) {      

                if (pthread_rwlock_wrlock(&ipport_lock) != 0) {
                        LERR("can't acquire write lock");
                        exit(-1);
                }                                                
                
                LDEBUG("DELETING..................");
                LDEBUG("NAME: [%s]", ipport->name);

                HASH_DEL( ipports, ipport);

                /* free */
                free(ipport);
                
                pthread_rwlock_unlock(&ipport_lock);
                
                return 1;
        }
        
        return 0;
}

int delete_ipport(char *ip, int port) {

        struct ipport_items *ipport;

        LDEBUG("delete ipport !");

        ipport = find_ipport(ip, port);

        return clear_ipport(ipport);
}


void clear_ipports() {

        struct ipport_items *s, *tmp;

        if (pthread_rwlock_wrlock(&ipport_lock) != 0) {
                        LERR("can't acquire write lock");
                        exit(-1);
        }                                                

        /* free the hash table contents */
        HASH_ITER(hh, ipports, s, tmp) {
                HASH_DEL(ipports, s);
                free(s);
        }
        
        pthread_rwlock_unlock(&ipport_lock);
}


int check_ipport(char *name)  {

	int ret = 1;
        ipport_items_t *ipport = NULL;


        if(!name) {
                LERR("bad name pointer in check_ipports!\n");
                return 3;
        }

        if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
                fprintf(stderr, "can't acquire write lock");
                exit(-1);
        }

        HASH_FIND_STR( ipports, name, ipport);

        if(ipport) {
        	if(((unsigned) time(NULL) - ipport->modify_ts) >=  expire_hash_value) {

                        HASH_DEL( ipports, ipport);
                        free(ipport);
                        ret = 2;
        	}
        	else {

        	        ret = 0;
        	}
        }

        pthread_rwlock_unlock(&ipport_lock);

        return ret;
}

void print_ipports() {

        struct ipport_items *s, *tmp;
        
        if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
                        LERR("can't acquire write lock");
                        exit(-1);
        }                                                

        HASH_ITER(hh, ipports, s, tmp) {

                LDEBUG("NAME IPPORTS: %s", s->name);
        }
        
        pthread_rwlock_unlock(&ipport_lock);
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

static int load_module(xml_node *config) {

	xml_node *params, *profile=NULL, *settings;
	char *key, *value = NULL;

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

		if(profile_size == 2) {
			break;
		}

		memset(&profile_database[profile_size], 0, sizeof(profile_database_t));

		/* set values */
		profile_database[profile_size].name = strdup(profile->attr[1]);
		profile_database[profile_size].description = strdup(profile->attr[3]);
		profile_database[profile_size].serial = atoi(profile->attr[7]);

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

					/* cache */
					if (!strncmp(key, "timer-timeout", 13) && atoi(value) > 200) timer_timeout = atoi(value);
					else if (!strncmp(key, "rtcp-timeout", 12) && atoi(value) > 600) rtcp_timeout = atoi(value);

				}

				nextparam: params = params->next;
			}
		}

		profile_size++;

		nextprofile: profile = profile->next;
	}

	/* free */
	free_module_xml_config();

	timer_init();

	return 0;
}


static int free_profile(unsigned int idx) {

	if (profile_database[idx].name)	 free(profile_database[idx].name);
	if (profile_database[idx].description)	 free(profile_database[idx].description);

	return 1;
}


static int unload_module(void) {
	unsigned int i = 0;

	LNOTICE("unloaded module %s", module_name);
	timer_loop_stop = 0;

	for (i = 0; i < profile_size; i++) {
		free_profile(i);
	}

	return 0;
}

static uint64_t serial_module(void)
{
	 return module_serial;
}


static int description(char *descr)
{
       LNOTICE("Loaded description");
       descr = module_description;
       return 1;
}

static int statistic(char *buf, size_t len)
{
	int ret = 0;

	ret += snprintf(buf+ret, sizeof(buf) - len, "TEST STATISTICS");

	return 1;
}

                        
