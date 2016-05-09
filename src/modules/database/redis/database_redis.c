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
#include <stdint.h>
#include <inttypes.h>
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

#include "../../../config.h"

#ifdef USE_REDIS
#include "hiredis/hiredis.h"
#endif

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "database_redis.h"
#include <captagent/log.h>

xml_node *module_xml_config = NULL;
char *module_name="database_redis";
uint64_t module_serial = 0;
char *module_description = NULL;

static database_redis_stats_t stats;

#ifdef USE_REDIS
redisContext *redisCon[MAX_DATABASE];
#endif

uint8_t link_offset = 14;
static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int free_profile(unsigned int idx);
static uint64_t serial_module(void);


bind_transport_module_api_t transport_bind_api;

unsigned int profile_size = 0;

//osip_message_t *sip;

static cmd_export_t cmds[] = {
        {"database_redis_bind_api",  (cmd_function)bind_redis_api,   1, 0, 0, 0},
        {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
		"database_redis",
        cmds,        /* Exported functions */
        load_module,    /* module initialization function */
        unload_module,
        description,
        statistic,
        serial_module
};

int bind_redis_api(database_module_api_t* api)
{
		api->insert = insert_redis;
		api->delete = delete_redis;
		api->update = insert_redis;
		api->select = select_redis;
		api->count = count_redis;
		api->raw_query =  raw_query_redis;
		api->reload_f = reload_config;
		api->module_name = module_name;

        return 0;
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

profile_database_t* get_profile_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return &profile_database[0];

	for (i = 0; i < profile_size; i++) {

		if(!strncmp(profile_database[i].name, name, strlen(profile_database[i].name))) {
			return &profile_database[1];
		}
	}

	return NULL;
}

unsigned int get_profile_index_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return 0;

	for (i = 0; i < profile_size; i++) {
		if(!strncmp(profile_database[i].name, name, strlen(profile_database[i].name))) {
			return i;
		}
	}
	return 0;
}

/* REDIS CACHE */
int make_cache_reconnect(unsigned int idx) {

#ifdef USE_REDIS

	redisReply *reply;

	struct timeval timeout = { 1, 500000 };

	stats.reconnect_total++;

	if (redisCon[idx]) redisFree(redisCon[idx]);

	redisCon[idx] = redisConnectWithTimeout(profile_database[idx].host, atoi(profile_database[idx].port), timeout);

	if (redisCon[idx] == NULL || redisCon[idx]->err) {
		if (redisCon[idx]) {
			LERR("Redis connection error: %s", redisCon[idx]->errstr);
			redisFree(redisCon[idx]);
			redisCon[idx] = NULL;
			return 0;
		} else {
			LERR("Redis connection error: can't allocate redis context");
			redisCon[idx] = NULL;
			return 0;
		}
	}

	if(profile_database[idx].password != NULL && strlen(profile_database[idx].password) > 0 ) {
		reply= redisCommand(redisCon[idx], "AUTH %s", profile_database[idx].password);
		if (reply && reply->type == REDIS_REPLY_ERROR) {
			/* Authentication failed */
			LERR("Redis AUTH error");
		}
		freeReplyObject(reply);
	}

	reply= redisCommand(redisCon[idx], "PING", profile_database[idx].password);
	if (reply && reply->type == REDIS_REPLY_ERROR) {
				LERR("Redis ping error");
	}
	freeReplyObject(reply);


	if (atoi(profile_database[idx].db_name)) {
		reply = redisCommand(redisCon[idx], "SELECT %d", atoi(profile_database[idx].db_name));
		freeReplyObject(reply);
	}

#endif

	return 1;
}

void close_cache_connection(unsigned int idx) {

#ifdef USE_REDIS

        if(redisCon[idx]) redisFree(redisCon[idx]);
        redisCon[idx] = NULL;
#endif        
        
        return;        
}

#ifdef USE_REDIS

redisReply *redis_command(unsigned int idx, char *query)
{

	redisReply *reply = NULL;

	if (redisCon[idx] == NULL || !(reply = redisCommand(redisCon[idx], query))) {

		if(make_cache_reconnect(idx)) {
			reply = redisCommand(redisCon[idx], query);
		}
	}

	stats.write_packets_total++;

	return reply;
}
#endif

/* redis cache push  */
int insert_redis(const db_msg_t *msg, const db_value_t* _v, const int _n) {

	int i = 0;

#ifdef USE_REDIS

	/* send to parse module */
	char query[MAX_QUERY_SIZE];
	unsigned int idx = 0, ret = 0;

	/* stats */
	stats.recieved_packets_total++;

	idx = get_profile_index_by_name(msg->profile_name.s);

	redisReply *reply;


	if (msg->batch == 0) {
		ret = snprintf(query, MAX_QUERY_SIZE, "SET");
	} else {

		ret = snprintf(query, MAX_QUERY_SIZE, "HMSET %.*s", msg->key_name.len, msg->key_name.s);
	}

	for (i = 0; i < _n; i++) {

		if (_v[i].type == DB_STRING) {
			ret += snprintf(query + ret, MAX_QUERY_SIZE - ret, " %.*s \"%.*s\"", _v[i].key.len, _v[i].key.s,
					_v[i].val.str_val.len,
					_v[i].val.str_val.s);

			/* set expire */
			if (msg->batch == 0 && msg->expire > 0)
				ret += snprintf(query + ret, MAX_QUERY_SIZE - ret, " %d", msg->expire);
		}
	}

	if ((reply = redis_command(idx, query))) {

		if (reply->type == REDIS_REPLY_ERROR) {
			i = 0;
			LDEBUG("couldnot add call to cache");
		} else {
			LDEBUG("Call SET [1]: [%s]", reply->str);
			i = 1;
		}

		freeReplyObject(reply);

		if (msg->batch == 1 && msg->expire > 0) {

			/* set auto expire */

			ret = snprintf(query, MAX_QUERY_SIZE, "EXPIRE %.*s %d", msg->key_name.len, msg->key_name.s, msg->expire);

			if ((reply = redis_command(idx, query))) {

				if (reply->type == REDIS_REPLY_ERROR) {
					i = 0;
					LDEBUG("couldnot add call to cache");
				} else {
					LDEBUG("coudlnot set expire for call: [%.*s]", msg->key_name.len, msg->key_name.s);
					i = 1;
				}

				freeReplyObject(reply);
			}
		}
	}

#endif

	return i;
}

/* redis cache push  */
int delete_redis(const db_msg_t *msg, const db_value_t* _v, const int _n) {


        int i = 0;
        
#ifdef USE_REDIS
        unsigned int idx = 0, ret = 0;
	redisReply *reply;	
	/* send to parse module */
	char query[MAX_QUERY_SIZE];


	/* stats */
	stats.recieved_packets_total++;

	idx = get_profile_index_by_name(msg->profile_name.s);

	if (_n == 0) {
		ret = snprintf(query, MAX_QUERY_SIZE, "DEL %.*s ", msg->key_name.len, msg->key_name.s);
	} else {
		ret = snprintf(query, MAX_QUERY_SIZE, "HDEL %.*s ", msg->key_name.len, msg->key_name.s);
		if (_v[i].type == DB_STRING) {
			ret += snprintf(query + ret, MAX_QUERY_SIZE - ret, "%.*s", _v[i].key.len, _v[i].key.s);
		}
	}

	if ((reply = redis_command(idx, query))) {

		if (reply->type == REDIS_REPLY_ERROR) {
			i = 0;
		} else if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 1) {
			i = 1;
		}
		else if (reply->type == REDIS_REPLY_INTEGER) {
		    i = reply->integer;
		}

		freeReplyObject(reply);

	} else {
		LDEBUG("Bad delete a call from cache: %.*s", msg->key_name.len, msg->key_name.s);
		i = 0;
	}
#endif

	return i;
}


/* redis cache push  */
int select_redis(const db_msg_t *msg, db_value_t* _v, const int _n) {

	unsigned int ret = 0;

#ifdef USE_REDIS
	
	unsigned int idx = 0;
	redisReply *reply;
	/* send to parse module */
	char query[MAX_QUERY_SIZE];
	int i = 0;

	/* stats */
	stats.recieved_packets_total++;

	idx = get_profile_index_by_name(msg->profile_name.s);

	if (_n == 0) {
		ret = snprintf(query, MAX_QUERY_SIZE, "GET %.*s", msg->key_name.len, msg->key_name.s);
		i = 1;
	} else {

		ret = snprintf(query, MAX_QUERY_SIZE, "HMGET %.*s", msg->key_name.len, msg->key_name.s);

		for (i = 0; i < _n; i++) {

			if (_v[i].type == DB_STRING) {
				ret += snprintf(query + ret, MAX_QUERY_SIZE - ret, " %.*s", _v[i].key.len, _v[i].key.s);
			}
		}
	}

	ret = 0;

	if ((reply = redis_command(idx, query))) {

		if (reply != NULL && reply->type == REDIS_REPLY_ARRAY && reply->elements == _n) {

			for (i = 0; i < _n; i++) {

				if (reply->element[i] != NULL && reply->element[i]->type != REDIS_REPLY_NIL) {

					if(reply->element[i]->type == REDIS_REPLY_STRING) {
							if(isCharsDigit(reply->element[i]->str)) {
									_v[i].type = DB_INT;
									_v[i].val.int_val = atoi(reply->element[i]->str);
							}
							else {
									_v[i].type = DB_STR;
									_v[i].val.str_val.len = strlen(reply->element[i]->str);
									_v[i].val.str_val.s = (char*) malloc(_v[i].val.str_val.len + 1);
									memcpy(_v[i].val.str_val.s, reply->element[i]->str, _v[i].val.str_val.len);
							}
					}
					else if(reply->element[i]->type == REDIS_REPLY_INTEGER) {
						_v[i].type = DB_INT;
						_v[i].val.int_val = reply->element[i]->integer;
					}

					ret = i;
				}
			}

			freeReplyObject(reply);
		}
		else if (reply->type == REDIS_REPLY_INTEGER) {
	        _v[0].val.int_val = reply->integer;
			_v[i].type = DB_INT;
			ret = 1;
		}
	}
#endif

	return ret;
}

/* redis cache push  */
int raw_query_redis(char* query, const db_msg_t *msg, db_value_t* _v, const int _n) {



	int i = 0;
#ifdef USE_REDIS

	unsigned int idx = 0;
	redisReply *reply;

	/* stats */
	stats.recieved_packets_total++;

	idx = get_profile_index_by_name(msg->profile_name.s);

	if ((reply = redis_command(idx, query))) {

		/* if _n == 0 we don't want to get this value. */

		if (_n > 0 && reply->type == REDIS_REPLY_ARRAY && reply->elements == _n) {

			if(reply->type == REDIS_REPLY_ARRAY)
			for (i = 0; i < _n; i++) {
				_v[i].type = DB_STR;
				_v[i].val.str_val.len = strlen(reply->element[i]->str);
				_v[i].val.str_val.s = (char*) malloc(_v[i].val.str_val.len + 1);
				memcpy(_v[i].val.str_val.s, reply->element[i]->str, _v[i].val.str_val.len);
			}
			i = _n;
		}
		else if (reply->type == REDIS_REPLY_INTEGER) {
        	_v[i].val.int_val = reply->integer;
        	i = 1;
		}

		if(reply) freeReplyObject(reply);
	}

#endif

	return i;
}

/* count redis */
int count_redis(char* query, const db_msg_t *msg) {

	int i = 0;

#ifdef USE_REDIS

	unsigned int idx = 0;
	redisReply *reply;
	/* send to parse module */


	stats.recieved_packets_total++;

	idx = get_profile_index_by_name(msg->profile_name.s);

	if ((reply = redis_command(idx, query))) {

		if (reply->type == REDIS_REPLY_INTEGER) i =reply->integer;

		if(reply) freeReplyObject(reply);
	}
#endif
	return i;
}

bool isCharsDigit(char *numArray)
{
    int i;
    const int len = strlen(numArray);
    bool ret = TRUE;

    for (i = 0; i < len; i++)
    {
        /* #include <ctype.h> for 'isdigit()'. */
        if (!isdigit(numArray[i])) {
        	ret = FALSE;
        	break;
        }
    }

    return ret;
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
	xml_node *params, *profile, *settings, *condition, *action;
	char *key, *value = NULL;
	unsigned int i = 0;

	LNOTICE("Loaded database_redis");

#ifndef USE_REDIS
	LERR("redis support was not activated. Please recompile with --enable-redis ");
#endif

	load_module_xml_config();
	/* READ CONFIG */
	profile = module_xml_config;

	/* reset profile */
	profile_size = 0;

	while (profile) {

		profile = xml_get("profile", profile, 1);

		if (profile == NULL)
			break;

		if(!profile->attr[4] || strncmp(profile->attr[4], "enable", 6)) {
			goto nextprofile;
		}

		/* if not equals "true" */
		if(!profile->attr[5] || strncmp(profile->attr[5], "true", 4)) {
			goto nextprofile;
		}

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
				if (params == NULL) break;

				if (params->attr[0] != NULL) {

					/* bad parser */
					if (strncmp(params->attr[0], "name", 4)) {
						LERR("bad keys in the config");
						goto nextparam;
					}

					key = params->attr[1];

					if(params->attr[2] && params->attr[3] && !strncmp(params->attr[2], "value", 5)) {
							value = params->attr[3];
					}
					else {
						value = params->child->value;
					}

					if (key == NULL || value == NULL) {
						LERR("bad values in the config");
						goto nextparam;

					}

					if(!strncmp(key, "host", 4)) profile_database[profile_size].host = strdup(value);
					else if(!strncmp(key, "port", 4)) profile_database[profile_size].port = strdup(value);
					else if(!strncmp(key, "password", 8)) profile_database[profile_size].password = strdup(value);
					else if(!strncmp(key, "user", 4)) profile_database[profile_size].user = strdup(value);
					else if(!strncmp(key, "db-num", 6)) profile_database[profile_size].db_name = strdup(value);
				}

				nextparam:
					params = params->next;

			}
		}

		/* STATS */

		condition = xml_get("statistic", profile, 1);

		while (condition) {

			condition = xml_get("condition", condition, 1);

			if (condition == NULL)
				break;

			if (condition->attr[0] != NULL && condition->attr[2] != NULL) {

				/* bad parser */
				if (strncmp(condition->attr[0], "field", 5) || strncmp(condition->attr[2], "expression", 10)) {
					LERR("bad keys in the config");
					goto nextstatistic;
				}

				key = condition->attr[1];
				value = condition->attr[3];

				if (key == NULL || value == NULL) {
					LERR("bad values in the config");
					goto nextstatistic;
				}

				action = condition->child;
				if (action && !strncmp(action->key, "action", 6)) {
					for (i = 0; action->attr[i]; i++) {
						if (!strncmp(action->attr[i], "application", 4)) {
							profile_database[profile_size].statistic_pipe = strdup(action->attr[i + 1]);
						}
						else if (!strncmp(action->attr[i], "profile", 7)) {
							profile_database[profile_size].statistic_profile = strdup(action->attr[i + 1]);
						}
					}
				}
			}

			nextstatistic: condition = condition->next;
		}

		profile_size++;

		nextprofile:
			profile = profile->next;
	}

	/* free it */
	free_module_xml_config();

	for (i = 0; i < profile_size; i++) {
		//snprintf(module_name, 256, "%s_bind_api", profile_database[i].transport_pipe);
		//transport_bind_api = (bind_transport_module_api_t) find_export(module_name, 1, 0);
		//transport_bind_api(&profile_database[i].transport_api);
		make_cache_reconnect(i);
	}

	return 0;
}

static int unload_module(void)
{

	LNOTICE("unloaded module database_redis");

	unsigned int i = 0;

	/* Close socket */

	for (i = 0; i < profile_size; i++) {

		close_cache_connection(i);
		free_profile(i);
	}

    return 0;
}

static uint64_t serial_module(void)
{
	 return module_serial;
}

static int free_profile(unsigned int idx) {

	/*free profile chars **/

	if (profile_database[idx].name)	 free(profile_database[idx].name);
	if (profile_database[idx].description) free(profile_database[idx].description);
	if (profile_database[idx].host) free(profile_database[idx].host);
	if (profile_database[idx].port) free(profile_database[idx].port);
	if (profile_database[idx].user) free(profile_database[idx].user);
	if (profile_database[idx].db_name) free(profile_database[idx].db_name);
	if (profile_database[idx].statistic_pipe) free(profile_database[idx].statistic_pipe);
	if (profile_database[idx].statistic_profile) free(profile_database[idx].statistic_profile);

	return 1;
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

		ret += snprintf(buf+ret, len-ret, "received: [%" PRId64 "]\r\n", stats.recieved_packets_total);
		ret += snprintf(buf+ret, len-ret, "wrote: [%" PRId64 "]\r\n", stats.write_packets_total);
		ret += snprintf(buf+ret, len-ret, "reconnect: [%" PRId64 "]\r\n", stats.reconnect_total);

		return 1;
}
