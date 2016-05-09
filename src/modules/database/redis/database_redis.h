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

#ifndef _database_redis_H_
#define _database_redis_H_

#include <captagent/xmlread.h>

#define FILTER_LEN 4080



/* SYNC this list: http://hep.sipcapture.org */
#define PROTO_SIP    0x01
#define PROTO_XMPP   0x02
#define PROTO_SDP    0x03
#define PROTO_RTP    0x04
#define PROTO_RTCP   0x05
#define PROTO_MGCP   0x06
#define PROTO_MEGACO 0x07
#define PROTO_M2UA   0x08
#define PROTO_M3UA   0x09
#define PROTO_IAX    0x0a
#define PROTO_H322   0x0b
#define PROTO_H321   0x0c

typedef struct database_redis_stats {
	uint64_t recieved_packets_total;
	uint64_t reconnect_total;
	uint64_t write_packets_total;
} database_redis_stats_t;

#define MAX_DATABASE 10
#define MAX_QUERY_SIZE 3000
profile_database_t profile_database[MAX_DATABASE];

extern char *global_config_path;

profile_database_t* get_profile_by_name(char *name);
unsigned int get_profile_index_by_name(char *name);
int bind_redis_api(database_module_api_t* api);
int insert_redis(const db_msg_t *msg, const db_value_t* _v, const int _n);
int delete_redis(const db_msg_t *msg, const db_value_t* _v, const int _n);
int update_redis(const db_msg_t *msg, const db_value_t* _v, const int _n);
int select_redis(const db_msg_t *msg, db_value_t* _v, const int _n);
int raw_query_redis(char* query, const db_msg_t *msg, db_value_t* _v, const int _n);
int count_redis(char* query, const db_msg_t *msg);
bool isCharsDigit(char *numArray);
void free_module_xml_config();
int reload_config (char *erbuf, int erlen);

#ifdef USE_REDIS
redisReply *redis_command(unsigned int idx, char *query);
#endif /* if USE REDIS */

int make_cache_reconnect(unsigned int idx);
void close_cache_connection(unsigned int idx);

#endif /* _database_redis_H_ */
