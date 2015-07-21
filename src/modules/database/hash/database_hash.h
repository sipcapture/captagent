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

#ifndef DATABASE_HASH_H_
#define DATABASE_HASH_H_


#include <captagent/xmlread.h>
#include "uthash.h"
#include "hash_structure.h"

int timer_timeout = 10;
int rtcp_timeout = 3600;


static int global_session_id = 0;

int cin_min = 100;
int cin_max = 800;

#define MAX_DATABASE 10
profile_database_t profile_database[MAX_DATABASE];

#define EXPIRE_RTCP_HASH 80
#define EXPIRE_TIMER_ARRAY 80

int expire_hash_value = EXPIRE_RTCP_HASH;

typedef struct mediaport {
  char ipportid[400];
} mediaport_t;


struct ipport_items *ipports = NULL;

bool hash_mode = FALSE;

int bind_api(database_module_api_t* api);
int w_is_rtcp_exists(msg_t *msg);
int w_check_rtcp_ipport(msg_t *msg);


extern char* global_config_path;

/* IPPORTS */
struct ipport_items *find_ipport(char *ip, int port);
struct ipport_items *find_ipport_key(char *key);
void add_ipport(char *key, char *callid);
int delete_ipport(char *ip, int port);
int clear_ipport(struct ipport_items *ipport);
int find_and_update(char *callid, const char *srcip, int srcport, const char *dstip, int dstport);
void clear_ipports();
void print_ipports();
int check_ipport(char *name);

#endif /* DATABASE_LI_H_ */
