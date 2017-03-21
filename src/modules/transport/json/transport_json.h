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


#ifndef _transport_json_H_
#define _transport_json_H_

#include <captagent/xmlread.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */


#ifdef USE_ZLIB
#include <zlib.h>
#endif /* USE_ZLIB */

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>

#endif /* USE_SSL */

#define MAX_TRANPORTS 10
profile_transport_t profile_transport[MAX_TRANPORTS];

typedef struct transport_json_stats {
	uint64_t received_packets_total;
	uint64_t send_packets_total;
	uint64_t reconnect_total;
	uint64_t compressed_total;
	uint64_t errors_total;
} transport_json_stats_t;


#ifdef USE_SSL
SSL_CTX* initCTX(void);
#endif /* USE_SSL */

//struct addrinfo *ai;
//struct addrinfo hints[1] = {{ 0 }};

extern char *global_config_path;

int send_data (void *buf, unsigned int len, unsigned int idx);
int init_jsonsocket_blocking (unsigned int idx);
int init_jsonsocket (unsigned int idx);
int sigPipe(void);
profile_transport_t* get_profile_by_name(char *name);
unsigned int get_profile_index_by_name(char *name);
int bind_usrloc(transport_module_api_t *api);
int send_json(msg_t *msg);
void free_module_xml_config();
int load_module_xml_config();
int reload_config (char *erbuf, int erlen);
int check_module_xml_config();
int w_send_json_api(msg_t *_m, char *param1);



#endif /* _transport_json_H_ */
