/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2023 (http://www.sipcapture.org)
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


#ifndef _CORE_XLI_H_
#define _CORE_XLI_H_

int readbody = 0;

#define USE_IPV6

#include <captagent/xmlread.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#define API_LIST_CONFIG "/api/config/list"
#define API_READ_CONFIG "/api/config/read"
#define API_READ_BACKUP "/api/backup/read"
#define API_DELETE_BACKUP "/api/backup"

#define API_INTERCEPTION_CREATE "/api/interception"
#define API_INTERCEPTION_UPDATE "/api/interception/"
#define API_INTERCEPTION_GET "/api/interception/"
#define API_INTERCEPTIONS_GET "/api/interceptions"
#define API_INTERCEPTION_DELETE "/api/interception/"

#define API_LIST_BACKUP "/api/backup/list"
#define API_SAVE_CONFIG "/api/config/save"
#define API_BACKUP_CONFIG "/api/config/backup"
#define API_BACKUP_RESTORE "/api/config/restore"
#define API_LIST_MODULES "/api/module/list"
#define API_RELOAD_MODULE "/api/module/reload"
#define API_SHOW_UPTIME "/api/status/uptime"
#define API_SHOW_INFO "/api/status/info"
#define API_AGENT_INFO "/api/agent/info"
#define API_MODULE_STATS "/api/module/stats"
#define API_MODULE_EXEC "/api/module/exec"

typedef struct interface_http_stats {
	uint64_t received_request_total;
	uint64_t received_request_put;
	uint64_t received_request_get;
	uint64_t received_request_delete;
	uint64_t received_request_post;
	uint64_t send_response_total;
	uint64_t send_json_response;
	uint64_t send_erros_total;
} interface_http_stats_t;


#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#define LISTENQ  1024
#define MAX_LINE 1000

extern struct ah ah;
struct mg_context *ctx;
struct mg_connection *client;
char auth_ha1[33];
int max_requests = 20;
#define MAX_OPTIONS 50

profile_interface_t profile_interface;

bind_socket_module_api_t socket_bind_api;
bind_protocol_module_api_t protocol_bind_api;
bind_transport_module_api_t transport_bind_api;
bind_statistic_module_api_t statistic_bind_api;
bind_database_module_api_t database_bind_api;

int api_request_handler(struct mg_connection *conn, void *cbdata);
int send_data_x2 (int socket, void *buf, unsigned int len);
int sigPipe(void);
char* read_file(char *name );
int add_base_info(json_object *jobj, char *status, char *description);
void free_module_xml_config();
int load_module_xml_config();
int reload_config (char *erbuf, int len);
int make_file_backup(char * src_path, char * dst_path, int check);

int proceed_delete_request(struct mg_request_info * request_info, struct mg_connection *conn);
int proceed_post_request(struct mg_request_info * request_info, struct mg_connection *conn);
int proceed_put_request(struct mg_request_info * request_info, struct mg_connection *conn);
int proceed_get_request(struct mg_request_info * request_info, struct mg_connection *conn);
int check_module_xml_config();

/* Ethernet / IP / UDP header IPv4 */
const int udp_payload_offset = 14+20+8;

extern struct stats_object stats_obj;


#endif
