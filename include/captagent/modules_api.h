/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or
 * modify
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

#ifndef MODULES_API_H_
#define MODULES_API_H_

typedef  struct module_exports* (*module_register)(void);
typedef  int (*cmd_function)(msg_t*, char* param1, char* param2);
typedef int (*fixup_function)(void** param, int param_no);

typedef struct cmd_export_ {
        char* name;             /**< null terminated command name */
        cmd_function function;  /**< pointer to the corresponding function */
        int param_no;           /**< number of parameters used by the function */
        int flags;              /**< Function flags */
        int fixup_flags;
        void* module_exports; /**< pointer to module structure */
} cmd_export_t;



typedef enum {
        STR_PARAM,  /* String parameter type */
        INT_PARAM,  /* Integer parameter type */
} modparam_t;       /* Allowed types of parameters */
                              

/* modules API */

typedef int (*ul_set_keepalive_timeout_t)(int _to);
typedef int (*parse_message_t)(msg_t *msg);
typedef int (*parse_only_message_t)(msg_t *msg, void* packet);
typedef int (*send_message_t)(msg_t *msg);
typedef int (*send_stats_t)(stats_msg_t *stats_msg);
typedef int (*reload_t)(char *erbuf, int len);
typedef int (*apply_filter_t)(filter_msg_t *filter);

typedef int (*update_db_t)(const db_msg_t *msg, const db_value_t* _v, const int _n);
typedef int (*delete_db_t)(const db_msg_t *msg, const db_value_t* _v, const int _n);
typedef int (*insert_db_t)(const db_msg_t *msg, const db_value_t* _v, const int _n);
typedef int (*select_db_t)(const db_msg_t* msg, db_value_t* _v, const int _n);
typedef int (*query_db_t)(char *query, const db_msg_t *msg, db_value_t* _v, const int _n);
typedef int (*count_db_t)(char *query, const db_msg_t *msg);


/* socket module API export structure */

typedef struct socket_module_api {

        int           	use_domain; /*! use_domain module parameter */
        char			*module_name;
        int         	db_mode;    /*! db_mode module parameter */
        unsigned int  	nat_flag;   /*! nat_flag module parameter */
        reload_t        reload_f;
        apply_filter_t  apply_filter_f;
        ul_set_keepalive_timeout_t set_keepalive_timeout;

} socket_module_api_t;

typedef struct protocol_module_api {

        int           use_domain; /*! use_domain module parameter */
        char		  *module_name;
        int           db_mode;    /*! db_mode module parameter */
        unsigned int  nat_flag;   /*! nat_flag module parameter */
        parse_message_t parse_f;
        parse_only_message_t parse_only_f;
        reload_t        reload_f;
        ul_set_keepalive_timeout_t set_keepalive_timeout;

} protocol_module_api_t;

typedef struct transport_module_api {

        int           use_domain; /*! use_domain module parameter */
        char		  *module_name;
        int           db_mode;    /*! db_mode module parameter */
        unsigned int  nat_flag;   /*! nat_flag module parameter */
        send_message_t send_f;
        reload_t        reload_f;
        ul_set_keepalive_timeout_t set_keepalive_timeout;

} transport_module_api_t;

typedef struct statistic_module_api {

        int           use_domain; /*! use_domain module parameter */
        char		  *module_name;
        int           db_mode;    /*! db_mode module parameter */
        unsigned int  nat_flag;   /*! nat_flag module parameter */
        send_stats_t  send_stats_f;
        reload_t        reload_f;
} statistic_module_api_t;

typedef struct database_module_api {
        int           db_mode;    /*! db_mode module parameter */
        char		  *module_name;
        update_db_t   update;
        delete_db_t   delete;
        insert_db_t   insert;
        select_db_t   select;
        count_db_t    count;
        query_db_t    raw_query;
        reload_t        reload_f;
} database_module_api_t;

typedef int (*bind_socket_module_api_t)(socket_module_api_t* api);
typedef int (*bind_command_api_t)(msg_t *_m, char *param1, char *param2);
typedef int (*bind_protocol_module_api_t)(protocol_module_api_t* api);
typedef int (*bind_transport_module_api_t)(transport_module_api_t* api);
typedef int (*bind_statistic_module_api_t)(statistic_module_api_t* api);
typedef int (*bind_database_module_api_t)(database_module_api_t* api);

#define MAX_FILTER_LEN 8000
#define MAX_API 10

/* profile socket */
typedef struct profile_socket {
		char *name;
		char *description;
		char *device;
		char *host;
		char *port;
		uint32_t serial;
		uint8_t reasm;
		uint8_t promisc;
		int socket;
		char *capture_plan;
		char *filter;
		int action;
		int protocol;
		char *capture_filter;
		uint32_t ring_buffer;
		uint32_t snap_len;
		uint32_t link_type;
		uint32_t timeout;
		uint8_t full_packet;
                struct profile_socket *next;
                void *reasm_t;
} profile_socket_t;


/* profile protocol */
typedef struct profile_protocol {
		char *name;
		char *description;
		uint32_t serial;
		uint16_t dialog_timeout;
		uint8_t dialog_type;
		uint8_t rtcp_tracking;
		uint8_t type;
		int action;
		char *ignore;
        struct profile_protocol *next;
} profile_protocol_t;


/* profile transport */
typedef struct profile_transport {
		char *name;
		char *description;
		int socket;
		unsigned int usessl;
#ifdef USE_SSL
		SSL *ssl;
		SSL_CTX *ctx;
#endif /* USE_SSL */
		unsigned int initfails;
		int serial;
		int version;
		char *capt_host;
		char *capt_port;
		char *capt_proto;
		unsigned int capt_id;
		char *capt_password;
		int compression;
		char *statistic_pipe;
		char *statistic_profile;
		int action;
        struct profile_transport *next;
        unsigned int flag;
} profile_transport_t;

/* database profile */
typedef struct profile_database {
		char *name;
		char *description;
		int serial;
		int type;
		char *host;
		char *port;
		char *db_name;
		char *user;
		char *password;
		char *statistic_pipe;
		char *statistic_profile;
        struct profile_database *next;
} profile_database_t;

/* interface profile */
typedef struct profile_interface {
		char *name;
		char *description;
		int serial;
		int type;
		int server_type;
		char *server_host;
		char *server_port;
		char *remote_host;
		char *remote_port;
		int remote_timeout;
		int remote_ssl;
		int server_auth;
		char *server_realm;
		char *server_auth_file;
		char *server_worker;
		char *server_directory;
		char *server_index;
		char *database_pipe;
		char *statistic_pipe;
		char *database_profile;
		char *statistic_profile;
        struct profile_interface *next;
} profile_interface_t;


#endif /* MODULES_API_H_ */
