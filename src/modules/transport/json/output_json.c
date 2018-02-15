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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#endif

#include "config.h"

#ifdef  HAVE_JSON_C_JSON_H  
#include <json-c/json.h>
#elif HAVE_JSON_JSON_H     
#include <json/json.h>
#elif HAVE_JSON_H  
#include <json.h>
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "output_json.h"
#include <captagent/log.h>

xml_node *module_xml_config = NULL;
char *module_name = "output_json";
uint64_t module_serial = 0;
char *module_description = NULL;
uint8_t link_offset = 14;

static output_json_stats_t stats;

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int free_profile(unsigned int idx);
static uint64_t serial_module(void);

bind_statistic_module_api_t stats_bind_api;
unsigned int sslInit = 0;
unsigned int profile_size = 0;

static cmd_export_t cmds[] = {
        {"output_json_bind_api", (cmd_function) bind_usrloc,   1, 0, 0, 0},
        {"send_json",  (cmd_function) w_send_json_api,   1, 0, 0, 0},
        {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
        "output_json",
        cmds,           /* Exported functions */
        load_module,    /* module initialization function */
        unload_module,
        description,
        statistic,
        serial_module
};

int bind_usrloc(transport_module_api_t *api)
{
		api->send_f = send_json;
		api->reload_f = reload_config;
		api->module_name = module_name;

        return 0;
}

int w_send_json_api(msg_t *_m, char *param1)
{
    
    int ret = -1;

    _m->profile_name = param1;
    
    LERR("SEND_JSON_API: [%s]\n", param1);    
    
    ret =  send_json(_m);

    return ret;
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

profile_transport_t *get_profile_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return &profile_transport[0];

	for (i = 0; i < profile_size; i++) {

		if(!strncmp(profile_transport[i].name, name, strlen(profile_transport[i].name))) {
			return &profile_transport[1];
		}
	}

	return NULL;
}

unsigned int get_profile_index_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return 0;

	for (i = 0; i < profile_size; i++) {
		if(!strncmp(profile_transport[i].name, name, strlen(profile_transport[i].name))) {
			return i;
		}
	}
	return 0;
}

#ifdef USE_SSL

void showCerts(SSL *ssl) {

        X509 *cert;
        char *line;

        cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
        if ( cert != NULL ) {
                LDEBUG("Server certificates:");
                line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
                LDEBUG("Subject: %s", line);
                free(line);       /* free the malloc'ed string */
                line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
                LDEBUG("Issuer: %s", line);
                free(line);       /* free the malloc'ed string */
                X509_free(cert);     /* free the malloc'ed certificate copy */
        }
        else
                LERR("No certificates.");
}

int initSSL(unsigned int idx) {

        long ctx_options;
	
        if(init_jsonsocket_blocking(idx)) {
	  LERR("capture: couldn't init hep socket");
	  return 1;
        }

        profile_transport[idx].ctx = initCTX();

        /* workaround bug openssl */
        ctx_options = SSL_OP_ALL;
        ctx_options |= SSL_OP_NO_SSLv2;
        SSL_CTX_set_options(profile_transport[idx].ctx, ctx_options);

        /* extra */
        SSL_CTX_ctrl(profile_transport[idx].ctx, BIO_C_SET_NBIO, 1, NULL);

        /* create new SSL connection state */
        profile_transport[idx].ssl = SSL_new(profile_transport[idx].ctx);

        SSL_set_connect_state(profile_transport[idx].ssl);

        /* attach socket */
        SSL_set_fd(profile_transport[idx].ssl, profile_transport[idx].socket);    /* attach the socket descriptor */

        /* perform the connection */
        if ( SSL_connect(profile_transport[idx].ssl) == -1 )  {
              ERR_print_errors_fp(stderr);
              return 1;
        }

        showCerts(profile_transport[idx].ssl);

        return 0;
}

#endif /* endif SSL */

int send_json(msg_t *msg) {

        rc_info_t *rcinfo = NULL;
        unsigned int idx = 0;
    	json_object *jobj_reply = NULL;
    	sip_msg_t *sipPacket = NULL;
    	const char *message = NULL;
        static int errors = 0;
        char tmpser[100];

        jobj_reply = json_object_new_object();

        idx = get_profile_index_by_name(msg->profile_name);
        rcinfo = &msg->rcinfo;

        if(msg->parsed_data && rcinfo->proto_type == 1) sipPacket = (sip_msg_t *) msg->parsed_data;

        stats.received_packets_total++;

        /* workaround for old json */
        snprintf(tmpser, 100, "%" PRId64, (int64_t) stats.received_packets_total);

	json_object_object_add(jobj_reply, "packet_id", json_object_new_string(tmpser));
        json_object_object_add(jobj_reply, "my_time", json_object_new_int(time(0)));
	json_object_object_add(jobj_reply, "ip_family", json_object_new_int(rcinfo->ip_family));
	json_object_object_add(jobj_reply, "ip_proto", json_object_new_int(rcinfo->ip_proto));

	if(rcinfo->ip_family == AF_INET) {
	     json_object_object_add(jobj_reply, "src_ip4", json_object_new_string(rcinfo->src_ip));
	     json_object_object_add(jobj_reply, "dst_ip4", json_object_new_string(rcinfo->dst_ip));
	}
	else {
	     json_object_object_add(jobj_reply, "src_ip6", json_object_new_string(rcinfo->src_ip));
	     json_object_object_add(jobj_reply, "dst_ip6", json_object_new_string(rcinfo->dst_ip));
	}

	json_object_object_add(jobj_reply, "src_port", json_object_new_int(rcinfo->src_port));
	json_object_object_add(jobj_reply, "dst_port", json_object_new_int(rcinfo->dst_port));

	json_object_object_add(jobj_reply, "tss", json_object_new_int(rcinfo->time_sec));
	json_object_object_add(jobj_reply, "tsu", json_object_new_int(rcinfo->time_usec));

	/* payload */
	if(profile_transport[idx].flag == 1) json_object_object_add(jobj_reply, "payload", json_object_new_string(msg->data));

	if(rcinfo->correlation_id.s && rcinfo->correlation_id.len > 0) {
	     json_object_object_add(jobj_reply, "corr_id", json_object_new_string_len(rcinfo->correlation_id.s, rcinfo->correlation_id.len));
        }

	json_object_object_add(jobj_reply, "proto_type", json_object_new_int(rcinfo->proto_type));
	json_object_object_add(jobj_reply, "capt_id", json_object_new_int(profile_transport[idx].capt_id));


	if(sipPacket != NULL) {

			if(sipPacket->callId.s && sipPacket->callId.len > 0)
				json_object_object_add(jobj_reply, "sip_callid", json_object_new_string_len(sipPacket->callId.s, sipPacket->callId.len));

			if(sipPacket->isRequest && sipPacket->methodString.s && sipPacket->methodString.len > 0)
				json_object_object_add(jobj_reply, "sip_method", json_object_new_string_len(sipPacket->methodString.s, sipPacket->methodString.len));
			else if(sipPacket->responseCode > 0)
				json_object_object_add(jobj_reply, "sip_response", json_object_new_int(sipPacket->responseCode));


			if(sipPacket->cSeqMethodString.s && sipPacket->cSeqMethodString.len > 0)
				json_object_object_add(jobj_reply, "sip_cseq", json_object_new_string_len(sipPacket->cSeqMethodString.s, sipPacket->cSeqMethodString.len));

			if(sipPacket->cSeqMethodString.s && sipPacket->cSeqMethodString.len > 0)
				json_object_object_add(jobj_reply, "sip_cseq", json_object_new_string_len(sipPacket->cSeqMethodString.s, sipPacket->cSeqMethodString.len));

			if(sipPacket->fromURI.s && sipPacket->fromURI.len > 0)
				json_object_object_add(jobj_reply, "sip_from_uri", json_object_new_string_len(sipPacket->fromURI.s, sipPacket->fromURI.len));

			if(sipPacket->toURI.s && sipPacket->toURI.len > 0)
				json_object_object_add(jobj_reply, "sip_to_uri", json_object_new_string_len(sipPacket->toURI.s, sipPacket->toURI.len));

			if(sipPacket->requestURI.s && sipPacket->requestURI.len > 0)
				json_object_object_add(jobj_reply, "sip_request_uri", json_object_new_string_len(sipPacket->requestURI.s, sipPacket->requestURI.len));

			if(sipPacket->paiUser.s && sipPacket->paiUser.len > 0)
				json_object_object_add(jobj_reply, "sip_pai_user", json_object_new_string_len(sipPacket->paiUser.s, sipPacket->paiUser.len));


			if(sipPacket->hasSdp)
				json_object_object_add(jobj_reply, "sip_sdp", json_object_new_int(1));

	}

	message = json_object_to_json_string(jobj_reply);

	/* make sleep after 100 errors */
	if(errors > 30) { sleep (2); errors = 0; }

	/* send this packet out of our socket */
	if(send_data((void *)message, strlen(message), idx) < 0) {
		     stats.errors_total++;
		     LERR( "JSON server is down...");
   		     if(!profile_transport[idx].usessl) {
      	  	           if(init_jsonsocket_blocking(idx)) {
      		   	         profile_transport[idx].initfails++;
                           }
                           errors=0;
                     }
#ifdef USE_SSL
                     else {
                           if(initSSL(idx)) profile_transport[idx].initfails++;
    		                errors=0;
                     }
#endif /* USE SSL */
        }

	json_object_put(jobj_reply);
	
	if(msg->mfree == 1) free(msg->data);
	if(msg->corrdata) {
	   free(msg->corrdata);
           msg->corrdata = NULL;
        }      
        
        return 1;
}



int send_data(void *buf, unsigned int len, unsigned int idx) {

        /* send this packet out of our socket */
        void * p = buf;

        if(!profile_transport[idx].usessl) {
                size_t sendlen = send(profile_transport[idx].socket, p, len, 0);
                if(sendlen == -1) {
                	if(errno == ECONNRESET) return -2;
                	else if(errno == ECONNRESET) return -3;
                	LERR("JSON send error: [%d]", errno);
                    return -1;
                }
        }
#ifdef USE_SSL
        else {
            if(SSL_write(profile_transport[idx].ssl, buf, len) < 0) {
            	LERR("json: couldn't re-init ssl socket: [%d]", errno);
                return -1;
            }
        }
#endif

        stats.send_packets_total++;

        /* RESET ERRORS COUNTER */
        return 0;
}



int init_jsonsocket (unsigned int idx) {

    struct timeval tv;
    socklen_t lon;
    long arg;
    fd_set myset;
    int valopt, res, ret = 0, s;
    struct addrinfo *ai;
    struct addrinfo hints[1] = {{ 0 }};

    if(profile_transport[idx].socket) close(profile_transport[idx].socket);

    if ((s = getaddrinfo(profile_transport[idx].capt_host, profile_transport[idx].capt_port, hints, &ai)) != 0) {
            LERR("capture: getaddrinfo: %s", gai_strerror(s));
            return 2;
    }

    if((profile_transport[idx].socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
             LERR("Sender socket creation failed: %s", strerror(errno));
             return 1;
    }

    // Set non-blocking
    if((arg = fcntl(profile_transport[idx].socket, F_GETFL, NULL)) < 0) {
        LERR( "Error fcntl(..., F_GETFL) (%s)", strerror(errno));
        close(profile_transport[idx].socket);
        return 1;
    }
    arg |= O_NONBLOCK;
    if( fcntl(profile_transport[idx].socket, F_SETFL, arg) < 0) {
        LERR( "Error fcntl(..., F_SETFL) (%s)", strerror(errno));
        close(profile_transport[idx].socket);
        return 1;
    }

    if((res = connect(profile_transport[idx].socket, ai->ai_addr, (socklen_t)(ai->ai_addrlen))) < 0) {
        if (errno == EINPROGRESS) {
                do {
                   tv.tv_sec = 5;
                   tv.tv_usec = 0;
                   FD_ZERO(&myset);
                   FD_SET(profile_transport[idx].socket, &myset);

                   res = select(profile_transport[idx].socket + 1 , NULL, &myset, NULL, &tv);

                   if (res < 0 && errno != EINTR) {
                      LERR( "Error connecting %d - %s", errno, strerror(errno));
                      close(profile_transport[idx].socket);
                      ret = 1;
                      break;
                   }
                   else if (res > 0) {
                      // Socket selected for write

                      lon = sizeof(int);
                      if (getsockopt(profile_transport[idx].socket, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon) < 0) {
                         close(profile_transport[idx].socket);
                         LERR( "Error in getsockopt() %d - %s", errno, strerror(errno));
                         ret = 2;
                      }
                      // Check the value returned...
                      if (valopt) {
                         close(profile_transport[idx].socket);
                         LERR( "Error in delayed connection() %d - %s", valopt, strerror(valopt));
                         ret = 3;
                      }
                      break;
                   }
                   else {
                      close(profile_transport[idx].socket);
                      LERR( "Timeout in select() - Cancelling!");
                      ret = 4;
                      break;
                   }
                } while (1);
        }
    }

    return ret;
}

int init_jsonsocket_blocking (unsigned int idx) {

    int s, ret = 0;
    struct addrinfo *ai;
    struct addrinfo hints[1] = {{ 0 }};

    stats.reconnect_total++;

    hints->ai_flags = AI_NUMERICSERV;
    hints->ai_family = AF_UNSPEC;

    if(!strncmp(profile_transport[idx].capt_proto, "udp", 3)) {
               hints->ai_socktype = SOCK_DGRAM;
               hints->ai_protocol = IPPROTO_UDP;
    }
    else if(!strncmp(profile_transport[idx].capt_proto, "tcp", 3) || !strncmp(profile_transport[idx].capt_proto, "ssl", 3)) {
               hints->ai_socktype = SOCK_STREAM;
               hints->ai_protocol = IPPROTO_TCP;
    }

    if(profile_transport[idx].socket) close(profile_transport[idx].socket);

    if ((s = getaddrinfo(profile_transport[idx].capt_host, profile_transport[idx].capt_port, hints, &ai)) != 0) {
            LERR( "capture: getaddrinfo: %s", gai_strerror(s));
            return 2;
    }

    if((profile_transport[idx].socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
             LERR("Sender socket creation failed: %s", strerror(errno));
             return 1;
    }

    if ((ret = connect(profile_transport[idx].socket, ai->ai_addr, (socklen_t)(ai->ai_addrlen))) == -1) {

         //select(profile_transport[idx].socket + 1 , NULL, &myset, NULL, &tv);
         if (errno != EINPROGRESS) {
             LERR("Sender socket creation failed: %s", strerror(errno));
             return 1;
          }
    }

    return 0;
}


#ifdef USE_SSL
SSL_CTX* initCTX(void) {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
  SSL_load_error_strings();   /* Bring in and register error messages */
  
  /* we use SSLv3 (possible warning here. Check here (https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=223388#c0) */
  method = SSLv3_client_method();  /* Create new client-method instance */
  
  ctx = SSL_CTX_new(method);   /* Create new context */
  if ( ctx == NULL ) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  return ctx;
}


#endif /* use SSL */


void handlerPipe(int signum)
{

        LERR("SIGPIPE JSON... trying to reconnect...[%d]", signum);
        return;
}


int sigPipe(void)
{

	struct sigaction new_action;

	/* sigation structure */
	new_action.sa_handler = handlerPipe;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	if (sigaction(SIGPIPE, &new_action, NULL) == -1) {
		LERR("Failed to set new Handle");
		return -1;
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

static int load_module(xml_node *config) {
	xml_node *params, *profile, *settings, *condition, *action;
	char *key, *value = NULL;
	unsigned int i = 0;
	char module_api_name[256];

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

		if(!profile->attr[4] || strncmp(profile->attr[4], "enable", 6)) {
			goto nextprofile;
		}

		/* if not equals "true" */
		if(!profile->attr[5] || strncmp(profile->attr[5], "true", 4)) {
			goto nextprofile;
		}

		/* set values */
		profile_transport[profile_size].name = strdup(profile->attr[1]);
		profile_transport[profile_size].description = strdup(profile->attr[3]);
		profile_transport[profile_size].serial = atoi(profile->attr[7]);
		profile_transport[profile_size].statistic_pipe = NULL;
		profile_transport[profile_size].flag = 1;

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

					if(!strncmp(key, "capture-host", 10)) profile_transport[profile_size].capt_host = strdup(value);
					else if(!strncmp(key, "capture-port", 13)) profile_transport[profile_size].capt_port = strdup(value);
					else if(!strncmp(key, "capture-proto", 14)) profile_transport[profile_size].capt_proto = strdup(value);
					else if(!strncmp(key, "capture-password", 17)) profile_transport[profile_size].capt_password = strdup(value);
					else if(!strncmp(key, "capture-id", 11)) profile_transport[profile_size].capt_id = atoi(value);
					else if(!strncmp(key, "payload-compression", 19) && !strncmp(value, "true", 5)) profile_transport[profile_size].compression = 1;
					else if(!strncmp(key, "version", 7)) profile_transport[profile_size].version = atoi(value);
					else if(!strncmp(key, "payload-send", 12) && !strncmp(value, "false", 5)) profile_transport[profile_size].flag = 0;
				}

				nextparam:
					params = params->next;

			}
		}


		/* STATS */

		condition = xml_get("statistic", profile, 1);

		while (condition) {

			condition = xml_get("condition", condition, 1);

			if (condition == NULL)	break;

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
									profile_transport[profile_size].statistic_pipe = strdup(action->attr[i + 1]);
								}
								else if (!strncmp(action->attr[i], "profile", 7)) {
									profile_transport[profile_size].statistic_profile = strdup(action->attr[i + 1]);
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

#ifndef USE_ZLIB
			if(profile_transport[i].compression) {
				printf("The captagent has not compiled with zlib. Please reconfigure with --enable-compression\n");
				LERR("The captagent has not compiled with zlib. Please reconfigure with --enable-compression");
			}
#endif /* USE_ZLIB */

			/*TLS || SSL*/
			if(!strncmp(profile_transport[i].capt_proto, "ssl", 3)) {

#ifdef USE_SSL
				profile_transport[i].usessl = 1;
				/* init SSL library */
				if(sslInit == 0) {
					SSL_library_init();
					sslInit = 1;
				}
#else
				printf("The captagent has not compiled with ssl support. Please reconfigure with --enable-ssl\n");
				LERR("The captagent has not compiled with ssl support. Please reconfigure with --enable-ssl");

#endif /* end USE_SSL */
			}

			if(!profile_transport[i].usessl) {
				if(init_jsonsocket_blocking(i)) {
					LERR("capture: couldn't init socket");
				}
			}

#ifdef USE_SSL
			else {
				if(initSSL(i)) {
					LERR("capture: couldn't init SSL socket");
				}
			}
#endif /* use SSL */

			if(profile_transport[i].statistic_pipe) {
				snprintf(module_api_name, 256, "%s_bind_api", profile_transport[i].statistic_pipe);
				//stats_bind_api = (bind_statistic_module_api_t) find_export(module_api_name, 1, 0);
				//stats_bind_api(&profile_transport[i].stats_api);
			}
	}

	sigPipe();

	return 0;
}

static int unload_module(void)
{
	unsigned int i = 0;

	LNOTICE("unloaded module transport_json");

	for (i = 0; i < profile_size; i++) {

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

	if (profile_transport[idx].name)	 free(profile_transport[idx].name);
	if (profile_transport[idx].description) free(profile_transport[idx].description);
	if (profile_transport[idx].capt_host) free(profile_transport[idx].capt_host);
	if (profile_transport[idx].capt_port) free(profile_transport[idx].capt_port);
	if (profile_transport[idx].capt_proto) free(profile_transport[idx].capt_proto);
	if (profile_transport[idx].capt_password) free(profile_transport[idx].capt_password);
	if (profile_transport[idx].statistic_pipe) free(profile_transport[idx].statistic_pipe);
	if (profile_transport[idx].statistic_profile) free(profile_transport[idx].statistic_profile);

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

	ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.received_packets_total);
	ret += snprintf(buf+ret, len-ret, "Reconnect total: [%" PRId64 "]\r\n", stats.reconnect_total);
	ret += snprintf(buf+ret, len-ret, "Errors total: [%" PRId64 "]\r\n", stats.errors_total);
	ret += snprintf(buf+ret, len-ret, "Compressed total: [%" PRId64 "]\r\n", stats.compressed_total);
	ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets_total);


	return 1;

}
                        
