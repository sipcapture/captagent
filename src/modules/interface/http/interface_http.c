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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>

#include "config.h"

#ifdef  HAVE_JSON_C_JSON_H  
#include <json-c/json.h>
#elif HAVE_JSON_JSON_H   
#include <json/json.h>  
#elif HAVE_JSON_H
#include <json.h>  
#endif

#include <captagent/globals.h>
#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>

#include <pcap.h>


/* HEP */
#include "extra_api.h"

#include "../../transport/hep/localapi.h"


xml_node *module_xml_config = NULL;

char *module_name="interface_http";
uint64_t module_serial = 0;

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int free_profile(unsigned int idx);
static uint64_t serial_module(void);

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>
#include "../../../captagent.h"

#include "civetweb.h"
#include <captagent/log.h>
#include "interface_http.h"

pthread_t client_thread;
int client_loop = 1;
pthread_mutex_t lock;

static interface_http_stats_t stats;
unsigned int profile_size = 0;

//osip_message_t *sip;

static cmd_export_t cmds[] = {
//{"protocol_sip_bind_api",  (cmd_function)bind_api,   1, 0, 0, 0},
		{ 0, 0, 0, 0, 0, 0 } };

struct module_exports exports = {
		"interface_http",
		cmds, /* Exported functions */
		load_module, /* module initialization function */
		unload_module,
		description,
		statistic,
        serial_module
};

int bind_api(protocol_module_api_t* api) {

	api->reload_f = reload_config;
	api->module_name = module_name;
	return 0;
}

int reload_config (char *erbuf, int len) {
	//
	//unload_module();
	//load_module(config);
	return 0;
}

int b64encode(const unsigned char *src, int src_len, char *dst) {
	static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i, j, a, b, c;

	for (i = j = 0; i < src_len; i += 3) {
		a = src[i];
		b = i + 1 >= src_len ? 0 : src[i + 1];
		c = i + 2 >= src_len ? 0 : src[i + 2];

		dst[j++] = b64[a >> 2];
		dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
		if (i + 1 < src_len) {
			dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
		}
		if (i + 2 < src_len) {
			dst[j++] = b64[c & 63];
		}
	}
	while (j % 4 != 0) {
		dst[j++] = '=';
	}
	return j;
}

char *read_conn(struct mg_connection *conn, int *size) {
	char buf[100], *data = NULL;
	int len;
	*size = 0;
	while ((len = mg_read(conn, buf, sizeof(buf))) > 0) {
		*size += len;
		if ((data = realloc(data, *size)) != NULL) {
			memcpy(data + *size - len, buf, len);
		}
	}
	return data;
}

void send_reply(struct mg_connection *conn, char *code, char *message, const char *uuid) {

	mg_printf(conn, "HTTP/1.1 %s\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %lu\r\n"
			"X-Response-UUID: %s\r\n"
			"\r\n"
			"%s", code, "text/plain", strlen(message), uuid ? uuid : "0", message);

	stats.send_response_total++;
	if(atoi(code) != 200) stats.send_erros_total++;
}

void send_json_reply(struct mg_connection *conn, char *code, json_object *jobj, const char *uuid, int type) {

	const char *message = json_object_to_json_string(jobj);

	mg_printf(conn, "HTTP/1.1 %s\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %lu\r\n"
			"X-Response-UUID: %s\r\n"
			"X-Type-Event: %s\r\n"
			"\r\n"
			"%s\r\n", code, "application/json", strlen(message)+2, uuid ? uuid : "0", type == 1 ? "push" : "reply", message);

	json_object_put(jobj);

	stats.send_response_total++;
	stats.send_json_response++;
}

char* read_file(char *name) {
	FILE *file;
	unsigned long fileLen;
	char *buffer;
	char bufpath[PATH_MAX + 1];

    if(realpath(name, bufpath)){
	   	if(strncmp(bufpath, global_config_path, strlen(global_config_path))) {
	    		return NULL;
	    }
	}
	else {
	   	return NULL;
	}

	//Open file
	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "Unable to open file %s", name);
		return NULL;
	}

	//Get file length
	fseek(file, 0, SEEK_END);
	fileLen = ftell(file);
	fseek(file, 0, SEEK_SET);

	//Allocate memory
	buffer = (char *) malloc(fileLen + 1);
	if (!buffer) {
		fprintf(stderr, "Memory error!");
		fclose(file);
		return NULL;
	}

	//Read file contents into buffer
	fread(buffer, fileLen, 1, file);
	fclose(file);

	return buffer;

	//Do what ever with buffer
}


int make_file_backup(char *src_path, char *dst_path, int check) {

    int src_fd, dst_fd, n, err;
    FILE *f;
    unsigned char buffer[4096];
	char bufpath[PATH_MAX + 1];

	errno = 0;

	if(realpath(src_path, bufpath) == 0
			|| strncmp(bufpath, global_config_path, strlen(global_config_path))) {
    	return -4;
    }

    errno = 0;
    if((realpath(dst_path, bufpath) == 0 && errno != ENOENT)
    		|| strncmp(bufpath, global_config_path, strlen(global_config_path)) ) {
    	return -4;
    }


    if(check == 1) {
		f = fopen(dst_path,"r");
		/* file exists */
		if(f){
			fclose(f);
			return -3;
		}
    }

    src_fd = open(src_path, O_RDONLY);
    dst_fd = open(dst_path, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);

    while (1) {
        err = read(src_fd, buffer, 4096);
        if (err == -1) {
            LERR("Error reading file [%s]", src_path);
            return -2;
        }
        n = err;

        if (n == 0) break;

        err = write(dst_fd, buffer, n);
        if (err == -1) {
        	LERR("Error writing to file [%s]", dst_path);
            return -2;
        }
    }

    close(src_fd);
    close(dst_fd);

    return 1;
}

static void base64_encode(const unsigned char *src, int src_len, char *dst) {
	static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i, j, a, b, c;

	for (i = j = 0; i < src_len; i += 3) {
		a = src[i];
		b = i + 1 >= src_len ? 0 : src[i + 1];
		c = i + 2 >= src_len ? 0 : src[i + 2];

		dst[j++] = b64[a >> 2];
		dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
		if (i + 1 < src_len) {
			dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
		}
		if (i + 2 < src_len) {
			dst[j++] = b64[c & 63];
		}
	}
	while (j % 4 != 0) {
		dst[j++] = '=';
	}
	dst[j++] = '\0';
}

// This function will be called by mongoose on every new request.
int api_request_handler(struct mg_connection *conn, void *cbdata) {

	const char *requestUuid = NULL;
	struct mg_request_info * request_info = mg_get_request_info(conn);

	requestUuid = mg_get_header(conn, "X-Request-UUID");

	LDEBUG("===========================================================");
	LDEBUG("CAPT_API DEBUG: METHOD: [%s]", request_info->request_method);
	LDEBUG("CAPT_API DEBUG: URI: [%s]", request_info->uri);

	stats.recieved_request_total++;

	if (!strcmp(request_info->request_method, "POST")) {

		stats.recieved_request_post++;
		proceed_post_request(request_info, conn);

	} else if (!strcmp(request_info->request_method, "PUT")) {

		stats.recieved_request_put++;
		proceed_put_request(request_info, conn);

	} else if (!strcmp(request_info->request_method, "DELETE")) {
		stats.recieved_request_delete++;
		proceed_delete_request(request_info, conn);

	} else if (!strcmp(request_info->request_method, "GET")) {

		stats.recieved_request_get++;
		proceed_get_request(request_info, conn);

	} else {

		send_reply(conn, "503 Server Error", "the method was not registered", requestUuid);
		return 1;
	}

	return 1;
}

int proceed_delete_request(struct mg_request_info * request_info, struct mg_connection *conn) {

	json_object *jobj_reply = NULL;
	char *filename = NULL;
	char buf[200];
	char *requestUuid = NULL;
	int ret = 0;

	requestUuid = (char *) mg_get_header(conn, "X-Request-UUID");
	int typeReply = 1;

	if((ret = check_extra_delete(conn, (char*) request_info->uri, &jobj_reply, requestUuid)) != 0) 
	{

	        if(ret == 1) send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
                return 1;
	}
	else if (!strncmp(request_info->uri, API_DELETE_BACKUP, strlen(API_DELETE_BACKUP))) 
	{

			jobj_reply = json_object_new_object();
			add_base_info(jobj_reply, "ok", "all good");

			filename = (char *) request_info->uri + strlen(API_DELETE_BACKUP) + 1;

			snprintf(buf, 200, "%s/%s", backup_dir, filename);

			unlink(buf);

			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);

			return 1;
        }
	else {
		send_reply(conn, "404 Not found", "the api call was not found",requestUuid);
		return 1;
	}
	return 1;
}

int proceed_post_request(struct mg_request_info * request_info, struct mg_connection *conn) {

	int post_data_len = 0, ret = 0;
	char post_data[8000], dst_path[200], src_path[200];
	FILE *file;
	json_object *jobj_reply = NULL, *obj = NULL;
	char *filename = NULL;
	char bufpath[PATH_MAX + 1];
	const char *tmp = NULL, *dmp = NULL, *requestUuid = NULL;
	int typeReply = 1;

	/* get request UUID */
	requestUuid = mg_get_header(conn, "X-Request-UUID");

	if (!strncmp(request_info->uri, API_SAVE_CONFIG, strlen(API_SAVE_CONFIG))) {

			post_data_len = mg_read(conn, post_data, sizeof(post_data));

			if (!post_data_len) {
				send_reply(conn, "503 Server Error", "no post data!", requestUuid);
				return 1;
			}

			filename = (char *) request_info->uri + strlen(API_SAVE_CONFIG) + 1;

			json_object * jobj = json_tokener_parse(post_data);

			jobj_reply = json_object_new_object();

			if (jobj == NULL) {
				LERR("JSON obj is null");
				add_base_info(jobj_reply, "bad", "couldnot parse");
			} else {

                                if(json_object_object_get_ex(jobj, "file", &obj) && obj != NULL) 
                                {
                                        dmp = json_object_get_string(obj);
                                }
                                
                                if(json_object_object_get_ex(jobj, "data", &obj) && obj != NULL) 
                                {
                                        tmp = json_object_get_string(obj);
                                }
                                                                
				if (dmp != NULL && tmp != NULL) {

					xml_node *node = xml_node_str((char *)tmp, strlen(tmp));

					if(node) {

						snprintf(dst_path, 200, "%s%s", global_config_path, dmp);
						if(realpath(dst_path, bufpath) && !strncmp(bufpath, global_config_path, strlen(global_config_path)))
						{
								file = fopen(dst_path, "w");
								ret = fputs(tmp, file);
								if (ret == EOF) {
										add_base_info(jobj_reply, "bad", "destination file is not writable");
								}
								else {
									add_base_info(jobj_reply, "ok", "all good");
								}
								fclose(file);
						}
						else {
							add_base_info(jobj_reply, "bad", "destination file is not in the path");
						}
					}
					else {
						add_base_info(jobj_reply, "bad", "bad xml data");
					}

				} else {
					add_base_info(jobj_reply, "bad", "no destination file provided");
				}

				json_object_put(jobj);
			}

			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);

			return 1;
	}

	else if (!strncmp(request_info->uri, API_BACKUP_RESTORE, strlen(API_BACKUP_RESTORE))) {

			post_data_len = mg_read(conn, post_data, sizeof(post_data));

			if (!post_data_len) {
				send_reply(conn, "503 Server Error", "no post data!", requestUuid);
				return 1;
			}

			filename = (char *) request_info->uri + strlen(API_BACKUP_RESTORE) + 1;

			json_object * jobj = json_tokener_parse(post_data);

			jobj_reply = json_object_new_object();

			if (jobj == NULL) {
				LERR("JSON obj is null. Bad parsing");
				add_base_info(jobj_reply, "bad", "couldnot parse");
			}
			else {

                                if(json_object_object_get_ex(jobj, "backup", &obj) && obj != NULL) 
                                {
                                        tmp = json_object_get_string(obj);
                                }

				if(tmp != NULL){

					snprintf(dst_path, 200, "%s%s", global_config_path, filename);
					snprintf(src_path, 200, "%s/%s", backup_dir, tmp);

					ret = make_file_backup(src_path, dst_path, 0);

					if(ret == -1) {
						add_base_info(jobj_reply, "bad", "source file is not readable");
					}
					else if(ret == -2) {
						add_base_info(jobj_reply, "bad", "destination file is not writable");
					}
					else if(ret == -3) {
						add_base_info(jobj_reply, "bad", "destination file exists");
					}
					else if(ret == -4) {
						add_base_info(jobj_reply, "bad", "bad path");
					}
					else {
						add_base_info(jobj_reply, "ok", "all good");
					}
				}
				else {
					add_base_info(jobj_reply, "bad", "no destination file provided");
				}

				json_object_put(jobj);

			}

			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);

			return 1;

	}
	else if (!strncmp(request_info->uri, API_BACKUP_CONFIG, strlen(API_BACKUP_CONFIG))) {

			post_data_len = mg_read(conn, post_data, sizeof(post_data));

			if (!post_data_len) {
				send_reply(conn, "503 Server Error", "no post data!", requestUuid);
				return 1;
			}

			filename = (char *) request_info->uri + strlen(API_BACKUP_CONFIG) + 1;

			json_object * jobj = json_tokener_parse(post_data);
			jobj_reply = json_object_new_object();

			if (jobj == NULL) {
				LERR("JSON obj is null");
				add_base_info(jobj_reply, "bad", "bad parsing");
			}
			else {

			        if(json_object_object_get_ex(jobj, "backup", &obj) && obj != NULL) 
                                {
                                        dmp = json_object_get_string(obj);
                                }
                                
                                if(json_object_object_get_ex(jobj, "destination", &obj) && obj != NULL) 
                                {
                                        tmp = json_object_get_string(obj);
                                }

				if(tmp != NULL && dmp != NULL)
				{
					snprintf(src_path, 200, "%s/%s", global_config_path, dmp);
					snprintf(dst_path, 200, "%s/%s", backup_dir, tmp);

					ret = make_file_backup(src_path, dst_path, 1);

					if(ret == -1) {
						add_base_info(jobj_reply, "bad", "source file is not readable");
					}
					else if(ret == -2) {
						add_base_info(jobj_reply, "bad", "destination file is not writable");
					}
					else if(ret == -3) {
						add_base_info(jobj_reply, "bad", "destination file exists");
					}
					else if(ret == -4) {
						add_base_info(jobj_reply, "bad", "bad path");
					}
					else {
						add_base_info(jobj_reply, "ok", "all good");
					}
				}
				else {
					add_base_info(jobj_reply, "bad", "no destination file provided");
				}

				json_object_put(jobj);
			}

			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);

			return 1;
			
        }
        else if((ret = check_extra_create(conn, (char *)request_info->uri, &jobj_reply, post_data, requestUuid)) != 0) 
        {
                if(ret == 1) send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
                return 1;
        }                                                  
	else {

		jobj_reply = json_object_new_object();
		add_base_info(jobj_reply, "bad", "API not registered");
		send_json_reply(conn, "404 Not found", jobj_reply, requestUuid, typeReply);
		return 1;
	}
}

int proceed_put_request(struct mg_request_info * request_info, struct mg_connection *conn) {

	json_object *jobj_reply = NULL;
	const char *requestUuid = NULL;
	int typeReply = 1;
        int ret = 0;
        char post_data[8000];
          

	/* get request UUID */
	requestUuid = mg_get_header(conn, "X-Request-UUID");
	
	if((ret = check_extra_update(conn, (char *)request_info->uri, &jobj_reply, post_data, requestUuid)) != 0) 
        {
                if(ret == 1) send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
                return 1;
        }                                                  
        else 
        {
        	jobj_reply = json_object_new_object();
        	add_base_info(jobj_reply, "bad", "API not registered");
        	send_json_reply(conn, "404 Not found", jobj_reply, requestUuid, typeReply);
        }

	return 1;
}

int proceed_get_request(struct mg_request_info * request_info, struct mg_connection *conn) {

	int i = 0, len = 0, found_module = 0;
	json_object *jobj_reply = NULL;
	DIR *dp;
	struct dirent *dir;
	char *config = NULL, *b64_sha = NULL, *filename = NULL;
	char buf[800], tmpser[100];
	struct stat fstat;
	struct module *m = NULL;
	const char *requestUuid = NULL;
	int typeReply = 1, ret = 0;

	/* get request UUID */
	requestUuid = mg_get_header(conn, "X-Request-UUID");

	if (!strncmp(request_info->uri, API_MODULE_STATS, strlen(API_MODULE_STATS))) {

		if (strlen(request_info->uri) > (strlen(API_MODULE_STATS)+4)) {
			filename = (char *) request_info->uri + strlen(API_MODULE_STATS) + 1;
		}

		jobj_reply = json_object_new_object();
		json_object *jarray = json_object_new_array();

		m = module_list;
		while (m) {

			if(filename && strncmp(m->name, filename, strlen(filename))) {
					continue;
			}

			json_object *jobj_module = json_object_new_object();
			json_object_object_add(jobj_module, "name", json_object_new_string(m->name));
			m->stats_f(buf, 800);
			json_object_object_add(jobj_module, "info", json_object_new_string(buf));
			json_object_array_put_idx(jarray, i, jobj_module);
			m = m->next;
			i++;
		}

		json_object_object_add(jobj_reply, "data", jarray);

		if (i == 0)
			add_base_info(jobj_reply, "bad", "not found");
		else
			add_base_info(jobj_reply, "ok", "all good");

		send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
		return 1;
	}
	else if (!strncmp(request_info->uri, API_SHOW_INFO, strlen(API_SHOW_INFO))) {

			jobj_reply = json_object_new_object();
			char hwkey[33];
			add_base_info(jobj_reply, "ok", "all good");
			/*Creating a json array*/
			json_object *jobj_second = json_object_new_object();
			if(global_license) json_object_object_add(jobj_second, "license", json_object_new_string(global_license));
			if(backup_dir) json_object_object_add(jobj_second, "backup", json_object_new_string(backup_dir));
			if(captagent_config) json_object_object_add(jobj_second, "config", json_object_new_string(captagent_config));
			if(ghk(hwkey)) json_object_object_add(jobj_second, "hwkey", json_object_new_string(hwkey));
			json_object_object_add(jobj_second, "uptime", json_object_new_int((time(0) - timestart)));
			json_object_object_add(jobj_second, "serial", json_object_new_int(serial));
			json_object_object_add(jobj_second, "debug", json_object_new_int(debug_level));

			/*Form the json object*/
			json_object_object_add(jobj_reply, "data", jobj_second);
			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
			return 1;

	}
	else if (!strncmp(request_info->uri, API_AGENT_INFO, strlen(API_AGENT_INFO))) {

				jobj_reply = json_object_new_object();
				char hwkey[33];
				add_base_info(jobj_reply, "ok", "all good");
				/*Creating a json array*/
				json_object *jobj_second = json_object_new_object();
				if(global_uuid) json_object_object_add(jobj_second, "uuid", json_object_new_string(global_uuid));
				if(ghk(hwkey)) json_object_object_add(jobj_second, "hwkey", json_object_new_string(hwkey));
				json_object_object_add(jobj_second, "uptime", json_object_new_int((time(0) - timestart)));
				json_object_object_add(jobj_second, "serial", json_object_new_int(serial));
				/*Form the json object*/
				json_object_object_add(jobj_reply, "data", jobj_second);
				send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
				return 1;

	}
	else if (!strncmp(request_info->uri, API_SHOW_UPTIME, strlen(API_SHOW_UPTIME))) {

		jobj_reply = json_object_new_object();
		add_base_info(jobj_reply, "ok", "all good");

		json_object_object_add(jobj_reply, "data", json_object_new_int((time(0) - timestart)));

		send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
		return 1;

	} 	
	else if((ret = check_extra_get(conn, (char *)request_info->uri, &jobj_reply, requestUuid)) != 0) 
        {
                if(ret == 1) send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
                return 1;
        }                                                  
	else if (!strncmp(request_info->uri, API_RELOAD_MODULE, strlen(API_RELOAD_MODULE))) {

			jobj_reply = json_object_new_object();
			add_base_info(jobj_reply, "ok", "all good");

			//char *modulereq = NULL;
			//modulereq = (char *) request_info->uri + strlen(API_RELOAD_MODULE) + 1;

			/* socket module */

			if(found_module ==  0) {
				add_base_info(jobj_reply, "bad", "module not found");
			}

			json_object_object_add(jobj_reply, "data", json_object_new_int((time(0) - timestart)));

			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
			return 1;

	} else if (!strncmp(request_info->uri, API_LIST_MODULES, strlen(API_LIST_MODULES))) {

		jobj_reply = json_object_new_object();
		json_object *jarray = json_object_new_array();
		struct module *m = NULL;
		i = 0;

		m = module_list;
		while (m) {

			snprintf(tmpser, 100, "%" PRId64, (int64_t) m->serial_f());
			json_object *jobj_module = json_object_new_object();
			json_object_object_add(jobj_module, "name", json_object_new_string(m->name));
		        json_object_object_add(jobj_module, "serial", json_object_new_string(tmpser));
			//json_object_object_add(jobj_module, "serial", json_object_new_int64((int64_t) m->serial_f()));
			json_object_array_put_idx(jarray, i, jobj_module);
			m = m->next;
			i++;
		}
		json_object_object_add(jobj_reply, "data", jarray);

		if (i == 0)
			add_base_info(jobj_reply, "bad", "not found");
		else
			add_base_info(jobj_reply, "ok", "all good");

		send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
		return 1;

	} else if (!strncmp(request_info->uri, API_READ_CONFIG, strlen(API_READ_CONFIG))) {

		if (strlen(request_info->uri) > strlen(API_READ_CONFIG)) {
			snprintf(buf, 800, "%s%s", global_config_path, request_info->uri + strlen(API_READ_CONFIG));
		} else {
			snprintf(buf, 800, "%s%s", global_config_path, "captagent.xml");
		}

		config = read_file(buf);

		/* reply */
		jobj_reply = json_object_new_object();

		if (config) {
			len = strlen(config);
			b64_sha = (char *) malloc(strlen(config) * 2);
			base64_encode((unsigned char *) config, len, b64_sha);
			add_base_info(jobj_reply, "ok", "all good");
			json_object_object_add(jobj_reply, "data", json_object_new_string(b64_sha));
			send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
		} else {
			add_base_info(jobj_reply, "bad", "the file not found");
		}

		if (b64_sha)
			free(b64_sha);
		if (config)
			free(config);
		return 1;
	} else if (!strncmp(request_info->uri, API_READ_BACKUP, strlen(API_READ_BACKUP))) {

			snprintf(buf, 800, "%s/%s", backup_dir, request_info->uri + strlen(API_READ_CONFIG));

			config = read_file(buf);

			/* reply */
			jobj_reply = json_object_new_object();

			if (config) {
				len = strlen(config);
				b64_sha = (char *) malloc(strlen(config) * 2);
				base64_encode((unsigned char *) config, len, b64_sha);
				add_base_info(jobj_reply, "ok", "all good");
				json_object_object_add(jobj_reply, "data", json_object_new_string(b64_sha));
				send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
			} else {
				add_base_info(jobj_reply, "bad", "the file not found");
			}

			if (b64_sha)
				free(b64_sha);
			if (config)
				free(config);
			return 1;
	} else if (!strncmp(request_info->uri, API_LIST_BACKUP, strlen(API_LIST_BACKUP))) {

		json_object *jarray = json_object_new_array();
		jobj_reply = json_object_new_object();

		if (strlen(request_info->uri) > (strlen(API_LIST_BACKUP)+4)) {
			filename = (char *) request_info->uri + strlen(API_LIST_BACKUP) + 1;
		}

		dp = opendir(backup_dir);
		if (dp != NULL) {

			while ((dir = readdir(dp)) != NULL) {
				/* not display . */
				if(dir->d_name[0] == '.') continue;

				if(filename && strncmp(dir->d_name, filename, strlen(filename))) {
						continue;
				}

				json_object *jobj_dir = json_object_new_object();
				snprintf(buf, 800, "%s/%s", backup_dir, dir->d_name);
				if(!stat(buf, &fstat)) {

					snprintf(tmpser, 100, "%" PRId64, (int64_t) fstat.st_mtim.tv_sec);
					json_object_object_add(jobj_dir, "name", json_object_new_string(dir->d_name));
					json_object_object_add(jobj_dir, "mtime", json_object_new_string(tmpser));
					//json_object_object_add(jobj_dir, "mtime", json_object_new_int64((int64_t) fstat.st_mtim.tv_sec));
					json_object_object_add(jobj_dir, "size", json_object_new_int(fstat.st_size));
					json_object_array_put_idx(jarray, i, jobj_dir);
					i++;
				}
			}
			(void) closedir(dp);

			json_object_object_add(jobj_reply, "data", jarray);

			add_base_info(jobj_reply, "ok", "all good");
		} else {
			add_base_info(jobj_reply, "bad", "the directory is not readable");
		}

		send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
		return 1;

	} else if (!strncmp(request_info->uri, API_LIST_CONFIG, strlen(API_LIST_CONFIG))) {

		if (strlen(request_info->uri) > (strlen(API_LIST_CONFIG)+4)) {
			filename = (char *) request_info->uri + strlen(API_LIST_CONFIG) + 1;
		}

		jobj_reply = json_object_new_object();
		json_object *jarray = json_object_new_array();
		struct stat fstat;

		dp = opendir(global_config_path);

		if (dp != NULL) {

			while ((dir = readdir(dp)) != NULL) {


				if(dir->d_name[0] == '.') continue;

				if(filename && strncmp(dir->d_name, filename, strlen(filename))) {
							continue;
				}

				if (!strncmp(dir->d_name + strlen(dir->d_name) - 4, ".xml", 4)) {

					json_object *jobj_dir = json_object_new_object();

					snprintf(buf, 800, "%s/%s", global_config_path, dir->d_name);


					if(!stat(buf, &fstat)) {

						snprintf(tmpser, 100, "%" PRId64, (int64_t) fstat.st_mtim.tv_sec);
						json_object_object_add(jobj_dir, "name", json_object_new_string(dir->d_name));
                        json_object_object_add(jobj_dir, "mtime", json_object_new_string(tmpser));
						//json_object_object_add(jobj_dir, "mtime", json_object_new_int64((int64_t) fstat.st_mtim.tv_sec));
						json_object_object_add(jobj_dir, "size", json_object_new_int(fstat.st_size));
						json_object_array_put_idx(jarray, i, jobj_dir);
						i++;
					}
				}
			}

			closedir(dp);

			/*Form the json object*/
			json_object_object_add(jobj_reply, "data", jarray);
		}

		if (i == 0)
			add_base_info(jobj_reply, "bad", "not found");
		else
			add_base_info(jobj_reply, "ok", "all good");

		send_json_reply(conn, "200 OK", jobj_reply, requestUuid, typeReply);
		return 1;
	} else {

		jobj_reply = json_object_new_object();
		add_base_info(jobj_reply, "bad", "API not registered");
		send_json_reply(conn, "404 Not found", jobj_reply, requestUuid, typeReply);

		return 1;
	}
	return 1;
}

int add_base_info(json_object *jobj, char *status, char *description) {

	json_object_object_add(jobj, "server", json_object_new_string("127.0.0.1"));
	json_object_object_add(jobj, "cid", json_object_new_int(120));
	json_object_object_add(jobj, "status", json_object_new_string(status));
	json_object_object_add(jobj, "description", json_object_new_string(description));

	return 1;
}


static int set_option(char **options, const char *name, const char *value) {
	int i, type;
	const struct mg_option *default_options = mg_get_valid_options();

	type = CONFIG_TYPE_UNKNOWN;
	for (i = 0; default_options[i].name != NULL; i++) {
		if (!strcmp(default_options[i].name, name)) {
			type = default_options[i].type;
		}
	}
	switch (type) {
	case CONFIG_TYPE_UNKNOWN:
		/* unknown option */
		return 0;
	case CONFIG_TYPE_NUMBER:
		/* integer number > 0, e.g. number of threads */
		if (atol(value) < 1) {
			/* invalid number */
			return 0;
		}
		break;
	case CONFIG_TYPE_STRING:
		/* any text */
		break;
	case CONFIG_TYPE_BOOLEAN:
		/* boolean value, yes or no */
		if ((0 != strcmp(value, "yes")) && (0 != strcmp(value, "no"))) {
			/* invalid boolean */
			return 0;
		}
		break;
	case CONFIG_TYPE_FILE:
	case CONFIG_TYPE_DIRECTORY:
		/* TODO: check this option when it is set, instead of calling verify_existence later */
		break;
	case CONFIG_TYPE_EXT_PATTERN:
		/* list of file extentions */
		break;
	default:
		LERR("Unknown option type - option %s", name);
		break;
	}

	for (i = 0; i < MAX_OPTIONS; i++) {
		if (options[2 * i] == NULL) {
			options[2 * i] = strdup(name);
			options[2 * i + 1] = strdup(value);
			options[2 * i + 2] = NULL;
			break;
		} else if (!strcmp(options[2 * i], name)) {
			free(options[2 * i + 1]);
			options[2 * i + 1] = strdup(value);
			break;
		}
	}

	if (i == MAX_OPTIONS) {
		LERR("Too many options specified");
	}

	if (options[2 * i] == NULL || options[2 * i + 1] == NULL) {
		LERR("Out of memory");
	}

	/* option set correctly */
	return 1;
}

void* client_connection ( void *arg ) {

	char ebuf[100];

	while(client_loop) {
		LDEBUG("connecting to master server...");
		if ((client = mg_connect_server(profile_interface.remote_host, atoi(profile_interface.remote_port),
									profile_interface.remote_ssl, ebuf, sizeof(ebuf))) == NULL) {
				LERR("Cannot make connection to master server... sleeping for %d seconds", profile_interface.remote_timeout);
				sleep(profile_interface.remote_timeout);
		}
		else {
			mg_set_request_handler_client(client, "/api", api_request_handler, 0);
			/* now starting new connection listening */
			mg_process_new_connection(client);
		}
   }

	return NULL;
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
	}

	return 1;
}


int check_module_xml_config() {

	char module_config_name[500];
	xml_node *next;

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, module_name);

	if ((next = xml_parse(module_config_name)) == NULL) {
		return 0;
	}

	xml_free(next);
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
	struct mg_callbacks callbacks;
	char *options[2 * MAX_OPTIONS + 1];
	struct module *m = NULL;
	int socket_count = 0, protocol_count = 0, transport_count = 0, statistic_count = 0, database_count = 0;

	LNOTICE("Loaded interface_http");

	load_module_xml_config();


	/* READ CONFIG */
	profile = module_xml_config;

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
		profile_interface.name = strdup(profile->attr[1]);
		profile_interface.description = strdup(profile->attr[3]);
		profile_interface.serial = atoi(profile->attr[7]);
		profile_interface.database_pipe = NULL;
		profile_interface.statistic_pipe = NULL;
		profile_interface.server_type = 1;
		profile_interface.remote_ssl = 0;
		profile_interface.remote_timeout = 10;

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
						profile_interface.server_host = strdup(value);
					else if (!strncmp(key, "remote-host", 11))
						profile_interface.remote_host = strdup(value);
					else if (!strncmp(key, "remote-port", 11))
						profile_interface.remote_port = strdup(value);
					else if (!strncmp(key, "remote-timeout", 14))
						profile_interface.remote_timeout = atoi(value);
					else if (!strncmp(key, "remote-ssl", 10) && !strncmp(value, "true", 5))
						profile_interface.remote_ssl = 1;
					else if (!strncmp(key, "type-client", 11) && !strncmp(value, "true", 5))
						profile_interface.server_type = 2;
					else if (!strncmp(key, "port", 4))
						profile_interface.server_port = strdup(value);
					else if (!strncmp(key, "realm", 5))
						profile_interface.server_realm = strdup(value);
					else if (!strncmp(key, "auth-file", 9))
						profile_interface.server_auth_file = strdup(value);
					else if (!strncmp(key, "worker", 6))
						profile_interface.server_worker = strdup(value);
					else if (!strncmp(key, "directory", 9))
						profile_interface.server_directory = strdup(value);
					else if (!strncmp(key, "index", 5))
						profile_interface.server_index = strdup(value);
					else if (!strncmp(key, "auth", 4) && !strncmp(value, "true", 5))
						profile_interface.server_auth = 1;

				}

				nextparam: params = params->next;

			}
		}

		/* TRANSPORT */

		condition = xml_get("database", profile, 1);

		while (condition) {

			condition = xml_get("condition", condition, 1);

			if (condition == NULL)
				break;

			if (condition->attr[0] != NULL && condition->attr[2] != NULL) {

				/* bad parser */
				if (strncmp(condition->attr[0], "field", 5) || strncmp(condition->attr[2], "expression", 10)) {
					LERR("bad keys in the config");
					goto nexttransport;
				}

				key = condition->attr[1];
				value = condition->attr[3];

				if (key == NULL || value == NULL) {
					LERR("bad values in the config");
					goto nexttransport;
				}

				action = condition->child;
				if (action && !strncmp(action->key, "action", 6)) {
					for (i = 0; action->attr[i]; i++) {
						if (!strncmp(action->attr[i], "application", 4)) {
							profile_interface.database_pipe = strdup(action->attr[i + 1]);
						} else if (!strncmp(action->attr[i], "profile", 7)) {
							profile_interface.database_profile = strdup(action->attr[i + 1]);
						}
					}
				}
			}

			nexttransport: condition = condition->next;
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
							profile_interface.statistic_pipe = strdup(action->attr[i + 1]);
						} else if (!strncmp(action->attr[i], "profile", 7)) {
							profile_interface.statistic_profile = strdup(action->attr[i + 1]);
						}
					}
				}
			}

			nextstatistic: condition = condition->next;
		}

		profile_size++;

		/* we should have only one interface profile */
		break;

		nextprofile: profile = profile->next;
	}

	options[0] = NULL;

	for (i = 0; i < profile_size; i++) {

		snprintf(module_api_name, 256, "%s_bind_api", profile_interface.database_pipe);
		//database_bind_api = (bind_database_module_api_t) find_export(module_api_name, 1, 0);
		//database_bind_api(&profile_interface.database_api);

		if (profile_interface.server_directory)
			set_option(options, "document_root", profile_interface.server_directory);
		if (profile_interface.server_port)
			set_option(options, "listening_ports", profile_interface.server_port);
		if (profile_interface.server_worker)
			set_option(options, "num_threads", profile_interface.server_worker);
		if (profile_interface.server_auth_file && profile_interface.server_auth) {
			set_option(options, "global_auth_file", profile_interface.server_auth_file);
		}

		if (profile_interface.server_realm)
			set_option(options, "authentication_domain", profile_interface.server_realm);

		//set_option(options, "protect_uri", "/=/usr/local/test/");
		set_option(options, "enable_keep_alive", "yes");

		LDEBUG("starting webserver on port: [%s]", profile_interface.server_port);
		/* start API port*/

		/* memset */
		memset(&callbacks, 0, sizeof(callbacks));

		//callbacks.begin_request = begin_request_handler;
		ctx = mg_start(&callbacks, NULL, (const char **) options);
		for (i = 0; options[i] != NULL; i++) {
			free(options[i]);
		}

		if (ctx == NULL) {
			LERR("Cannot start webserver");
		}

		mg_set_request_handler(ctx, "/api", api_request_handler, 0);

	    if(profile_interface.server_type == 2) {
	    	  // start thread
	    	 pthread_create(&client_thread, NULL, client_connection, 0);
	    }

		LDEBUG("start webserver as client");

		break;
	}

	socket_count = 0;
	protocol_count = 0;
	transport_count = 0;
	statistic_count = 0;
	database_count = 0;

	m = module_list;
	while (m) {

		snprintf(module_api_name, 256, "%s_bind_api", m->name);

		if (!strncmp(m->name, "socket", 6) && socket_count < MAX_API) {
			socket_bind_api = (bind_socket_module_api_t) find_export(module_api_name, 1, 0);
			//socket_bind_api(&profile_interface.socket_api[socket_count]);
			socket_count++;
		} else if (!strncmp(m->name, "protocol", 8) && protocol_count < MAX_API) {
			protocol_bind_api = (bind_protocol_module_api_t) find_export(module_api_name, 1, 0);
			//protocol_bind_api(&profile_interface.proto_api[protocol_count]);
			protocol_count++;
		} else if (!strncmp(m->name, "transport", 6) && transport_count < MAX_API) {
			transport_bind_api = (bind_transport_module_api_t) find_export(module_api_name, 1, 0);
			//transport_bind_api(&profile_interface.transport_api[transport_count]);
			transport_count++;
		} else if (!strncmp(m->name, "socket", 6) && statistic_count < MAX_API) {
			statistic_bind_api = (bind_statistic_module_api_t) find_export(module_api_name, 1, 0);
			//statistic_bind_api(&profile_interface.stats_api[statistic_count]);
			statistic_count++;
		} else if (!strncmp(m->name, "database", 8) && database_count < MAX_API) {
			database_bind_api = (bind_database_module_api_t) find_export(module_api_name, 1, 0);
			//database_bind_api(&profile_interface.database_api[database_count]);
			database_count++;
		}

		//module_list = m->next;
		m = m->next;
	}

	return 0;
}

static int free_profile(unsigned int idx) {

	/*free profile chars **/

	if (profile_interface.name)	 free(profile_interface.name);
	if (profile_interface.description) free(profile_interface.description);
	if (profile_interface.server_host) free(profile_interface.server_host);
	if (profile_interface.server_port) free(profile_interface.server_port);
	if (profile_interface.server_realm) free(profile_interface.server_realm);
	if (profile_interface.server_auth_file) free(profile_interface.server_auth_file);
	if (profile_interface.server_worker) free(profile_interface.server_worker);
	if (profile_interface.server_directory) free(profile_interface.server_directory);
	if (profile_interface.server_index) free(profile_interface.server_index);
	if (profile_interface.database_pipe) free(profile_interface.database_pipe);
	if (profile_interface.database_profile) free(profile_interface.database_profile);
	if (profile_interface.statistic_pipe) free(profile_interface.statistic_pipe);
	if (profile_interface.statistic_profile) free(profile_interface.statistic_profile);
	if (profile_interface.remote_host) free(profile_interface.remote_host);
	if (profile_interface.remote_port) free(profile_interface.remote_port);

	return 1;
}

static int unload_module(void) {

	LNOTICE("unloaded module interface_http");

	unsigned int i = 0;

	for (i = 0; i < profile_size; i++) {

		if(profile_interface.server_type == 2) {
	    	  // start thread
			client_loop = 0;
			if(client)	{
				mg_close_connection(client);
				client = NULL;
			}
			pthread_join(client_thread,NULL);
	    }

		free_profile(i);
	}

	return 0;
}

static uint64_t serial_module(void)
{
	 return module_serial;
}


static int description(char *descr) {
	LNOTICE("Loaded description");
	char *description = "test description";
	descr = description;
	return 1;
}

static int statistic(char *buf, size_t len) {

	int ret = 0;
	ret += snprintf(buf+ret, len-ret, "Total requests: [%" PRId64 "]\r\n", stats.recieved_request_total);
	ret += snprintf(buf+ret, len-ret, "GET requests: [%" PRId64 "]\r\n", stats.recieved_request_get);
	ret += snprintf(buf+ret, len-ret, "POST requests: [%" PRId64 "]\r\n", stats.recieved_request_post);
	ret += snprintf(buf+ret, len-ret, "DELETE requests: [%" PRId64 "]\r\n", stats.recieved_request_delete);
	ret += snprintf(buf+ret, len-ret, "Total response: [%" PRId64 "]\r\n", stats.send_response_total);
	ret += snprintf(buf+ret, len-ret, "JSON response: [%" PRId64 "]\r\n", stats.send_json_response);
	ret += snprintf(buf+ret, len-ret, "Error response: [%" PRId64 "]\r\n", stats.send_erros_total);

	return 1;
}
