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
#include <captagent/log.h>
#include "localapi.h"
#include "protocol_tcp.h"
#include "parser_tls.h"

pthread_rwlock_t ipport_lock;

unsigned int profile_size   = 0;

xml_node *module_xml_config = NULL;
char *module_name           = "protocol_tcp";
uint64_t module_serial      = 0;
char *module_description    = NULL;

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int reload_config (char *erbuf, int erlen);
static uint64_t serial_module(void);


static cmd_export_t cmds[] = {
  {"proto_tcp_bind_api", (cmd_function) bind_api, 1, 0, 0, 0},
  {"parse_tls",          (cmd_function) w_parse_tls, 0, 0, 0, 0 },
  {"bind_protocol_tcp",  (cmd_function) bind_protocol_tcp, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
  "protocol_tcp",
  cmds,           /* Exported functions */
  load_module,    /* module initialization function */
  unload_module,
  description,
  statistic,
  serial_module
};


int w_parse_tls(msg_t *msg) {

  int json_len;
  char json_tls_buffer[JSON_BUFFER_LEN] = {0};
  Flow_key * flow_key;
  
  msg->mfree = 0;

  // call dissector
  if((json_len = parse_tls((char *) &msg->data, msg->len, json_tls_buffer, JSON_BUFFER_LEN, msg->rc_info->ip_family, msg->rc_info->src_port, msg->rc_info->dst_port, msg->rc_info->ip_proto, flow_key)) > 0) {
    
    msg->data = json_tls_buffer; // JSON buff --> Msg data
    msg->len = json_len;
    msg->mfree = 1;
  }
  else if(json_len == -3) {
    LERR("Error on malloc for handshake\n");
    if(msg->corrdata) 
      {
	free(msg->corrdata);
	msg->corrdata = NULL;
      }
    else if(json_len == -2) {
      LERR("Error on decription packet\n");
      if(msg->corrdata) 
	{
	  free(msg->corrdata);
	  msg->corrdata = NULL;
	}
    }
    else {
      LERR("INVALID TLS/SSL packet\n");
      if(msg->corrdata) 
	{
	  free(msg->corrdata);
	  msg->corrdata = NULL;
	}
    }
    return -1;
  }
  LERR("JSON TLS %s\n", json_tls_buffer);
  
  return 0;
}



/* ### CAPTAGENT FUNCTIONS ### */

int bind_api(database_module_api_t* api)
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
  if(module_xml_config) {
    xml_free(module_xml_config);	     
  }
}

/* modules external API */

static int load_module(xml_node *config) {

  xml_node *params, *profile = NULL, *settings;
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
    profile_protocol[profile_size].name = strdup(profile->attr[1]);
    profile_protocol[profile_size].description = strdup(profile->attr[3]);
    profile_protocol[profile_size].serial = atoi(profile->attr[7]);

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
	  /* set param value for private or public key */
	  if(strncmp(params->attr[1], "private-key-path", 16))
	    profile_protocol[profile_size].pvt_key_path = strdup(profile->attr[1]);
	  else
	    profile_protocol[profile_size].pub_key_pub = strdup(profile->attr[3]);
	}
	
      nextparam: params = params->next;
      }
    }

    profile_size++;

  nextprofile: profile = profile->next;
  }

  /* free */
  free_module_xml_config();

  return 0;
}


static int free_profile(unsigned int idx) {
  
  if (profile_database[idx].name)	 free(profile_database[idx].name);
  if (profile_database[idx].description) free(profile_database[idx].description);
  
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
