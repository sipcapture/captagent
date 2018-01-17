/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) QXIP BV 2012-2017 (http://qxip.net)
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

#include "config.h"

#include <captagent/globals.h>
#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>
#include <captagent/md5.h>
#include "localapi.h"
#include "protocol_tcp.h"

/* #include <openssl/md5.h> */

#ifdef USE_SSL
#include "parser_tls.h"
#include "decryption.h"
#include "define.h"
#endif

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

#define KEY_PATH  400

/* ### CAPTAGENT FUNCTIONS ### */

int bind_api(protocol_module_api_t* api)
{
  api->reload_f = reload_config;
  api->module_name = module_name;

  return 0;
}

/**
   Function to read FILE and return string
**/
static unsigned char * read_file(char *name) {
  FILE *file = NULL;
  unsigned long fileLen = 0;
  unsigned char *buffer = NULL;

  char path[1000];

  if(getcwd(path, 1000) == NULL)
    LERR("GETCWD ERROR -> wrong path resolution");

  strcat(path, "/");
  strcat(path, name);
  
  // Open file
  file = fopen(name, "rb");
  if (!file) {
    LERR("Unable to open file %s", name);
    return NULL;
  }
  
  // Get file length
  fseek(file, 0, SEEK_END);
  fileLen = ftell(file);
  fseek(file, 0, SEEK_SET);
  
  // Allocate memory
  buffer = calloc((fileLen + 1), sizeof(unsigned char));
  if(buffer == NULL) {
    LERR("Memory error!");
    fclose(file);
    return NULL;
  }
  
  // Read file contents into buffer
  fread(buffer, fileLen, 1, file);
  fclose(file);
  
  return buffer;
}


int w_parse_tls(msg_t *msg) {

  /* int json_len; */
  /* char json_tls_buffer[JSON_BUFFER_LEN] = {0}; */
  
  /* LERR("MESSAGE LEN [%d]\n", msg->len); */

  /* MD5 of KEY */
  /* char key[33]; */
  /* unsigned char hash[16]; */
  /* MD5_CTX ctx; */
  /* MD5_Init(&ctx); */
  /* MD5_Update(&ctx, (const char *) PVTkey, strlen((const char *) PVTkey)); */
  /* MD5_Final(hash, &ctx); */
  /* int i = 0; */
  /* for (i = 0; i < 16; i++) sprintf(&key[i*2], "%02X", (unsigned int)hash[i]);                        */
  /* LERR("MESSAGE MD5 KEY [%s]\n", key); */
  
  
#ifdef USE_SSL

  int ret_len = 0, index = 0;
  char decrypted_buffer[DECR_LEN] = {0};
  struct Flow * flow = NULL;
  int Key_Hash = 0;
  char pvtkey_path[KEY_PATH];   // PVT KEY path buff
  unsigned char *PVTkey = NULL; // PVT KEY path
  
  
  msg->mfree = 0;

  /**
     # FLOW #
     define the Flow (allocate memory)
  */
  flow = malloc(sizeof(struct Flow));
  memset(flow, 0, sizeof(struct Flow));

  flow->src_port = msg->rcinfo.src_port;     // src port
  flow->dst_port = msg->rcinfo.dst_port;     // dst port
  flow->proto_id_l3 = msg->rcinfo.ip_proto;  // l3 proto
  
  /**
     # KEY #
     prepare the key (port_src + port_dst + proto_id_l3)
     TODO: CHECK IF IP IS BETTER THAN PORT
  */
  if(msg->rcinfo.ip_family == AF_INET)
    Key_Hash = (int) (msg->rcinfo.src_port + msg->rcinfo.dst_port + msg->rcinfo.ip_proto);

  LDEBUG("KEY in proto_tcp = %d", Key_Hash);

  /** PREPARE THE KEY **/
  while(profile_protocol[index].pvt_key_path == NULL) // search the profile protocol TLS
    index++;

  int klen = strlen(profile_protocol[index].pvt_key_path);
  
  // copy the key path to buffer key_path_buff
  memcpy(pvtkey_path, profile_protocol[index].pvt_key_path, klen);
  pvtkey_path[klen] = '\0';
  
  // call READ_FILE to get the string from key
  PVTkey = read_file(pvtkey_path);
  if(PVTkey == NULL) {
    fprintf(stderr, "invalid private key\n");
    free(flow);
    return -5;
  }

  // call dissector
  if((ret_len = dissector_tls((const u_char *) msg->data, msg->len, decrypted_buffer, DECR_LEN, msg->rcinfo.src_port, msg->rcinfo.dst_port, msg->rcinfo.ip_proto, flow, Key_Hash, PVTkey)) > 0) {

    LDEBUG("DECRIPTED BUFFER TLS = %s", decrypted_buffer);
    memcpy(msg->data, decrypted_buffer, ret_len); // decrypted buff --> Msg data
    msg->len = ret_len;
    msg->mfree = 1;
  }
  else if(ret_len == -3) {
    LERR("Error on malloc for handshake");
    if(msg->corrdata) 
      {
	free(msg->corrdata);
	free(PVTkey);
	free(flow);
	msg->corrdata = NULL;
      }
    return -3;
  }
  else if(ret_len == -2) {
    LERR("Error on decription packet");
    if(msg->corrdata) 
      {
	free(msg->corrdata);
	free(PVTkey);
	free(flow);
	msg->corrdata = NULL;
      }
    return -2;
  }
  else if(ret_len == -1) {
    LERR("INVALID TLS/SSL packet");
    if(msg->corrdata) 
      {
	free(msg->corrdata);
	free(PVTkey);
	free(flow);
	msg->corrdata = NULL;
      }
    return -1;
  }
  
  free(PVTkey);
  free(flow);
    
#else
  LERR("TLS has been not enabled. Please reconfigure captagent with param --enable-ssl and --enable-tls");
#endif

  LDEBUG("TLS packet found");

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
  int r;

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

    memset(&profile_protocol[profile_size], 0, sizeof(profile_database_t));

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

	  if (params->attr[2] && params->attr[3] && !strncmp(params->attr[2], "value", 5)) {
	    value = params->attr[3];
	  } else {
	    value = params->child->value;
	  }

	  key = params->attr[1];
	  value = params->attr[3];

	  if (key == NULL || value == NULL) {
	    LERR("bad values in the config");
	    goto nextparam;
	  }

	  int len = strlen(params->attr[3]);
	  
	  /**
	     Set param value for private or public key 
	  **/
	  r = strncmp(key, "private-key-path", 16);
	  if(r == 0) {
	    /* profile_protocol[profile_size].pvt_key_path = strdup(value); */
	    profile_protocol[profile_size].pvt_key_path = calloc((len + 1), sizeof(char));
	    strncpy(profile_protocol[profile_size].pvt_key_path, params->attr[3], len);
	  }
	  else profile_protocol[profile_size].pvt_key_path = NULL;
	}
	
      nextparam: params = params->next;
      }
    }

    profile_size++;

  nextprofile: profile = profile->next;
  }
  //timer_init();

  /* free */
  free_module_xml_config();

  return 0;
}


static int free_profile(unsigned int idx) {
  
  if (profile_protocol[idx].name)	 free(profile_protocol[idx].name);
  if (profile_protocol[idx].description) free(profile_protocol[idx].description);
  
  return 1;
}


static int unload_module(void) {
  unsigned int i = 0;

  LNOTICE("unloaded module %s", module_name);

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
