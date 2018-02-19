/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) QXIP BV 2012-2018 (http://qxip.net)
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/capture.h>
#include <captagent/xmlread.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>

#include "md5.h"
#include <captagent/globals.h>
#include "captagent.h"
#include "config.h"

char *dupArgs[2];
char *server;
xml_node *tree;

int cfg_errors=0;
int debug = 0;
int nofork = 1;
int foreground = 0;
int debug_level = 1;
char *usefile = NULL;
char *global_license = NULL;
char *global_chroot = NULL;
char *global_config_path = NULL;
char *global_node_name = NULL;
char *global_capture_plan_path = NULL;
char *global_uuid = NULL;
char *backup_dir;
char *pid_file = NULL;
int timestart;
int serial;
const char *captagent_config;


struct capture_list main_ct;
struct action* clist[20];

struct stats_object stats_obj;

void handler(int value) {

	int terminating = 1;

	LDEBUG("The agent has been terminated");

	unlink(pid_file);

	if (!unregister_modules()) {
		LDEBUG("modules unload");
	}

	/* free variables */
	if(module_path) free(module_path);
	if(pid_file) free(pid_file);
	if(global_license) free(global_license);
	if(global_uuid) free(global_uuid);
	if(global_chroot) free(global_chroot);
	if(global_config_path) free(global_config_path);
	if(global_node_name) free(global_node_name);
	if(global_capture_plan_path) free(global_capture_plan_path);

	destroy_log();

	exit(0);
}

int get_basestat(char *module, char *buf, size_t len) {

	char *res;
	int pos = 0, ret = 0;
	char stats[200];

	struct module *m = NULL;
	m = module_list;
	while (m) {

		if (!strncmp(module, "all", 3)) {
			if (m->stats_f(stats, sizeof(stats))) {
				pos += snprintf(buf + pos, len - pos, "%s\r\n", stats);
				ret = 1;
			}
		} else {
			if (!strncmp(m->name, module, strlen(module))) {
				if (m->stats_f(stats, sizeof(stats))) {
					ret = snprintf(buf, len, "%s\r\n", stats);
					ret = 1;
					break;
				}
			}
		}

		m = m->next;
	}

	return ret;
}

int daemonize(int nofork) {

	FILE *pid_stream;
	pid_t pid;
	int p;
	struct sigaction new_action;

	if (!nofork) {

		if ((pid = fork()) < 0) {
			LERR("Cannot fork:%s", strerror(errno));
			goto error;
		} else if (pid != 0) {
			exit(0);
		}
	}

	if (pid_file != 0  && !nofork) {
		if ((pid_stream = fopen(pid_file, "r")) != NULL) {
			if (fscanf(pid_stream, "%d", &p) < 0) {
				LERR("could not parse pid file %s", pid_file);
			}
			fclose(pid_stream);
			if (p == -1) {
				LERR(
						"pid file %s exists, but doesn't contain a valid" " pid number",
						pid_file);
				goto error;
			}
			if (kill((pid_t) p, 0) == 0 || errno == EPERM) {
				LERR("running process found in the pid file %s", pid_file);
				goto error;
			} else {
				LERR("pid file contains old pid, replacing pid");
			}
		}
		pid = getpid();
		if ((pid_stream = fopen(pid_file, "w")) == NULL) {
			LERR("unable to create pid file %s: %s", pid_file, strerror(errno));
			goto error;
		} else {
			fprintf(pid_stream, "%i\n", (int) pid);
			fclose(pid_stream);
		}
	}

	/* sigation structure */
	new_action.sa_handler = handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;

	if (sigaction(SIGINT, &new_action, NULL) == -1) {
		LERR("Failed to set new Handle");
		return -1;
	}
	if (sigaction(SIGTERM, &new_action, NULL) == -1) {
		LERR("Failed to set new Handle");
		return -1;
	}

	return 0;
	error: return -1;
}

void usage(int8_t e) {
	printf(
			"usage: captagent <-vh> <-f config>\n"
					"   -h  is help/usage\n"
					"   -v  is version information\n"
					"   -f  is the config file\n"
					"   -D  is use specified pcap file instead of a device from the config\n"
					"   -c  is checkout\n"
					"   -d  is daemon mode\n"
					"   -n  is foreground mode\n"
					"   -K  is hardware key of your system\n"
					"");
	exit(e);
}

void print_hw() {

	char k[33];
	if((ghk(k))) printf("HW: [%s]\n",k);
	else printf("error during key generation");
}

int main(int argc, char *argv[]) {

	xml_node *next, *modules, *config, *sockets;
	const char **attr, **attr_mod;
	int i = 0, y = 0, c, checkout = 0;
	bool global = FALSE;
	int errout = 1;
	char *k;

	/* how much entries */
	main_ct.entries = 0;
	main_ct.idx = -1;

	timestart = time(0);

	captagent_config = DEFAULT_CAPT_CONFIG;
	
	while ((c = getopt(argc, argv, "dcvhnEKf:D:")) != EOF) {

		switch (c) {
		case 'v':
			printf("version: %s\n", VERSION);
			exit(0);
			break;
		case 'f':
			captagent_config = optarg;
			break;
		case 'd':
			nofork = 0;
			break;
		case '?':
		case 'h':
			usage(0);
			break;
		case 'c':
			checkout = 1;
			break;
		case 'D':
			usefile = optarg;
			break;
		case 'E':
			errout = 0;
			break;
		case 'K':
			print_hw();
			exit(0);
			break;
		case 'n':
			foreground = 1;
			break;

		default:
			abort();
		}
	}

	set_log_level(5);
	init_log("captagent", 0);

	/* PATH */
	module_path = MODULE_DIR;

	hepmod = malloc(sizeof(hep_module_t));

	load_xml_config();

	/*CORE CONFIG */

	if (!(config = get_core_config("core", tree))) {
			LERR("Config for core has been not found");
	} else {
		if (!core_config(config)) {
			LERR("Config for core found");
		}
	}

	if (foreground)
		nofork = 1;

	if (daemonize(nofork) != 0) {
		LERR("Daemonize failed: %s", strerror(errno));
		exit(-1);
	}

	/* do register modules */
	register_modules(tree);

	free_xml_config();

	LDEBUG("The Captagent is ready");

	select(0, NULL, NULL, NULL, NULL);

	return EXIT_SUCCESS;
}

int load_xml_config() {

	if ((tree = xml_parse(captagent_config)) == NULL) {
		LERR("Unable to open configuration file: %s", captagent_config);
		exit(1);
	}

	return 1;
}

void free_xml_config() {

	/* now we are free */
	if(tree) xml_free(tree);
}

xml_node *get_module_config_by_name(char *mod_name) {

	xml_node *config = NULL;

	load_xml_config();

	if (!(config = get_module_config(mod_name, tree))) {
		LERR("CAP: Config for [%s] has been not found", mod_name);
	}

	return config;
}

xml_node *get_module_config(const char *mod_name, xml_node *mytree) {

	xml_node *next, *modules = NULL, *config;
	int i = 0;

	if (mytree == NULL) return modules;

	next = mytree;

	while (next) {

		next = xml_get("module", next, 1);

		if (next == NULL) break;

		for (i = 0; next->attr[i]; i++) {

			if (!strncmp(next->attr[i], "name", 4)) {

				if (!strncmp(next->attr[i + 1], mod_name, strlen(mod_name))) {
					modules = next;
					break;
				}
			}
		}
		next = next->next;
	}
	return modules;
}


xml_node *get_core_config(const char *mod_name, xml_node *mytree) {

	xml_node *next, *modules = NULL, *config;
	int ret = 0, i = 0;
	char cfg[128];

	if (mytree == NULL) return modules;

	ret = snprintf(cfg, sizeof(cfg), "%s.conf", mod_name);

	next = mytree;

	while (next) {

		next = xml_get("configuration", next, 1);

		if (next == NULL) break;

		for (i = 0; next->attr[i]; i++) {
			if (!strncmp(next->attr[i], "name", 4)) {
				if (!strncmp(next->attr[i + 1], cfg, ret)) {
					modules = next;
					break;
				}
			}
		}
		next = next->next;
	}

	return modules;
}


int core_config(xml_node *config) {
	char *dev, *usedev = NULL;
	xml_node *modules;
	char *key, *value;
	int _use_syslog = 0;
	int mlen = 0;

	LNOTICE("Loaded core config");

	if (config == NULL) {
		LERR("xml config is null");
	}

	/* READ CONFIG */
	modules = config;

	while (modules) {
		//if (modules == NULL) break;
		modules = xml_get("param", modules, 1);
		if (modules->attr[0] != NULL && modules->attr[2] != NULL) {

			/* bad parser */
			if (strncmp(modules->attr[2], "value", 5)
					|| strncmp(modules->attr[0], "name", 4)) {
				LERR("bad keys in the config");
				goto next;

			}

			key = modules->attr[1];
			value = modules->attr[3];

			if (key == NULL || value == NULL) {
				LERR("bad values in the config");
				goto next;
			}

			if (!strncmp(key, "debug", 5))
				debug_level = atoi(value);
			else if (!strncmp(key, "serial", 6))
						serial = atoi(value);
			else if (!strncmp(key, "daemon", 6) && !strncmp(value, "true", 4)
					&& nofork == 1)
				nofork = 0;
			else if (!strncmp(key, "module_path", 11))
				module_path = strdup(value);
			else if (!strncmp(key, "syslog", 6) && !strncmp(value, "true", 4))
				_use_syslog = 1;
			else if (!strncmp(key, "pid_file", 8)) {
				free(pid_file);
				pid_file = strdup(value);
			} else if (!strncmp(key, "license", 7))
				global_license = strdup(value);
			else if (!strncmp(key, "uuid", 4))
				global_uuid = strdup(value);
			else if (!strncmp(key, "chroot", 6))
				global_chroot = strdup(value);
			else if (!strncmp(key, "config_path", 11))
				global_config_path = strdup(value);
			else if (!strncmp(key, "node", 4))
				global_node_name = strdup(value);				
			else if (!strncmp(key, "capture_plans_path", 18))
				global_capture_plan_path = strdup(value);
			else if (!strncmp(key, "backup", 6))
				backup_dir = strdup(value);
		}
		next:

		modules = modules->next;
	}

	if(!pid_file)
		pid_file = strdup(DEFAULT_PIDFILE);

	if(!global_node_name) {
		global_node_name = malloc(8);
		snprintf(global_node_name, 8, "default");
	}

	if(!global_config_path)	{
		global_config_path = strdup(AGENT_CONFIG_DIR);
	}

	if(!global_capture_plan_path) {	
		global_capture_plan_path = strdup(AGENT_PLAN_DIR);		
	}	

	/* reinit syslog */
	destroy_log();
	set_log_level(debug_level);
	init_log("captagent", _use_syslog);

	return 1;
}
