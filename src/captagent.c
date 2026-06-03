/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) QXIP BV 2012-2023 (http://qxip.net)
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
#include <limits.h>
#include <pcap.h>

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

int cfg_errors = 0;
int debug = 0;
int nofork = 1;
int foreground = 0;
int debug_level = 1;
int is_x = -1;
char *usefile = NULL;
char *set_debug = NULL;
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
int use_current_timestamp = 0;
const char *captagent_config;
struct capture_list main_ct;
struct action *clist[20];

struct stats_object stats_obj;

/* Fallback for lexer builds that still reference yywrap(). */
int yywrap(void)
{
    return 1;
}
static volatile sig_atomic_t terminate_requested = 0;

static int replace_owned_string(char **dst, const char *src, const char *key_name)
{
    char *tmp;

    if (src == NULL)
        return 1;

    tmp = strdup(src);
    if (tmp == NULL) {
        LERR("failed to allocate memory for %s", key_name);
        return 0;
    }

    free(*dst);
    *dst = tmp;
    return 1;
}

static void shutdown_agent(int exit_code)
{
    LDEBUG("The agent has been terminated");

    if (pid_file)
        unlink(pid_file);

    if (!unregister_modules()) {
        LDEBUG("modules unload");
    }

    /* free variables */
    if (module_path)
        free(module_path);
    if (pid_file)
        free(pid_file);
    if (global_license)
        free(global_license);
    if (global_uuid)
        free(global_uuid);
    if (global_chroot)
        free(global_chroot);
    if (global_config_path)
        free(global_config_path);
    if (global_node_name)
        free(global_node_name);
    if (global_capture_plan_path)
        free(global_capture_plan_path);
    if (backup_dir)
        free(backup_dir);

    destroy_log();

    exit(exit_code);
}

void handler(int value)
{
    (void)value;
    terminate_requested = 1;
}

void usage(int8_t e)
{
	printf(
        "usage: Captagent <-vh> <-f config>\n"
        "   -h  display help/usage\n"
        "   -a  print a list of all availlable devices\n"
        "   -v  display version information\n"
        "   -c  validate configuration and exit\n"
        "   -d  enable daemon mode\n"
        "   -n  enable foreground mode\n"
        "   -f  [/path/to/rtpagent.xml] to specify a config file\n"
        "   -D  [/path/to/file.pcap] to specify a pcap file as input\n"
        "   -t  [0] use current timestamp instead of pcap packet timestamp (0 = current time)\n"
        "   -x  [1 - 10] set debug level\n");
	exit(e);
}


// Print the list of availlable devices
static void print_all_devices()
{
    int i = 0;
    pcap_if_t *all_devs, *d = NULL;
    char err_buff[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devs, err_buff) == PCAP_ERROR) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", err_buff);
        exit(-1);
    }

    printf("List of available devices on your system:\n");
    for (d = all_devs; d; d = d->next) {
        if ((strncmp(d->name, "any", 3) != 0) && (strncmp(d->name, "lo", 2) != 0)) {
            printf("device %d = %s", ++i, d->name);
            if (d->description)
                printf("\t\t (%s)\n", d->description);
            else
                printf("\t\t No description available for this device\n");
        }
    }
    pcap_freealldevs(all_devs);
}


int get_basestat(char *module, char *buf, size_t len)
{
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


int daemonize(int nofork)
{
    FILE *pid_stream;
    pid_t pid;
    int p = -1;
    struct sigaction new_action;

    if (!nofork) {

        if ((pid = fork()) < 0) {
            LERR("Cannot fork:%s", strerror(errno));
            goto error;
        } else if (pid != 0) {
            exit(0);
        }
    }

    if (pid_file != 0 && !nofork) {
        if ((pid_stream = fopen(pid_file, "r")) != NULL) {
            if (fscanf(pid_stream, "%d", &p) != 1 || p <= 0) {
                LERR("could not parse pid file %s", pid_file);
                fclose(pid_stream);
                goto error;
            }
            fclose(pid_stream);

            errno = 0;
            if (kill((pid_t) p, 0) == 0 || errno == EPERM) {
                LERR("running process found in the pid file %s", pid_file);
                goto error;
            } else if (errno == ESRCH) {
                LERR("pid file contains old pid, replacing pid");
            } else {
                LERR("unable to verify pid file %s: %s", pid_file, strerror(errno));
                goto error;
            }
        }
        pid = getpid();
        if ((pid_stream = fopen(pid_file, "w")) == NULL) {
            LERR("unable to create pid file %s: %s", pid_file, strerror(errno));
            goto error;
        } else {
            fprintf(pid_stream, "%i\n", (int)pid);
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
 error:return -1;
}


void print_hw() {
    char k[33];
    if ((ghk(k)))
        printf("HW: [%s]\n", k);
    else
        printf("error during key generation");
}


static int validate_module_xml_configs(xml_node *mytree)
{
    xml_node *next, *modules;
    int i = 0;
    int errors = 0;
    char module_config_name[PATH_MAX];
    char erbuf[256];

    if (mytree == NULL) {
        LERR("Configuration tree is empty");
        return 1;
    }

    next = mytree;

    while (next) {
        next = xml_get("configuration", next, 1);

        if (next == NULL)
            break;

        for (i = 0; next->attr[i]; i++) {
            if (!strncmp(next->attr[i], "name", 4)
                && !strncmp(next->attr[i + 1], "modules.conf", 13)) {

                modules = next;
                while (modules) {
                    modules = xml_get("load", modules, 1);

                    if (modules == NULL)
                        break;

                    if (modules->attr[0] != NULL && modules->attr[1] != NULL) {
                        snprintf(module_config_name, sizeof(module_config_name),
                                 "%s/%s.xml", global_config_path, modules->attr[1]);

                        if (!xml_parse_with_report(module_config_name, erbuf, sizeof(erbuf))) {
                            LERR("Configuration check failed for [%s]: %s",
                                 module_config_name, erbuf);
                            errors++;
                        }
                    }

                    modules = modules->next;
                }
            }
        }
        next = next->next;
    }

    return errors;
}


int main(int argc, char *argv[])
{

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

    while ((c = getopt(argc, argv, "adcvhnEKf:D:t:x:")) != EOF) {

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
        case 't':
            if (atoi(optarg) == 0) {
                use_current_timestamp = 1;
            }
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
        case 'x':
            is_x = 1;
            set_debug = optarg;
            break;
        case 'a':
            print_all_devices();
            exit(0);
        default:
            abort();
        }
    }

    set_log_level(5);
    init_log("captagent", 0);

    /* PATH */
    if (!replace_owned_string(&module_path, MODULE_DIR, "module_path")) {
        destroy_log();
        exit(EXIT_FAILURE);
    }

    load_xml_config();

    /*CORE CONFIG */

    if (!(config = get_core_config("core", tree))) {
        LERR("Config for core has been not found");
        free_xml_config();
        destroy_log();
        return EXIT_FAILURE;
    }

    if (!core_config(config)) {
        LERR("Config for core is invalid");
        free_xml_config();
        destroy_log();
        return EXIT_FAILURE;
    }

    if (checkout == 1) {        // read config and validate module XML files
        int module_cfg_errors = validate_module_xml_configs(tree);
        free_xml_config();

        if (module_cfg_errors > 0) {
            LERR("Configuration check failed with %d error(s)", module_cfg_errors);
            return EXIT_FAILURE;
        }

        printf("Configuration check completed successfully\n");
        return EXIT_SUCCESS;
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

    while (!terminate_requested) {
        errno = 0;
        if (select(0, NULL, NULL, NULL, NULL) == -1 && errno == EINTR)
            continue;

        if (errno != 0 && errno != EINTR) {
            LERR("select() failed: %s", strerror(errno));
            break;
        }
    }

    shutdown_agent(EXIT_SUCCESS);
    return EXIT_SUCCESS;
}


int load_xml_config()
{

    if ((tree = xml_parse(captagent_config)) == NULL) {
        LERR("Unable to open configuration file: %s", captagent_config);
        exit(1);
    }

    return 1;
}


void free_xml_config()
{
    /* now we are free */
    if (tree)
        xml_free(tree);
}


xml_node *get_module_config_by_name(char *mod_name)
{
    xml_node *config = NULL;

    load_xml_config();

    if (!(config = get_module_config(mod_name, tree))) {
        LERR("CAP: Config for [%s] has been not found", mod_name);
    }

    return config;
}


xml_node *get_module_config(const char *mod_name, xml_node * mytree)
{
    xml_node *next, *modules = NULL, *config;
    int i = 0;

    if (mytree == NULL)
        return modules;

    next = mytree;

    while (next) {

        next = xml_get("module", next, 1);

        if (next == NULL)
            break;

        for (i = 0; next->attr && next->attr[i]; i++) {

            if (!strcmp(next->attr[i], "name")) {

                if (next->attr[i + 1] && !strcmp(next->attr[i + 1], mod_name)) {
                    modules = next;
                    break;
                }
            }
        }
        next = next->next;
    }
    return modules;
}


xml_node *get_core_config(const char *mod_name, xml_node * mytree)
{
    xml_node *next, *modules = NULL, *config;
    int ret = 0, i = 0;
    char cfg[128];

    if (mytree == NULL)
        return modules;

    ret = snprintf(cfg, sizeof(cfg), "%s.conf", mod_name);
    if (ret < 0 || ret >= (int)sizeof(cfg)) {
        LERR("core config name is too long: %s", mod_name);
        return modules;
    }

    next = mytree;

    while (next) {

        next = xml_get("configuration", next, 1);

        if (next == NULL)
            break;

        for (i = 0; next->attr && next->attr[i]; i++) {
            if (!strcmp(next->attr[i], "name")) {
                if (next->attr[i + 1] && !strcmp(next->attr[i + 1], cfg)) {
                    modules = next;
                    break;
                }
            }
        }
        next = next->next;
    }

    return modules;
}


int core_config(xml_node * config)
{
    char *dev, *usedev = NULL;
    xml_node *modules;
    char *key, *value;
    const char *plan_base_path;
    const char *plan_sep;
    size_t plan_base_len;
    int _use_syslog = 0;
    int mlen = 0;
    char default_plan_path[1024];

    LNOTICE("Loaded core config");

    if (config == NULL) {
        LERR("xml config is null");
    }

    /* READ CONFIG */
    modules = config;

    while (modules) {
        modules = xml_get("param", modules, 1);
        if (modules == NULL)
            break;

        if (modules->attr && modules->attr[0] != NULL && modules->attr[1] != NULL
            && modules->attr[2] != NULL && modules->attr[3] != NULL) {

            /* bad parser */
            if (strncmp(modules->attr[2], "value", 5)
                || strncmp(modules->attr[0], "name", 4)) {
                LERR("bad keys in the config");
                modules = modules->next;
                continue;
            }

            key = modules->attr[1];
            value = modules->attr[3];

            if (key == NULL || value == NULL) {
                LERR("bad values in the config");
                modules = modules->next;
                continue;
            }

            if (!strncmp(key, "debug", 5)) {
                if (is_x == -1)
                    debug_level = atoi(value);
                else
                    debug_level = atoi(set_debug);
            } else if (!strncmp(key, "serial", 6))
                serial = atoi(value);
            else if (!strncmp(key, "daemon", 6) && !strncmp(value, "true", 4)
                     && nofork == 1)
                nofork = 0;
            else if (!strncmp(key, "module_path", 11))
                if (!replace_owned_string(&module_path, value, "module_path"))
                    return 0;
            else if (!strncmp(key, "syslog", 6) && !strncmp(value, "true", 4))
                _use_syslog = 1;
            else if (!strncmp(key, "pid_file", 8)) {
                if (!replace_owned_string(&pid_file, value, "pid_file"))
                    return 0;
            } else if (!strncmp(key, "license", 7))
                if (!replace_owned_string(&global_license, value, "license"))
                    return 0;
            else if (!strncmp(key, "uuid", 4))
                if (!replace_owned_string(&global_uuid, value, "uuid"))
                    return 0;
            else if (!strncmp(key, "chroot", 6))
                if (!replace_owned_string(&global_chroot, value, "chroot"))
                    return 0;
            else if (!strncmp(key, "config_path", 11))
                if (!replace_owned_string(&global_config_path, value, "config_path"))
                    return 0;
            else if (!strncmp(key, "node", 4))
                if (!replace_owned_string(&global_node_name, value, "node"))
                    return 0;
            else if (!strncmp(key, "capture_plans_path", 18))
                if (!replace_owned_string(&global_capture_plan_path, value, "capture_plans_path"))
                    return 0;
            else if (!strncmp(key, "backup", 6))
                if (!replace_owned_string(&backup_dir, value, "backup"))
                    return 0;
        } else {
            LERR("bad values in the config");
        }

        modules = modules->next;
    }

    if (!pid_file)
        if (!replace_owned_string(&pid_file, DEFAULT_PIDFILE, "pid_file"))
            return 0;

    if (!global_node_name) {
        global_node_name = malloc(8);
        if (!global_node_name) {
            LERR("failed to allocate memory for node");
            return 0;
        }
        snprintf(global_node_name, 8, "default");
    }

    if (!global_config_path) {
        if (!replace_owned_string(&global_config_path, AGENT_CONFIG_DIR, "config_path"))
            return 0;
    }

    if (!global_capture_plan_path) {
        plan_base_path = global_config_path ? global_config_path : AGENT_CONFIG_DIR;
        plan_base_len = strlen(plan_base_path);
        plan_sep = (plan_base_len > 0 && plan_base_path[plan_base_len - 1] == '/') ? "" : "/";
        if (snprintf(default_plan_path, sizeof(default_plan_path), "%s%scaptureplans",
                     plan_base_path, plan_sep) >= (int)sizeof(default_plan_path)) {
            LERR("capture plans path is too long");
            return 0;
        }

        if (!replace_owned_string(&global_capture_plan_path, default_plan_path, "capture_plans_path"))
            return 0;
    }

    /* reinit syslog */
    destroy_log();
    set_log_level(debug_level);
    init_log("captagent", _use_syslog);

    return 1;
}
