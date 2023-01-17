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

#ifndef CAPTAGENT_H_
#define CAPTAGENT_H_

#include "md5.h"
#include "config.h"
#include <captagent/api.h>

#define CAPTAGENT_VERSION "6.1.0"

#define DEFAULT_CAPT_CONFIG AGENT_CONFIG_DIR "captagent.xml"

#define DEFAULT_PIDFILE  "/var/run/captagent.pid"
#define MAX_STATS 3000

/* sender socket */
int sock;
extern char *pid_file;
xml_node *get_core_config(const char *mod_name, xml_node * mytree);
xml_node *get_module_config(const char *mod_name, xml_node * mytree);
int load_xml_config();
void free_xml_config();
xml_node *get_module_config_by_name(char *mod_name);
int core_config(xml_node * config);
void print_hw();

static inline int ghk(char *_0)
{
    unsigned aO = 0;
    FILE *f;
    char _1[50];
    md5_byte_t h[33];
    md5_state_t c;
    f = fopen("/sys/class/dmi/id/product_uuid", "r");
    if (f == NULL)
        return 0;
    fgets(_1, 37, f);
    fclose(f);
    aO = strlen(_1);
    _1[aO] = '\0';
    md5_init(&c);
    md5_append(&c, (const md5_byte_t *)_1, aO - 1);
    md5_finish(&c, h);
    for (aO = 0; aO < 16; aO++)
        sprintf(_0 + (aO * 2), "%02X", (unsigned int)h[aO]);
    return 1;
}

#endif                          /* CAPTAGENT_H_ */
