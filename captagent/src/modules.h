/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
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

typedef struct module {
        int (*load_module)(struct xml_node *config);
        int (*unload_module)(void);
        char *(*description)(void);
        char *(*statistic)(void);
        void *lib;
        char resource[256];
        struct module *next;
} module_t;

struct rc_info;

typedef struct hep_module {
        int (*send_hep_basic)(struct rc_info *rcinfo, unsigned char *data, unsigned int len);
        int (*send_hep_advance)(void);
} hep_module_t;

#define MODULE_DIR "/usr/local/lib/captagent/modules"

int register_module(char *module, xml_node *config);
int unregister_modules(void);


int load_module(void);                  /* Initialize the module */
int unload_module(void);                /* Cleanup all module structures, sockets, etc */
int usecount(void);                     /* How many channels provided by this module are in use? */
char *description(void);                /* Description of this module */
char *statistic(void);                  /* Statistic of this module */

char *module_path;
