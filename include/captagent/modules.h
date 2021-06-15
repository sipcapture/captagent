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

#ifndef MODULES_H_
#define MODULES_H_

extern char *module_path;

#define VAR_PARAM_NO  -128

struct rc_info;

typedef struct hep_module {
        int (*send_hep_basic)(struct rc_info *rcinfo, unsigned char *data, unsigned int len);
        int (*send_hep_advance)(void);
} hep_module_t;


typedef int (*init_function)(xml_node *config);
typedef int (*destroy_function)(void);
typedef int (*description_function)(char *descr);
typedef int (*statistic_function)(char *stats, size_t len);
typedef void (*onbreak_function)(msg_t* msg);
typedef uint64_t (*serial_function)(void);

typedef struct module {
        init_function load_f;
	destroy_function unload_f;
	description_function description_f;
	statistic_function stats_f;
	serial_function serial_f;
	onbreak_function onbreak_f;
	cmd_export_t* cmds;
        void *lib;
        char *path;
        char name[256];
        struct module *next;
} module_t;

typedef struct module_exports {
        char* name;
        cmd_export_t* cmds;
        init_function load_f;
    	destroy_function unload_f;
    	description_function description_f;
    	statistic_function stats_f;
	serial_function serial_f;
	onbreak_function onbreak_f;
	
	char** param_names;    /* parameter names registered by this modules */
	char** cmd_names;               /* cmd names registered by this modules */
	int cmd_no;                     /* number of registered commands */
        int par_no;            /* number of registered parameters */
        int* param_no;                  /* number of parameters used*/
        cmd_function* cmd_pointers;     /* pointers to the corresponding functions */
        modparam_t* param_types; /* Type of parameters */
        void** param_pointers; /* Pointers to the corresponding memory locations */
	        
} module_exports_t;


int register_module(char *resource_name, xml_node *config, bool global);
int register_modules(xml_node *tree);
int unregister_modules(void);
int usecount(void);
/* How many channels provided by this module are in use? */
//char *description(void);                /* Description of this module */
//int *statistic(char *stats, size_t len);                  /* Statistic of this module */


#endif /* MODULES_H_ */
