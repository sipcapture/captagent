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

#ifndef MODULES_C_
#define MODULES_C_

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/log.h>
#include <captagent/xmlread.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>

struct module *module_list;
char *module_path;

int register_module(char *resource_name, xml_node *config, bool global) {
	const char *error;
	module_exports_t *exp;
	int flag = RTLD_NOW;
	int i = 0, n = 0;
    cmd_export_t* ret;

	LDEBUG("Loading module: [%s]", resource_name);

	static char fn[256];
	int errors = 0, res, hep_error = 0;
	struct module *m = malloc(sizeof(struct module));

	if (!m) {
		LERR("Out of memory modules");
		return -1;
	}

	/* if (global == TRUE) {
		flag = RTLD_NOW | RTLD_GLOBAL;
		LDEBUG("[%s] registerd as 'global'", resource_name);
	}
	*/

	strncpy(m->name, resource_name, sizeof(m->name));
	if (resource_name[0] == '/')
		strncpy(fn, resource_name, sizeof(fn));
	else
		snprintf(fn, sizeof(fn), "%s/%s.so", module_path, resource_name);

	/*if (!(m->lib = dlopen(fn, RTLD_NOW  | RTLD_GLOBAL))) { */
	if (!(m->lib = dlopen(fn, flag))) {
		LERR("dlopen error [%s]", dlerror());
		free(m);
		return -1;
	}

	dlerror();

	exp = (struct module_exports*)dlsym(m->lib, "exports");
	if ( (error =(char*)dlerror())!=0 ){
		LERR( "ERROR: load_module: %s\n", error);
			errors++;
    }

	m->load_f = exp->load_f;
	m->unload_f = exp->unload_f;
	m->description_f = exp->description_f;
	m->stats_f = exp->stats_f;
	m->serial_f = exp->serial_f;
	m->path = module_path;
	/*
	if (!(m->load_f = dlsym(m->lib, "load_module"))) {
		LERR("No load_module in module %s", fn);
		errors++;
	} else if (!(m->unload_f = dlsym(m->lib, "unload_module"))) {
		LERR("No unload_module in module %s", fn);
		errors++;
	} else if (!(m->description_f = dlsym(m->lib, "description"))) {
		LERR("No description in module %s", fn);
		errors++;
	} else if (!(m->stats_f = dlsym(m->lib, "statistic"))) {
		LERR("No statistic in module %s", fn);
		errors++;
	}
	*/

	if (errors) {
		LERR("%d error(s) loading module %s, aborted", errors, fn);
		dlclose(m->lib);
		free(m);
		return -1;
	}

	for (; exp->cmds[n].name; n++);

	ret = malloc(sizeof(*ret)*(n+1));
	memset(ret, 0, sizeof(*ret)*(n+1));

	for (i=0; i < n; i++) {
		 ret[i].name = exp->cmds[i].name;
		 ret[i].function = exp->cmds[i].function;
		 ret[i].param_no = exp->cmds[i].param_no;
		 ret[i].flags = exp->cmds[i].flags;
		 ret[i].module_exports = m;
	}

	m->cmds = ret;

	if ((res = m->load_f(config))) {
		LERR("load_module [%s] failed, returning %d", m->name, res);
		free(m);
		return -1;
	}

	m->next = module_list;
	module_list = m;

	return 1;
}

int unregister_module(struct module *m) {

	int res = -1;
	res = m->unload_f();
	if (res) {
		LERR("module unload failed for [%s]", m->name);
		dlclose(m->lib);
	}

	return res;
}


int unregister_modules(void) {
	struct module *m, *ml = NULL;
	int res = -1;
	m = module_list;
	cmd_export_t* ret;
	
	while (m) {

		unregister_module(m);
		module_list = m->next;
		ml = m;
		m = m->next;
		ret = ml->cmds;
		free(ret);
		free(ml);
	}

	return res;
}


int register_modules(xml_node *tree) {
	/* SOCKETS */

	xml_node *next, *modules, *config, *sockets;
	bool global = FALSE;
	int i = 0;

		next = tree;


		while (next) {

			next = xml_get("configuration", next, 1);

			if (next == NULL)	break;

			for (i = 0; next->attr[i]; i++) {
				if (!strncmp(next->attr[i], "name", 4)) {

					if (!strncmp(next->attr[i + 1], "modules.conf", 13)) {
						modules = next;
						while (modules) {
							/* modules by default dont' share own functions */
							global = FALSE;
							modules = xml_get("load", modules, 1);

							if (modules == NULL) break;

							if (modules->attr[0] != NULL && modules->attr[1] != NULL) {
								/* get config */

								/*if (!(config = get_module_config(modules->attr[1], tree))) {
									LERR("Config for [%s] has been not found",
											modules->attr[1]);
								}

								if (modules->attr[2] != NULL && !strncmp(modules->attr[2], "register", 8)) {
									if (modules->attr[3] != NULL && !strncmp(modules->attr[3], "global",	6))
										global = TRUE;
								}
								*/

								if (!register_module(modules->attr[1], config, global)) {
									LERR("Module [%s] couldnot be registered", modules->attr[1]);
								}
							}

							modules = modules->next;
						}
					}
				}
			}
			next = next->next;
		}

		return 0;

}





#endif /* MODULES_C_ */

