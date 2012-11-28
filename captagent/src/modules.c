
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>             
#include <string.h>

#include "api.h"       
#include "xmlread.h"
#include "modules.h"

int register_module(char *resource_name, xml_node *config)
{
        const char *error;

	//printf("MODULE LOAD: %s\n", resource_name);
	
	static char fn[256];
        int errors=0, res, hep_error=0;
        struct module *m = malloc(sizeof(struct module));

        if (!m) {
                fprintf(stderr, "Out of memory\n");
                return -1;
        }
        strncpy(m->resource, resource_name, sizeof(m->resource));
        if (resource_name[0] == '/') strncpy(fn, resource_name, sizeof(fn));
        else snprintf(fn, sizeof(fn), "%s/%s.so", module_path, resource_name);

        if (!(m->lib = dlopen(fn, RTLD_NOW  | RTLD_GLOBAL))) {
                fprintf(stderr, "%s\n", dlerror());
                free(m);
                return -1;
        }
        
        dlerror();

        if (!(m->load_module = dlsym(m->lib, "load_module"))) {
                fprintf(stderr, "No load_module in module %s\n", fn);
                errors++;
        }        
        else if (!(m->unload_module = dlsym(m->lib, "unload_module"))) {
                fprintf(stderr, "No unload_module in module %s\n", fn);
                errors++;
        }
        else if (!(m->description = dlsym(m->lib, "description"))) {
                fprintf(stderr, "No description in module %s\n", fn);
                errors++;
        }        
        else if (!(m->statistic = dlsym(m->lib, "statistic"))) {
                fprintf(stderr, "No statistic in module %s\n", fn);
                errors++;
        }                
                
        if (errors) {
                fprintf(stderr, "%d error(s) loading module %s, aborted\n", errors, fn);
                dlclose(m->lib);
                free(m);
                return -1;
        }
                
        /* HEP module. Check our function */
        if(!strncmp("core_hep", resource_name, 8)) {        
                if(!(hepmod->send_hep_basic = dlsym(m->lib, "send_hep_basic"))) {
                       fprintf(stderr, "No HEP basic found");                                                
                       hep_error++;
                }                
        }                
                

        if ((res = m->load_module(config))) {
                fprintf(stderr, "%s: load_module failed, returning %d\n", m->resource, res);
                free(m);
                return -1;
        }

	m->next = module_list;
        module_list = m;	
	
	return 1;
}

int unregister_modules(void)
{
        struct module *m, *ml = NULL;
        int res = -1;
        m = module_list;
        while(m) {

		res = m->unload_module();                        
		if (res) fprintf(stderr, "Firm unload failed for %s\n", m->resource);

                dlclose(m->lib);

		module_list = m->next;

		ml = m;
	        m = m->next;
		free(ml);
        }

        return res;
}

