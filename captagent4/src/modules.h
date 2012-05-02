
typedef struct module {
        int (*load_module)(struct xml_node *config);
        int (*unload_module)(void);
        char *(*description)(void);
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

char *module_path;
