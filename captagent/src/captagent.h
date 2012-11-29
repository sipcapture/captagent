#define VERSION "4.1.1"
#define DEFAULT_CONFIG "/usr/local/etc/captagent/captagent.xml"
#define DEFAULT_PIDFILE  "/var/run/captagent.pid"
#define MAX_STATS 3000

/* sender socket */
int sock;
char* pid_file = DEFAULT_PIDFILE;
xml_node *get_module_config( const char *mod_name, xml_node *mytree);
int core_config (xml_node *config);

int nofork = 1;
int debug_level = 1;
char *usefile = NULL;

