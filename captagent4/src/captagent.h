

#define VERSION "4.0.1a"
#define DEFAULT_CONFIG "/usr/local/etc/captagent/captagent.xml"
#define DEFAULT_PIDFILE  "/var/run/captagent.pid"

/* sender socket */
int sock;
char* pid_file = DEFAULT_PIDFILE;
xml_node *get_module_config( const char *mod_name, xml_node *mytree);
int core_config (xml_node *config);

int nofork = 1;
int debug_level = 1;

