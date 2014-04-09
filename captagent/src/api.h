/* API params */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef OS_LINUX
#include <linux/types.h>
#endif /* OS_LINUX */

typedef struct xml_node {
        char *key;
        char *value;
        char **attr;
        struct xml_node *child;
        struct xml_node *parent;
        struct xml_node *next;
} xml_node;


struct rc_info {
    uint8_t     ip_family; /* IP family IPv6 IPv4 */
    uint8_t     ip_proto; /* IP protocol ID : tcp/udp */
    uint8_t     proto_type; /* SIP: 0x001, SDP: 0x03*/
    const char  *src_ip;
    const char  *dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint32_t    time_sec;
    uint32_t    time_usec;
} ;

typedef struct rc_info rc_info_t;

typedef struct _str {
        char* s; /**< Pointer to the first character of the string */
        int len; /**< Length of the string */
} str;
                

typedef enum msg_body_type {
        MSG_BODY_UNKNOWN = 0,
        MSG_BODY_SDP
} msg_body_type_t;


struct hep_module *hepmod;
extern int send_message (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int get_basestat(char *module, char *buf);
struct module *module_list;

