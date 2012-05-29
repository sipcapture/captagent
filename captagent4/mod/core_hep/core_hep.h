#define USE_IPV6

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

int sock;
char *capt_host  = "213.148.130.41";
char *capt_port  = "9000";
char *capt_proto = "udp";
char *capt_password;
int   capt_id = 101;
int hep_version = 3;


int load_module(xml_node *config);
void handler(int value);

int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_data (void *buf, unsigned int len);


/* HEPv3 types */
typedef struct hep_chunk {
       u_int16_t vendor_id;
       u_int16_t type_id;
       u_int16_t length;
} hep_chunk_t;

typedef struct hep_chunk_uint8 {
       hep_chunk_t chunk;
       u_int8_t data;
} hep_chunk_uint8_t;

typedef struct hep_chunk_uint16 {
       hep_chunk_t chunk;
       u_int16_t data;
} hep_chunk_uint16_t;

typedef struct hep_chunk_uint32 {
       hep_chunk_t chunk;
       u_int32_t data;

} hep_chunk_uint32_t;

typedef struct hep_chunk_str {
       hep_chunk_t chunk;
       char *data;
} hep_chunk_str_t;

typedef struct hep_chunk_ip4 {
       hep_chunk_t chunk;
       struct in_addr data;
} hep_chunk_ip4_t;

typedef struct hep_chunk_ip6 {
       hep_chunk_t chunk;
       struct in6_addr data;
} hep_chunk_ip6_t;


typedef struct hep_ctrl {
    char id[4];
    u_int16_t length;
} hep_ctrl_t;

/* Structure of HEP */

struct hep_generic {
        hep_ctrl_t         header;
        hep_chunk_uint8_t  ip_family;
        hep_chunk_uint8_t  ip_proto;
        hep_chunk_ip4_t    src_ip4;
        hep_chunk_ip4_t    dst_ip4;
        hep_chunk_ip6_t    src_ip6;
        hep_chunk_ip6_t    dst_ip6;
        hep_chunk_uint16_t src_port;
        hep_chunk_uint16_t dst_port;
        hep_chunk_uint32_t time_sec;
        hep_chunk_uint32_t time_usec;
        hep_chunk_uint8_t  proto_t;
        hep_chunk_uint32_t capt_id;
        hep_chunk_uint16_t keep_tm;
        hep_chunk_str_t    auth_key;
        hep_chunk_t        payload;
        //hep_chunk_str_t    payload;
} __attribute__((packed));

typedef struct hep_generic hep_generic_t;

/*
static hep_generic_t HDR_HEP = {
    {0x48455033, 0x0},
    {0, 0x0001, 0x00, 0x00},
    {0, 0x0002, 0x00, 0x00},
    {0, 0x0003, 0x00, 0x00},
    {0, 0x0004, 0x00, 0x00},
    {0, 0x0005, 0x00, 0x00},
    {0, 0x0006, 0x00, 0x00},
    {0, 0x0007, 0x00, 0x00},
    {0, 0x0008, 0x00, 0x00},
    {0, 0x0009, 0x00, 0x00},
    {0, 0x000a, 0x00, 0x00},
    {0, 0x000b, 0x00, 0x00},
    {0, 0x000c, 0x00, 0x00},
    {0, 0x000d, 0x00, 0x00},
    {0, 0x000e, 0x00, 0x00},
    {0, 0x000f, 0x00, 0x00}
};
*/


/* Ethernet / IP / UDP header IPv4 */
const int udp_payload_offset = 14+20+8;

struct hep_hdr{
    u_int8_t hp_v;            /* version */
    u_int8_t hp_l;            /* length */
    u_int8_t hp_f;            /* family */
    u_int8_t hp_p;            /* protocol */
    u_int16_t hp_sport;       /* source port */
    u_int16_t hp_dport;       /* destination port */
};

struct hep_timehdr{
    u_int32_t tv_sec;         /* seconds */
    u_int32_t tv_usec;        /* useconds */
    u_int16_t captid;         /* Capture ID node */
};

struct hep_iphdr{
        struct in_addr hp_src;
        struct in_addr hp_dst;      /* source and dest address */
};

#ifdef USE_IPV6
struct hep_ip6hdr {
        struct in6_addr hp6_src;        /* source address */
        struct in6_addr hp6_dst;        /* destination address */
};
#endif
