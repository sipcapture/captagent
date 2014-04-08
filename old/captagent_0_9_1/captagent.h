#define VERSION "0.9.1"
#define DEFAULT_CONFIG "/usr/local/etc/captagent/captagent.ini"
#define DEFAULT_PIDFILE  "/var/run/captagent.pid"
#define DEFAULT_PORT "5060"

/* filter to extract SIP packets */
char filter_expr[1024];

/* Ethernet / IP / UDP header IPv4 */
const int udp_payload_offset = 14+20+8;

struct ethhdr_vlan {
	unsigned char        h_dest[6];
	unsigned char        h_source[6];
	uint16_t             type;		 	/* vlan type*/ 
	uint16_t             ptt;		 	 /* priority */   
	uint16_t             h_proto;
};


#define PROTO_SIP    0x01

/* FreeBSD or Solaris */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
struct ethhdr {
	unsigned char        h_dest[6];
	unsigned char        h_source[6];
	uint16_t             h_proto;
};
#endif

/* header offsets */
#define ETHHDR_SIZE 14
#define TOKENRING_SIZE 22
#define PPPHDR_SIZE 4
#define SLIPHDR_SIZE 16
#define RAWHDR_SIZE 0
#define LOOPHDR_SIZE 4
#define FDDIHDR_SIZE 21
#define ISDNHDR_SIZE 16
#define IEEE80211HDR_SIZE 32


/* functions */
void callback_proto(u_char *useless, struct pcap_pkthdr *pkthdr, u_char *packet);
int dump_proto_packet(struct pcap_pkthdr *pkthdr, u_char *packet, uint8_t proto, unsigned char *data, uint32_t len,
                 const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint8_t flags,
                                  uint16_t hdr_offset, uint8_t frag, uint16_t frag_offset, uint32_t frag_id, uint32_t ip_ver);
int send_hep_basic (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_hepv3 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
int send_hepv2 (rc_info_t *rcinfo, unsigned char *data, unsigned int len);
