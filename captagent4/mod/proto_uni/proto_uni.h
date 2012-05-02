

#define FILTER_LEN 4080

/* SYNC this list: http://hep.sipcapture.org */
#define PROTO_SIP    0x01
#define PROTO_XMPP   0x02
#define PROTO_SDP    0x03
#define PROTO_RTP    0x04
#define PROTO_RTCP   0x05
#define PROTO_MGCP   0x06
#define PROTO_MEGACO 0x07
#define PROTO_M2UA   0x08
#define PROTO_M3UA   0x09
#define PROTO_IAX    0x0a
#define PROTO_H322   0x0b
#define PROTO_H321   0x0c

int port = 5060; /* default port is SIP */
char *portrange = NULL;
char *userfilter=NULL;
char *ip_proto = NULL;
int proto_type = PROTO_SIP; /* DEFAULT SIP */
int promisc = 1;



          
int load_module(xml_node *config);
void handler(int value);

int dump_proto_packet(struct pcap_pkthdr *, u_char *, uint8_t, unsigned char *, uint32_t,const char *,
            const char *, uint16_t, uint16_t, uint8_t,uint16_t, uint8_t, uint16_t, uint32_t, uint32_t);




