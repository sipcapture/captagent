

#define FILTER_LEN 4080


int port = 5060; /* default port is SIP */
char *portrange = NULL;
char *userfilter=NULL;
char *ip_proto = NULL;
char *proto_type = "sip";
int promisc = 1;

          
int load_module(xml_node *config);
void handler(int value);

int dump_proto_packet(struct pcap_pkthdr *, u_char *, uint8_t, unsigned char *, uint32_t,const char *,
            const char *, uint16_t, uint16_t, uint8_t,uint16_t, uint8_t, uint16_t, uint32_t, uint32_t);




