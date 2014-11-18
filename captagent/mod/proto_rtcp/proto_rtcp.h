/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or modify
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

#ifndef _PROTO_RTCP_H
#define _PROTO_RTCP_H

#include "../../src/xmlread.h"
  

#define FILTER_LEN 4080

/* SYNC this list: http://hep.sipcapture.org */
#define PROTO_SIP    0x01
#define PROTO_XMPP   0x02
#define PROTO_SDP    0x03
#define PROTO_RTP    0x04
#define PROTO_RTCP_JSON   0x05
#define PROTO_RTCP   0x06
#define PROTO_MGCP   0x06
#define PROTO_MEGACO 0x07
#define PROTO_M2UA   0x08
#define PROTO_M3UA   0x09
#define PROTO_IAX    0x0a
#define PROTO_H322   0x0b
#define PROTO_H321   0x0c

char json_rtcp_buffer[5000];                        
char sip_callid[250];
int rtcp_port = 0; 
char *rtcp_portrange = NULL;
char *rtcp_userfilter=NULL;
int rtcp_proto_type = PROTO_RTCP; /* DEFAULT RTCP */
int rtcp_promisc = 1;
int rtcp_vlan = 0; /*vlan filter*/
int rtcp_as_json = 1;
int send_sdes = 1;

/* ip reasm */
int debug_proto_rtcp_enable = 0;

static int sendPacketsCount=0;

extern char* usefile;
extern int handler(int value);

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

/* our payload range between 0 - 191 */
#define RTP_FILTER "(ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 )"
//#define RTP_FILTER "(udp)"
/* our payload range between 200 and 204 */
#define RTCP_FILTER "(ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xcc)"

         
int load_module(xml_node *config);

int dump_rtp_packet(struct pcap_pkthdr *, u_char *, uint8_t, unsigned char *, uint32_t,const char *,
            const char *, uint16_t, uint16_t, uint8_t,uint16_t, uint8_t, uint16_t, uint32_t, uint32_t);



#endif

