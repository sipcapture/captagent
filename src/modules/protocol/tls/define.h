/**
   Definition of macro and header size
   
   Copyright (C) 2016-2017 Michele Campus <fci1908@gmail.com>
             (C) QXIP BV 2012-2023 (http://qxip.net)
   
   Homer capture agent is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version
   
   Homer capture agent is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**/
#ifndef DEFINE_H_
#define DEFINE_H_

/* Header offsets */
#define ETHHDR_SIZE                 14
#define TOKENRING_SIZE              22
#define PPPHDR_SIZE                  4
#define SLIPHDR_SIZE                16
#define RAWHDR_SIZE                  0
#define LOOPHDR_SIZE                 4
#define FDDIHDR_SIZE                21
#define ISDNHDR_SIZE                16
#define IEEE80211HDR_SIZE           32

#define IPv4                         4
#define IPv6                         6

/* IPV6 header length */
#define IPV6_HDR_LEN                40
/* UDP header length */
#define UDP_HDR_LEN                  8

/* Ethernet protocol ID's from Ether Type field */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_RARP	        0x8035		/* Reverse ARP */
#define ETHERTYPE_APPLETLK	0x809B		/* AppleTalk protocol */
#define ETHERTYPE_APPLEARP	0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define	ETHERTYPE_IPv4		0x0800		/* IP */
#define	ETHERTYPE_IPv6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */
#define ETHERTYPE_MPLS_UNI      0x8847
#define ETHERTYPE_MPLS_MULTI    0x8848
#define ETHERTYPE_PPPoE_1       0x8863
#define ETHERTYPE_PPPoE         0x8864
#define ETHERTYPE_LLDP          0x88CC

/* SNAP extension */
#define SNAP                      0xaa

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)
/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

#endif
