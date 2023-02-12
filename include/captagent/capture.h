/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2023 (http://www.sipcapture.org)
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

#ifndef CAPTURE_H_
#define CAPTURE_H_

struct capture_list{
        struct action* clist[20];        
        int idx; 
        int entries; 
        char names[20][100]; 
};

#define FILTER_LEN 4080

/* our payload range between 0 - 191 */
#define RTP_FILTER "(ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80)"
/* our payload range between 200 and 204 */
#define RTCP_FILTER "(ip and ip[6] & 0x2 = 0 and ip[6:2] & 0x1fff = 0 and udp and udp[8] & 0xc0 = 0x80 and udp[9] >= 0xc8 && udp[9] <= 0xc9)"
/* IP-to-IP encapsulation filter // check portrange 5060-5090 */
#define IP_IP_FILTER "(ip[9]=0x04 and ((ip[40:2]>=0x13c4 and ip[40:2]<=0x13e2) or (ip[42:2]>=0x13c4 and ip[42:2]<=0x13e2)))"

#endif /* CAPTURE_H_ */
