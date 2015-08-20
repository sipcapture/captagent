/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or
 * modify
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

#ifndef STRUCTURE_H_
#define STRUCTURE_H_

#include "proto_sip.h"

typedef struct msg {
        void *data;
        char *profile_name;
        uint32_t len;
        uint8_t tcpflag;
        rc_info_t rcinfo;
        uint8_t parse_it;
        void *parsed_data;
        sip_msg_t sip;
        void *var;
        uint8_t mfree;
        int flag[10];
} msg_t;

typedef struct stats_msg {
        char *mod_name;
        uint32_t value;
} stats_msg_t;

typedef struct filter_msg {
        char *data;
        uint32_t value;
} filter_msg_t;


typedef struct db_msg {
       str key_name;
       str profile_name;
       uint16_t expire;
       uint32_t len;
       uint8_t batch;
} db_msg_t;



#endif /* STRUCTURE_H_ */
