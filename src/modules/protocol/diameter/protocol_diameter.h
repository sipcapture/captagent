/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *          Michele Campus <fci1908@gmail.com>
 *
 *  (C) Homer Project 2012-2017 (http://www.sipcapture.org)
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

#ifndef PROTOCOL_DIAMETER_H_
#define PROTOCOL_DIAMETER_H_

#include <captagent/xmlread.h>
#include "parser_diameter.h"

#define PROTO_DIAMETER  0x38

typedef struct protocol_diameter_stats {
	uint64_t received_packets_total;
	uint64_t parsed_packets;
	uint64_t send_packets;
} protocol_diameter_stats_t;

static protocol_diameter_stats_t stats;

#define MAX_PROTOCOLS 10
profile_protocol_t profile_protocol[MAX_PROTOCOLS];

int bind_api(protocol_module_api_t* api);
int reload_config (char *erbuf, int erlen);
void free_module_xml_config();
int load_module_xml_config();

/** Functions for DIAMETER **/
int w_parse_diameter_to_json(msg_t *msg);

#endif /* PROTOCOL_DIAMETER_H_ */
