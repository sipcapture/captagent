/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Holger Hans Peter Freyther <help@moiji-mobile.com>
 *  (C) Homer Project 2016 (http://www.sipcapture.org)
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

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <captagent/api.h>
#include <captagent/structure.h>


enum sctp_chunk_type {
	SCTP_CHUNK_DATA,
	SCTP_CHUNK_INIT,
	SCTP_CHUNK_INIT_ACK,
	SCTP_CHUNK_SACK,
	/* Right now only _DATA matters */
};

struct sctp_common_hdr {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	ver_tag;
	uint32_t	checksum;
	uint8_t		data[0];
} __attribute__((packed));

struct sctp_chunk_hdr {
	uint8_t		type;
	uint8_t		flags;
	uint16_t	len;
	uint8_t		data[0];
} __attribute__((packed));

struct sctp_chunk_data_hdr {
	/* hdr */
	uint8_t		type;
	uint8_t		reserved:5,
			unordered:1,
			beginning:1,
			ending: 1;
	uint16_t	len;

	/* chunk types */
	uint32_t		tsn;
	uint16_t		stream_id;
	uint16_t		seqno;
	uint32_t		ppid;
	uint8_t			data[0];
} __attribute__((packed));

int sctp_parse_common(msg_t *msg, const uint8_t *data, size_t len);
int sctp_parse_chunk(msg_t *msg, const uint8_t *data, size_t len, bool *send_data);
