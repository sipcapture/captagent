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

#include "sctp_support.h"


int sctp_parse_common(msg_t *_msg, const uint8_t *data, size_t len)
{
	struct sctp_common_hdr *sctp_hdr;

	/* not enough space for the header */
	if (len < sizeof(*sctp_hdr))
		return -1;

	sctp_hdr = (struct sctp_common_hdr *) data;
	_msg->rcinfo.src_port = ntohs(sctp_hdr->source);
	_msg->rcinfo.dst_port = ntohs(sctp_hdr->dest);
	return sizeof(*sctp_hdr);;
}

int sctp_parse_chunk(msg_t *_msg, const uint8_t *data, size_t len, bool *send_data)
{
	struct sctp_chunk_data_hdr *dhdr;
	uint16_t chunk_len;

	*send_data = false;
	if (len < sizeof(struct sctp_chunk_hdr))
		return -1;

	/* length smaller than the header */
	dhdr = (struct sctp_chunk_data_hdr *) data;
	chunk_len = ntohs(dhdr->len);
	if (chunk_len < sizeof(*dhdr))
		return -2;

	if (chunk_len > len)
		return -3;

	if (dhdr->type != SCTP_CHUNK_DATA)
		return chunk_len;

	/* check for additional data */
	if (len < sizeof(*dhdr))
		return -4;

	/* Only handle non-fragmented SCTP data chunks */
	if (dhdr->beginning && dhdr->ending)
		*send_data = true;
	_msg->sctp_ppid = ntohl(dhdr->ppid);
	return chunk_len;
}
