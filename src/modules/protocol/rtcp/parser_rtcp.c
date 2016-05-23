/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2014 (http://www.sipcapture.org)
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

#include <stdio.h>
#include <captagent/log.h>
#include "parser_rtcp.h"


int check_rtcp_version (char *packet, int len) {

	if(packet == NULL || len == 0) return -1;

	rtcp_header_t *rtcp = (rtcp_header_t *)packet;

	if(rtcp->version != 2)
	{
		LERR("wrong version\n");
		return -2;
	}
	
	if(rtcp->type >= RTCP_SR && rtcp->type <= RTCP_SDES) {
		return 1;
	}

	return -3;
}


int capt_parse_rtcp(char *packet, int len, char *json_buffer, int buffer_len) {


	if(packet == NULL || len == 0) return -1;

	rtcp_header_t *rtcp = (rtcp_header_t *)packet;
	int ret=0;
	char *rptr;

	if(rtcp->version != 2)
	{
		LERR("wrong version\n");
		return -2;
	}

	ret+=snprintf(json_buffer, buffer_len, "{ ");

	int pno = 0, total = len;
	LDEBUG("Parsing compound packet (total of %d bytes)\n", total);
	while(rtcp) {
		pno++;
		switch(rtcp->type) {
			case RTCP_SR: {
				/* SR, sender report */
				LDEBUG("#%d SR (200)\n", pno);
				rtcp_sr_t *sr = (rtcp_sr_t*)rtcp;

				ret += snprintf(json_buffer+ret, buffer_len - ret, SENDER_REPORT_JSON,
								sender_info_get_ntp_timestamp_msw(&sr->si),
								sender_info_get_ntp_timestamp_lsw(&sr->si),
								sender_info_get_octet_count(&sr->si),
								sender_info_get_rtp_timestamp(&sr->si),
								sender_info_get_packet_count(&sr->si));

				if(sr->header.rc > 0) {

					ret += snprintf(json_buffer+ret, buffer_len - ret, REPORT_BLOCK_JSON,
								ntohl(sr->ssrc), rtcp->type,
								report_block_get_ssrc(&sr->rb[0]),
								report_block_get_high_ext_seq(&sr->rb[0]),
								report_block_get_fraction_lost(&sr->rb[0]),
								report_block_get_interarrival_jitter(&sr->rb[0]),
								report_block_get_cum_packet_loss(&sr->rb[0]),
								report_block_get_last_SR_time(&sr->rb[0]),
								report_block_get_last_SR_delay(&sr->rb[0]));
				}


				break;
			}
			case RTCP_RR: {
				/* RR, receiver report */
				LDEBUG("#%d RR (201)\n", pno);
				rtcp_rr_t *rr = (rtcp_rr_t*)rtcp;

				if(rr->header.rc > 0) {

					ret += snprintf(json_buffer+ret, buffer_len - ret, REPORT_BLOCK_JSON,
								ntohl(rr->ssrc), rtcp->type,
								report_block_get_ssrc(&rr->rb[0]),
								report_block_get_high_ext_seq(&rr->rb[0]),
								report_block_get_fraction_lost(&rr->rb[0]),
								report_block_get_interarrival_jitter(&rr->rb[0]),
								report_block_get_cum_packet_loss(&rr->rb[0]),
								report_block_get_last_SR_time(&rr->rb[0]),
								report_block_get_last_SR_delay(&rr->rb[0]));
				}
				break;
			}
			case RTCP_SDES: {
				LDEBUG("#%d SDES (202)\n", pno);

				/* if not needed send sdes */
				if(!send_sdes) break;

				rtcp_sdes_t *sdes = (rtcp_sdes_t*)rtcp;

				rptr = rtcp+2;
				int sdes_report_count = 0;

				char *end=(char*) rptr+(4*(rtcp_header_get_length(&sdes->header)+1)-15);

				ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_BEGIN_JSON, ntohl(sdes->ssrc), sdes_chunk_get_csrc(&sdes->chunk));

				while(rptr < end) {

					if (rptr+2<=end) {

						uint8_t chunk_type=rptr[0];
						uint8_t chunk_len=rptr[1];

						if(chunk_len == 0) break;

						rptr+=2;

						ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_INFO_JSON, chunk_type, chunk_len, rptr);

						sdes_report_count++;

						if (rptr+chunk_len<=end) rptr+=chunk_len;
						else break;
					}
					else {
						break;
					}
				}

				/* cut , off */
				ret-=1;

				ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_END_JSON, sdes_report_count);

				break;
			}
			case RTCP_BYE: {
				LDEBUG("#%d BYE (203)\n", pno);
				ret = 0;
				//rtcp_bye_t *bye = (rtcp_bye_t*)rtcp;
				break;
			}
			case RTCP_APP: {
				LDEBUG("#%d APP (204)\n", pno);
				ret = 0;
				//rtcp_app_t *app = (rtcp_app_t*)rtcp;
				break;
			}
			default:
				break;
		}


		int length = ntohs(rtcp->length);
		if(length == 0) {
			break;
		}
		total -= length*4+4;
		if(total <= 0) {
			LDEBUG("End of RTCP packet\n");
			break;
		}
		rtcp = (rtcp_header_t *)((uint32_t*)rtcp + length + 1);
	}

	/* bad parsed message */
	if(ret  < 10) return 0;

	ret+=snprintf(json_buffer+ret-1, buffer_len-ret+1, "}");

	return ret;
}

