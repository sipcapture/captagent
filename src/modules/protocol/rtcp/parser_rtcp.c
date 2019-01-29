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

int check_rtp_version(char *packet, int len) {

  if(packet == NULL || len == 0) return -1;

  rtcp_header_t *rtcp = (rtcp_header_t *)packet;

  if(rtcp->version != 2)
    {
      LERR("wrong version\n");
      return -2;
    }

  return 1;
}


int capt_parse_rtcp(char *packet, int len, char *json_buffer, int buffer_len) {

  // check parameters
  if(packet == NULL || len == 0) return -1;

  rtcp_header_t *rtcp = (rtcp_header_t *)packet;
  int ret = 0, flag = 0;

  ret += snprintf(json_buffer, buffer_len, "{ ");

  int pno = 0, total = len;
  LDEBUG("Parsing compound packet (total of %d bytes)\n", total);
  
  while(rtcp) {

    pno++;
    
    switch(rtcp->type) {

      /* SR, sender report */
    case RTCP_SR: {

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
			report_block_get_identifier(&sr->rb[0]),
			report_block_get_high_ext_seq(&sr->rb[0]),
			report_block_get_fraction_lost(&sr->rb[0]),
			report_block_get_interarrival_jitter(&sr->rb[0]),
			report_block_get_cum_packet_loss(&sr->rb[0]),
			report_block_get_last_SR_time(&sr->rb[0]),
			report_block_get_last_SR_delay(&sr->rb[0]));
      }
      break;
    }
      /* RR, receiver report */
    case RTCP_RR: {
      
      LDEBUG("#%d RR (201)\n", pno);
      rtcp_rr_t *rr = (rtcp_rr_t*)rtcp;

      if(rr->header.rc > 0) {

	ret += snprintf(json_buffer+ret, buffer_len - ret, REPORT_BLOCK_JSON,
			ntohl(rr->ssrc),
			rtcp->type,
			report_block_get_identifier(&rr->rb[0]),
			report_block_get_high_ext_seq(&rr->rb[0]),
			report_block_get_fraction_lost(&rr->rb[0]),
			report_block_get_interarrival_jitter(&rr->rb[0]),
			report_block_get_cum_packet_loss(&rr->rb[0]),
			report_block_get_last_SR_time(&rr->rb[0]),
			report_block_get_last_SR_delay(&rr->rb[0]));
      }
      break;
    }
      /* SDES, source description */
    case RTCP_SDES: {

      LDEBUG("#%d SDES (202)\n", pno);
      
      /* if not needed send sdes */
      if(!send_sdes) break;

      int items;

      rtcp_sdes_t *sdes = (rtcp_sdes_t*)rtcp;
      rtcp_sdes_item_t *end = (rtcp_sdes_item_t *)
                                ((uint32_t *)rtcp + ntohs(rtcp->length) + 1);
      rtcp_sdes_item_t *rsp, *rspn;

      ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_BEGIN_JSON,
          ntohl(sdes->csrc), sdes->header.rc);

      rsp = &sdes->item[0];
      if (rsp >= end) break;
      for (items = 0; rsp->type; rsp = rspn ) {
        rspn = (rtcp_sdes_item_t *)((char*)rsp+rsp->len+2);
        if (rspn >= end) {
          rsp = rspn;
          break;
        }
        ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_INFO_JSON,
            rsp->type, rsp->len, rsp->content);
        items++;
      }
      /* cut , off */
      if (items) ret -= 1;
      ret += snprintf(json_buffer+ret, buffer_len - ret, "],");

      break;
    }
      /* BYE, Goodbye */
    case RTCP_BYE: {
      
      LDEBUG("#%d BYE (203)\n", pno);
      flag = 1;
      //rtcp_bye_t *bye = (rtcp_bye_t*)rtcp;
      break;
    }
      /* APP, Application-defined */
    case RTCP_APP: {
      
      LDEBUG("#%d APP (204)\n", pno);
      flag = 1;
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
  
  /* Bad parsed message or BYE/APP packet */
  if(ret < 10) {
    if(flag == 0) // BAD PARSING
      return -2;
    // else: BYE or APP packet
    return 0;
  }
  
  /* replace last comma */
  json_buffer[ret-1]='}';
  
  //ret += snprintf(json_buffer + ret - 1, buffer_len - ret + 1, "}");

  return ret;
}
