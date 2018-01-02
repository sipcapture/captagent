/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Michele Campus <fci1908@gmail.com>
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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <captagent/log.h>
#include <arpa/inet.h>
#include "parser_diameter.h"

// Check packet
int is_diameter(char *packet, int size_payload)
{
  // check param
  if(!packet || size_payload == 0) return -1;

  // cast to diameter header
  struct diameter_header_t *diameter = (struct diameter_header_t *) packet;

  // check if the packet is diameter
  if(diameter->version == 0x01 &&
     (diameter->flags == REQUEST ||
      diameter->flags == PROXYABLE ||
      diameter->flags == ERROR ||
      diameter->flags == RETRASM)) {

    u_int16_t com_code = diameter->com_code[2] + (diameter->com_code[1] << 8) + (diameter->com_code[0] << 8);
    
    if(com_code == AC || com_code == AS ||
       com_code == CC || com_code == CE ||
       com_code == DW || com_code == DP ||
       com_code == RA || com_code == ST)
      return 0; // OK
  }
  // wrong packet
  return -2;
}


// Parse packet and fill JSON buffer
int parse_diameter(char *packet, int size_payload, char json_buffer[], int buffer_len)
{
  int offset = 0, js_ret = 0;
  
  int ret = is_diameter(packet, size_payload);
  if(ret != 0) return -1; // invalid params

  // cast to diameter header
  struct diameter_header_t *diameter = (struct diameter_header_t *) packet;

  u_int16_t length = diameter->length[2] + (diameter->length[1] << 8) + (diameter->length[0] << 8);
  
  if(length != size_payload) return -2; // invalid length size

  // pointer used to move through the pkt
  char *pp = packet;

  // increment offset
  offset += DIAM_HEADER_LEN;
  
  // move the pointer forward
  pp = pp + DIAM_HEADER_LEN;

  /**
     Create json buffer: it's created dinamically because it's impossibile determine a static format (not all the same fields are present in a Diameter packet 
  */
  js_ret += snprintf((json_buffer + js_ret), buffer_len, "{ \"Diameter_report_information\":{ ");
  
  while(offset < length) {

    // Info from AVP headers
    u_int32_t avp_code;
    u_int16_t avp_len;
    u_int16_t l;
    u_int8_t padd = 0;

    // Header AVP
    struct avp_header_t *avp = (struct avp_header_t *) pp;

    // calculate AVP code
    avp_code = ntohl(avp->code);
    // calculate AVP length
    avp_len = avp->length[2] + (avp->length[1] << 8) + (avp->length[0] << 8);

    // search the presence of Vendor-ID field (optional)
    if(avp->flag != AVP_FLAGS_P && avp->flag != AVP_FLAGS_M)
      pp = pp + 4;

    switch(avp_code) {
      
      // 263
    case SESS_ID:

      pp = pp + AVP_HEADER_LEN;
      u_int16_t sess_id_len = avp_len - AVP_HEADER_LEN;
      session_id = calloc(sess_id_len, sizeof(char));
      memcpy(session_id, pp, sess_id_len);

      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + sess_id_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"session-ID\":%s, ", session_id);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 461
    case SERV_CONTX_ID:

      pp = pp + AVP_HEADER_LEN;
      u_int16_t serv_contx_len = avp_len - AVP_HEADER_LEN;
      serv_contx_id = calloc(serv_contx_len, sizeof(char));
      memcpy(serv_contx_id, pp, serv_contx_len);

      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + serv_contx_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"service-context-ID\":%s, ", serv_contx_id);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;      
      
      // 443
    case SUBSCR_ID:

      pp = pp + AVP_HEADER_LEN;
      // 1
      struct avp_header_t *avp_sub_id_data = (struct avp_header_t *) pp;
      u_int16_t avp_sub_id_lenD = avp_sub_id_data->length[2] + (avp_sub_id_data->length[1] << 8) + (avp_sub_id_data->length[0] << 8);
      u_int16_t dlen = avp_sub_id_lenD - AVP_HEADER_LEN;
      char * subscr_id_data = calloc(dlen, sizeof(char));
      pp = pp + AVP_HEADER_LEN;
      memcpy(subscr_id_data, pp, dlen);
      pp = pp + dlen;
      // 2
      struct avp_header_t * avp_sub_id_type = (struct avp_header_t *) pp;
      u_int16_t avp_sub_id_lenT = avp_sub_id_type->length[2] + (avp_sub_id_type->length[1] << 8) + (avp_sub_id_type->length[0] << 8);
      pp = pp + AVP_HEADER_LEN;
      u_int32_t subscr_id_type = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      u_int16_t tlen = avp_sub_id_lenT - AVP_HEADER_LEN;
      pp = pp + tlen;
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }

      pp = pp + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 SUBSCR_ID_JSON, subscr_id_data, subscr_id_type);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 264
    case ORIGIN_HOST:

      pp = pp + AVP_HEADER_LEN;
      u_int16_t org_host_len = avp_len - AVP_HEADER_LEN;
      org_host = calloc(org_host_len, sizeof(char));
      memcpy(org_host, pp, org_host_len);

      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + org_host_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Origin-host\":%s, ", org_host);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 293
    case DEST_HOST:

      pp = pp + AVP_HEADER_LEN;
      u_int16_t dst_host_len = avp_len - AVP_HEADER_LEN;
      dst_host = calloc(dst_host_len, sizeof(char));
      memcpy(dst_host, pp, dst_host_len);

      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + dst_host_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Destination-host\":%s, ", dst_host);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 296
    case ORIGIN_REALM:

      pp = pp + AVP_HEADER_LEN;
      u_int16_t org_realm_len = avp_len - AVP_HEADER_LEN;
      org_realm = calloc(org_realm_len, sizeof(char));
      memcpy(org_realm, pp, org_realm_len);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + org_realm_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Origin-realm\":%s, ", org_realm);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 283
    case DEST_REALM:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t dst_realm_len = avp_len - AVP_HEADER_LEN;
      dst_realm = calloc(dst_realm_len, sizeof(char));
      memcpy(dst_realm, pp, dst_realm_len);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + dst_realm_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Destination-realm\":%s, ", dst_realm);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;

      // 55
    case TIMESTAMP:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t time_len = avp_len - AVP_HEADER_LEN;
      tm = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8); /* CHECK */
      char buff_tm[25] = {0};
      sprintf(buff_tm, "%s", ctime(&tm));
      u_int8_t pos = strlen(buff_tm) - 1;
      buff_tm[pos] = '\0';
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + time_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Timestamp\":%s, ", buff_tm);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 440
    case SERV_PAR_INFO:
      
      pp = pp + AVP_HEADER_LEN;
      // 1
      struct avp_header_t *avp_serv_par_type = (struct avp_header_t *) pp;
      u_int16_t avp_serv_par_Tlen = avp_serv_par_type->length[2] + (avp_serv_par_type->length[1] << 8) + (avp_serv_par_type->length[0] << 8);
      pp = pp + AVP_HEADER_LEN;
      u_int32_t serv_par_info_type = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      u_int16_t Tlen = avp_serv_par_Tlen - AVP_HEADER_LEN;
      pp = pp + Tlen;      
      // 2
      struct avp_header_t * avp_serv_par_value = (struct avp_header_t *) pp;
      u_int16_t avp_serv_par_Vlen = avp_serv_par_value->length[2] + (avp_serv_par_value->length[1] << 8) + (avp_serv_par_value->length[0] << 8);
      u_int16_t Vlen = avp_serv_par_Vlen - AVP_HEADER_LEN;
      char * serv_par_value = calloc(Vlen, sizeof(char));
      pp = pp + AVP_HEADER_LEN;
      memcpy(serv_par_value, pp, Vlen);
      pp = pp + Vlen;

      // check for internal padding
      l = avp_serv_par_Vlen;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      pp = pp + padd; // move pointer forward
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 SERV_PARAM_JSON, serv_par_info_type, serv_par_value);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 258
    case AUTH_APP_ID:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t auth_app_len = avp_len - AVP_HEADER_LEN;
      auth_app_id = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + auth_app_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"auth-application-ID\":%u, ", auth_app_id);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 278
    case ORIGIN_ST_ID:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t org_state_len = avp_len - AVP_HEADER_LEN;
      org_state_id = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + org_state_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Origin-state-ID\":%u, ", org_state_id);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 415
    case CC_REQ_NUM:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t cc_req_num_len = avp_len - AVP_HEADER_LEN;
      cc_req_num = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + cc_req_num_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"CC-request-number\":%u, ", cc_req_num);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 416
    case CC_REQ_TYPE:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t cc_req_type_len = avp_len - AVP_HEADER_LEN;
      cc_req_type = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + cc_req_type_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"CC-request-type\":%u, ", cc_req_type);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 268
    case RES_CODE:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t res_code_len = avp_len - AVP_HEADER_LEN;
      res_code = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + res_code_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Result-code\":%u, ", res_code);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;

      // 448
    case VALID_TIME:
      
      pp = pp + AVP_HEADER_LEN;
      u_int16_t valid_len = avp_len - AVP_HEADER_LEN;
      valid_time = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8);
      
      // check for padding
      l = avp_len;
      padd = 0;
      while(l % 4 != 0) {
	padd++;	l++;
      }
      
      pp = pp + valid_len + padd; // move pointer forward
      offset += avp_len + padd; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 "\"Validity-time\":%u, ", valid_time);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 437
    case REQ_SERV_UNT:
      
      pp = pp + AVP_HEADER_LEN;
      req_serv_unit = (struct req_serv_unit_t *) pp;
      u_int64_t req_value_dgt = req_serv_unit->value_dgt[7] + (req_serv_unit->value_dgt[6] << 8) + (req_serv_unit->value_dgt[5] << 8) + (req_serv_unit->value_dgt[4] << 8) + (req_serv_unit->value_dgt[3] << 8) + (req_serv_unit->value_dgt[2] << 8) + (req_serv_unit->value_dgt[1] << 8) + (req_serv_unit->value_dgt[0] << 8);
      u_int32_t req_currency_code = req_serv_unit->curr_code[3] + (req_serv_unit->curr_code[2] << 8) + (req_serv_unit->curr_code[1] << 8) + (req_serv_unit->curr_code[0] << 8);
      
      pp = pp + avp_len - AVP_HEADER_LEN; // move pointer forward
      offset += avp_len; // update offset

      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 REQ_SERV_UNT_JSON, req_value_dgt, req_currency_code);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 431
    case GRANT_SERV_UNT:
      
      pp = pp + AVP_HEADER_LEN;
      grant_serv_unit = (struct grant_serv_unit_t *) pp;
      u_int64_t grant_value_dgt = grant_serv_unit->value_dgt[7] + (grant_serv_unit->value_dgt[6] << 8) + (grant_serv_unit->value_dgt[5] << 8) + (grant_serv_unit->value_dgt[4] << 8) + (grant_serv_unit->value_dgt[3] << 8) + (grant_serv_unit->value_dgt[2] << 8) + (grant_serv_unit->value_dgt[1] << 8) + (grant_serv_unit->value_dgt[0] << 8);
      u_int32_t grant_currency_code = grant_serv_unit->curr_code[3] + (grant_serv_unit->curr_code[2] << 8) + (grant_serv_unit->curr_code[1] << 8) + (grant_serv_unit->curr_code[0] << 8);

      pp = pp + avp_len - AVP_HEADER_LEN; // move pointer forward
      offset += avp_len; // update offset

      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 GRANT_SERV_UNT_JSON, grant_value_dgt, grant_currency_code);
      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 446
    case USED_SERV_UNT:
      
      pp = pp + AVP_HEADER_LEN;
      used_serv_unit = (struct used_serv_unit_t *) pp;
      u_int64_t used_value_dgt = used_serv_unit->value_dgt[7] + (used_serv_unit->value_dgt[6] << 8) + (used_serv_unit->value_dgt[5] << 8) + (used_serv_unit->value_dgt[4] << 8) + (used_serv_unit->value_dgt[3] << 8) + (used_serv_unit->value_dgt[2] << 8) + (used_serv_unit->value_dgt[1] << 8) + (used_serv_unit->value_dgt[0] << 8);
      u_int32_t used_currency_code = used_serv_unit->curr_code[3] + (used_serv_unit->curr_code[2] << 8) + (used_serv_unit->curr_code[1] << 8) + (used_serv_unit->curr_code[0] << 8);

      pp = pp + avp_len - AVP_HEADER_LEN; // move pointer forward
      offset += avp_len; // update offset
      
      // put buffer in JSON buffer
      js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
			 USED_SERV_UNT_JSON, used_value_dgt, used_currency_code);

      /* printf("json_buffer = %s\n", json_buffer); */
      break;
      
      // 456
    case MULTI_SERV_CC: /* TODO (need more test pkts) */
      break;

    default: return -3; // error: avp->code unknown
    }
  }
  
  js_ret += snprintf((json_buffer + js_ret - 2), (buffer_len - js_ret + 1), "}");

  // update general statistic info **TODO** //
  
  return strlen(json_buffer); // OK
}
