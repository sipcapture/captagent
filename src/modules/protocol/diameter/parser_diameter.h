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
#ifndef PARSER_DIAMETER_H
#define PARSER_DIAMETER_H

#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>


#define SUBSCR_ID_JSON "\"Subscription-ID\":[{\"Subscription-ID-data\":%s, \"Subscription-ID-type\":%u}], "
#define SERV_PARAM_JSON "\"Service-parameter-info\":[{\"Service-parameter-type\":%u, \"Service-parameter-value\":%s}], "
#define REQ_SERV_UNT_JSON "\"Requested-service-unit\":[{\"Value-digits\":%lu, \"Currency-code\":%u}], "
#define GRANT_SERV_UNT_JSON "\"Granted-service-unit\":[{\"Value-digits\":%lu, \"Currency-code\":%u}], "
#define USED_SERV_UNT_JSON "\"Used-service-unit\":[{\"Value-digits\":%lu, \"Currency-code\":%u}], "

#define JSON_BUFFER_LEN 5000

// Header Flags possibile values
#define REQUEST   0X80
#define PROXYABLE 0X40
#define ERROR     0X20
#define RETRASM   0X10

typedef enum {
    AC = 271,
    AS = 274,
    CC = 272,
    CE = 257,
    DW = 280,
    DP = 282,
    RA = 258,
    ST = 275
} com_type_t;

#define DIAM_HEADER_LEN 20

// DIAMETER header
struct diameter_header_t
{
  u_int8_t  version;
  u_int8_t  length[3];
  u_int8_t  flags;
  u_int8_t  com_code[3];
  u_int32_t app_id;
  u_int32_t hop_id;
  u_int32_t end_id;
};

// AVP flags possibile values
#define AVP_FLAGS_P 0x20
#define AVP_FLAGS_M 0x40

#define AVP_HEADER_LEN 8

typedef enum {

  SESS_ID        = 263,
  SERV_CONTX_ID  = 461,
  SUBSCR_ID      = 443,
  ORIGIN_HOST    = 264,
  DEST_HOST      = 293,
  ORIGIN_REALM   = 296,
  DEST_REALM     = 283,
  TIMESTAMP      = 55,
  VENDOR_ID      = 266,
  SERV_PAR_INFO  = 440,
  AUTH_APP_ID    = 258,
  ORIGIN_ST_ID   = 278,
  CC_REQ_NUM     = 415, // 0 - 3
  CC_REQ_TYPE    = 416, // 1 - 4
  CC_MONEY       = 413,
  CC_UNIT_VAL    = 445,
  CC_CODE        = 425,
  VALUE_DGT      = 447,
  RES_CODE       = 268,
  VALID_TIME     = 448,
  REQ_SERV_UNT   = 437,
  GRANT_SERV_UNT = 431,
  USED_SERV_UNT   = 446,
  MULTI_SERV_CC  = 456
  /* CHEKC IF COMPLETE */
} avp_block_code;

// AVP HEADER
struct avp_header_t
{
  u_int32_t code;       // 1 - 255 for RADIUS compatibility | > 255 for Diameter
  u_int8_t  flag;
  u_int8_t  length[3];  /* Values not multiple of four-octets is followed by padding to have 32-bit boundary for the next AVP (if exists) */
};

// Requested-service-unit struct
struct req_serv_unit_t
{
  struct avp_header_t cc_money_head;   // 413
  struct avp_header_t cc_unit_val;     // 445
  struct avp_header_t value_dgt_head;  // 447
  u_int8_t value_dgt[8];
  struct avp_header_t cc_code_head;    // 425
  u_int8_t curr_code[4];
  /* Maybe incomplete */
};

// Granted-service-unit struct
struct grant_serv_unit_t
{
  struct avp_header_t cc_money_head;   // 413
  struct avp_header_t cc_unit_val;     // 445
  struct avp_header_t value_dgt_head;  // 447
  u_int8_t value_dgt[8];
  struct avp_header_t cc_code_head;    // 425
  u_int8_t curr_code[4];
  /* Maybe incomplete */
};

// Used-service-unit struct
struct used_serv_unit_t
{
  struct avp_header_t cc_money_head;   // 413
  struct avp_header_t cc_unit_val;     // 445
  struct avp_header_t value_dgt_head;  // 447
  u_int8_t value_dgt[8];
  struct avp_header_t cc_code_head;    // 425
  u_int8_t curr_code[4];
  /* Maybe incomplete */
};
  
/* List of ALL the structures for the AVP information block */
char* session_id;                          // 263
char* serv_contx_id;                       // 461
char* org_host;                            // 264
char* dst_host;                            // 293
char* org_realm;                           // 296
char* dst_realm;                           // 283
time_t tm;                                 // 55
u_int32_t auth_app_id;                     // 258
u_int32_t cc_req_num;                      // 415
u_int32_t cc_req_type;                     // 416 (1 - 4)
u_int32_t org_state_id;                    // 278
u_int32_t valid_time;                      // 448
u_int32_t res_code;                        // 268 ( 2xxx success - else failure)
struct req_serv_unit_t *req_serv_unit;     // 437
struct grant_serv_unit_t *grant_serv_unit; // 431
struct used_serv_unit_t *used_serv_unit;   // 446
/*** TODO Multiple Service Credit Control (Need more test pkts) ***/

/**
   Functions for the dissection 
**/
// Check packet
int is_diameter(char *packet, int size_payload);
// Parse packet and fill JSON buffer
int parse_diameter(char *packet, int size_payload, char json_buffer[], int buffer_len);

#endif
