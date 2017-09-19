/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Michele Campus <fci1908@gmail.com>
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
#ifndef PARSER_RTCPXR_H
#define PARSER_RTCPXR_H

#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// Macro to create JSON buffer (fields from RTCP-XR block)
#define EXTENDED_REPORT_JSON "\"Extended_report_information\":{\"identifier\":%u, \"loss_rate\":%u, \"discard_rate\":%u, \"burst_rate\":%u, \"gap_rate\":%u, \"burst_duration\":%u, \"gap_duration\":%u, \"round_trip_delay\":%u, \"end_sys_delay\":%u, \"signal_lev\":%u, \"noise_lev\":%u, \"RERL\":%u, \"Gmin\":%u, \"R_fact\":%u, \"ext_R_fact\":%u, \"MOS_LQ\":%u, \"MOS_CQ\":%u, \"RX_conf\":[{\"PLC\":%u, \"JB_adapt\":%u, \"JB_rate\":%u}], \"JB_nom\":%u, \"JB_max\":%u, \"JB_abs_max\":%u}"

#define JSON_BUFFER_LEN 5000

typedef enum {
    RTCP_SR   = 200,
    RTCP_RR   = 201,
    RTCP_SDES = 202,
    RTCP_BYE  = 203,
    RTCP_APP  = 204,
    RTCP_XR   = 207
} rtcp_type_t;


// RTCP header
struct rtcp_header_t
{
#if __BYTE_ORDER == __BIG_ENDIAN
  u_int16_t version:2;
  u_int16_t padding:1;
  u_int16_t rc:5;
  u_int16_t pkt_type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  u_int16_t rc:5;
  u_int16_t padding:1;
  u_int16_t version:2;
  u_int16_t pkt_type:8;
#endif
  u_int16_t length:16;
} PACK_OFF;

// get the block length
#define rtcp_header_get_length(h)     ntohs((h)->length)
// get the type of block (skip all != 207 (EXR) )
#define rtcp_header_get_pkt_type(h)   ntohs((h)->pkt_type)

// RTCP-XR header
struct rtcp_xr_header_t
{
  u_int8_t type;
  u_int8_t sp_type;
  u_int16_t len;
};

// RTCP-XR information block
struct rtcp_xr_block_t
{
  u_int32_t id;
  u_int8_t loss_rate;
  u_int8_t discard_rate;
  u_int8_t burst_rate;
  u_int8_t gap_rate;
  u_int16_t burst_duration;
  u_int16_t gap_duration;
  u_int16_t round_trip_delay;
  u_int16_t end_sys_delay;
  u_int8_t signal_lev;
  u_int8_t noise_lev;
  u_int8_t RERL;
  u_int8_t Gmin;
  u_int8_t R_fact;
  u_int8_t ext_R_fact;
  u_int8_t MOS_LQ;
  u_int8_t MOS_CQ;
#if __BYTE_ORDER == __BIG_ENDIAN
  u_int8_t PLC:2;
  u_int8_t JB_adapt:2;
  u_int8_t JB_rate:4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t JB_rate:4;
  u_int8_t JB_adapt:2;
  u_int8_t PLC:2;
#endif  
  u_int8_t RESERVED;
  u_int16_t JB_nom;
  u_int16_t JB_max;
  u_int16_t JB_abs_max;
};

// Macros to get information from the XR block
#define rtcp_header_get_id(xr)           ntohl((xr)->id)
#define rtcp_header_get_loss(xr)         (xr)->loss_rate
#define rtcp_header_discard(xr)          (xr)->discard_rate
#define rtcp_header_burst_rate(xr)       (xr)->burst_rate
#define rtcp_header_gap_rate(xr)         (xr)->gap_rate
#define rtcp_header_burst_duration(xr)   (xr)->burst_duration
#define rtcp_header_gap_duration(xr)     (xr)->gap_duration
#define rtcp_header_round_trip_del(xr)   ntohs((xr)->round_trip_delay)
#define rtcp_header_end_sys_delay(xr)    ntohs((xr)->end_sys_delay)
#define rtcp_header_signal_lev(xr)       (xr)->signal_lev
#define rtcp_header_noise_lev(xr)        (xr)->noise_lev
#define rtcp_header_RERL(xr)             (xr)->RERL
#define rtcp_header_Gmin(xr)             (xr)->Gmin
#define rtcp_header_Rfact(xr)            (xr)->R_fact
#define rtcp_header_ext_Rfact(xr)        (xr)->ext_R_fact
#define rtcp_header_MOS_LQ(xr)           (xr)->MOS_LQ
#define rtcp_header_MOS_CQ(xr)           (xr)->MOS_CQ
#define rtcp_header_PLC(xr)              (xr)->PLC
#define rtcp_header_JB_adapt(xr)         (xr)->JB_adapt
#define rtcp_header_JB_rate(xr)          (xr)->JB_rate
#define rtcp_header_JB_nom(xr)           ntohs((xr)->JB_nom)
#define rtcp_header_JB_max(xr)           ntohs((xr)->JB_max)
#define rtcp_header_JB_abs_max(xr)       ntohs((xr)->JB_abs_max)

// RTCP-XR packet
struct rtcp_xr_t
{
  struct rtcp_header_t header;
  u_int32_t ssrc;
  struct rtcp_xr_header_t xr_header;
  struct rtcp_xr_block_t block;
};

/** Functions for the dissection **/

// Check version
int check_rtcpxr_version(char *packet, int size_payload);
// Parse packet and fill JSON buffer
int parse_rtcpxr(u_char *packet, int size_payload, char *json_buffer, int buffer_len);

#endif
