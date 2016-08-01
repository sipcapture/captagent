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

#ifndef _RTCP_PARSER_H
#define _RTCP_PARSER_H

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>

#define SENDER_REPORT_JSON "\"sender_information\":{\"ntp_timestamp_sec\":%u,\"ntp_timestamp_usec\":%u,\"octets\":%u,\"rtp_timestamp\":%u, \"packets\":%u},"
#define REPORT_BLOCK_JSON "\"ssrc\":%u,\"type\":%u, \"report_blocks\":[{\"source_ssrc\":%u,\"highest_seq_no\":%u,\"fraction_lost\":%u,\"ia_jitter\":%u,\
\"packets_lost\":%u,\"lsr\":%u,\"dlsr\":%u}],\"report_count\":1,"

#define SDES_REPORT_BEGIN_JSON "\"sdes_ssrc\":%u,\"sdes_chunk_ssrc\":%u,\"sdes_information\": [ "
#define SDES_REPORT_INFO_JSON "{\"type\":%u,\"text\":\"%.*s\"},"
#define SDES_REPORT_END_JSON "],\"sdes_report_count\":%u,"


extern int send_sdes;

typedef enum {
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204,
} rtcp_type_t;


typedef struct _rtcp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rc:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:8;
#endif
	uint16_t length:16;
} rtcp_header_t;


#define rtcp_header_get_length(ch)       ntohs((ch)->length)

typedef struct _sender_info
{
	uint32_t ntp_timestamp_msw;
	uint32_t ntp_timestamp_lsw;
	uint32_t rtp_timestamp;
	uint32_t senders_packet_count;
	uint32_t senders_octet_count;
} sender_info_t;

#define sender_info_get_ntp_timestamp_msw(si) ((si)->ntp_timestamp_msw)
#define sender_info_get_ntp_timestamp_lsw(si) ((si)->ntp_timestamp_lsw)
#define sender_info_get_rtp_timestamp(si) ((si)->rtp_timestamp)
#define sender_info_get_packet_count(si) ntohl((si)->senders_packet_count)
#define sender_info_get_octet_count(si) ntohl((si)->senders_octet_count)

/*! \brief RTCP Report Block (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct _report_block
{

	uint32_t ssrc;
	uint32_t fl_cnpl;
	uint32_t ext_high_seq_num_rec;
	uint32_t interarrival_jitter;
	uint32_t lsr;
	uint32_t delay_snc_last_sr;
} report_block_t;

#define report_block_get_ssrc(rb) ntohl((rb)->ssrc)
#define report_block_get_fraction_lost(rb) (((uint32_t)ntohl((rb)->fl_cnpl))>>24)
static inline int32_t report_block_get_cum_packet_loss(const report_block_t * rb)
{
        int cum_loss = ntohl(rb->fl_cnpl);
        if (((cum_loss>>23)&1)==0) return 0x00FFFFFF & cum_loss;
        else return 0xFF000000 | (cum_loss-0xFFFFFF-1);
}
/* bug */
/* #define report_block_get_cum_packet_loss(rb) (((uint32_t)ntohl((rb)->fl_cnpl)) & 0xFFFFFF) */
#define report_block_get_high_ext_seq(rb) ntohl(((report_block_t*)(rb))->ext_high_seq_num_rec)
#define report_block_get_interarrival_jitter(rb) ntohl(((report_block_t*)(rb))->interarrival_jitter)
#define report_block_get_last_SR_time(rb) ntohl(((report_block_t*)(rb))->lsr)
#define report_block_get_last_SR_delay(rb) ntohl(((report_block_t*)(rb))->delay_snc_last_sr)


typedef struct _rtcp_sr
{
	rtcp_header_t header;
	uint32_t ssrc;
	sender_info_t si;
	report_block_t rb[1];
} rtcp_sr_t;

typedef struct _rtcp_rr
{
	rtcp_header_t header;
	uint32_t ssrc;
	report_block_t rb[1];
} rtcp_rr_t;

typedef struct _rtcp_sdes_chunk
{
	uint32_t csrc;
} rtcp_sdes_chunk_t;

typedef struct _rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char content[1];
} rtcp_sdes_item_t;

typedef struct _rtcp_sdes_t
{
	rtcp_header_t header;
	uint32_t ssrc;
	rtcp_sdes_chunk_t chunk;
	rtcp_sdes_item_t item;
} rtcp_sdes_t;

typedef struct _rtcp_bye
{
	rtcp_header_t header;
	uint32_t ssrc[1];
} rtcp_bye_t;

typedef struct _rtcp_app
{
	rtcp_header_t header;
	uint32_t ssrc;
	char name[4];
} rtcp_app_t;

#define sdes_chunk_get_csrc(c)  ntohl((c)->csrc)
#define sdes_chunk_item_get_len(item)  (item)->len
#define sdes_chunk_item_get_type(item) (item)->type

int capt_parse_rtcp(char *packet, int len, char *json_buffer, int buffer_len);
int check_rtcp_version (char *packet, int len);

#endif /* _RTCP_PARSER_H*/
