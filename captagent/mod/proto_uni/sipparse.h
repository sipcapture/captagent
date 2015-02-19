/*
 *
 *  sipgrep - Monitoring tools
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2014 (http://www.sipcapture.org)
 *
 * Sipgrep is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * Sipgrep is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _SIPPARSE_H
#define _SIPPARSE_H

#include "src/api.h"  

#define SIP_REQUEST 1
#define SIP_REPLY   2

#define CANCEL "CANCEL"
#define ACK    "ACK"
#define INVITE "INVITE"

#define INVITE_LEN 6
#define ACK_LEN 3
#define CANCEL_LEN 6
#define BYE_LEN 3
#define INFO_LEN 4
#define REGISTER_LEN 8
#define SUBSCRIBE_LEN 9
#define NOTIFY_LEN 6
#define MESSAGE_LEN 7
#define OPTIONS_LEN 7
#define PRACK_LEN 5
#define UPDATE_LEN 6
#define REFER_LEN 5
#define PUBLISH_LEN 7
#define NOTIFY_LEN 6
#define OPTIONS_LEN 7
#define ACK_LEN 3
#define UAC_LEN 10

#define INVITE_METHOD "INVITE"
#define ACK_METHOD "ACK"
#define CANCEL_METHOD "CANCEL"
#define BYE_METHOD "BYE"
#define INFO_METHOD "INFO"
#define REGISTER_METHOD "REGISTER"
#define SUBSCRIBE_METHOD "SUBSCRIBE"
#define NOTIFY_METHOD "NOTIFY"
#define MESSAGE_METHOD "MESSAGE"
#define OPTIONS_METHOD "OPTIONS"
#define PRACK_METHOD "PRACK"
#define UPDATE_METHOD "UPDATE"
#define REFER_METHOD "REFER"
#define PUBLISH_METHOD "PUBLISH"
#define NOTIFY_METHOD "NOTIFY"
#define OPTIONS_METHOD "OPTIONS"
#define ACK_METHOD "ACK"
#define UNKNOWN_METHOD "UNKNOWN"


#define TO_LEN 2
#define PAI_LEN 19
#define FROM_LEN 4
#define CALLID_LEN 7
#define CSEQ_LEN 4
#define PROXY_AUTH_LEN 19
#define WWW_AUTH_LEN 16
#define CONTENTLENGTH_LEN 14
#define CONTENTTYPE_LEN 12
#define USERAGENT_LEN 10

#define INVITE_TRANSACTION 1
#define REGISTER_TRANSACTION 2
#define BYE_TRANSACTION 3
#define CANCEL_TRANSACTION 4
#define NOTIFY_TRANSACTION 5
#define OPTIONS_TRANSACTION 6
#define ACK_TRANSACTION 7
#define SUBSCRIBE_TRANSACTION 8
#define PUBLISH_TRANSACTION 9
#define UNKNOWN_TRANSACTION 99


#define CALL_CANCEL_TERMINATION 1
#define CALL_BYE_TERMINATION 2
#define CALL_MOVED_TERMINATION 3
#define CALL_BUSY_TERMINATION 4
#define CALL_AUTH_TERMINATION 5
#define CALL_4XX_TERMINATION 5
#define CALL_5XX_TERMINATION 6
#define CALL_6XX_TERMINATION 7

#define REGISTRATION_200_TERMINATION 1
#define REGISTRATION_AUTH_TERMINATION 2
#define REGISTRATION_4XX_TERMINATION 3
#define REGISTRATION_5XX_TERMINATION 4
#define REGISTRATION_6XX_TERMINATION 5

typedef struct _miprtcp {
        str media_ip;
        int media_port;
        str rtcp_ip;
        int rtcp_port;
} miprtcp_t;

typedef struct preparsed_sip {
      str callid;
      unsigned int is_method;
      unsigned int reply;
      unsigned int content_length;
      unsigned int cseq_num;
      unsigned int len;
      char *method;
      char *cseq_method;
      char reason[32];
      int has_sdp;
      int mrp_size;
      miprtcp_t mrp[10];
} preparsed_sip_t;

int set_hname(str *hname, int len, char *s);
int parse_message(char *body, unsigned int blen, unsigned int* bytes_parsed, struct preparsed_sip *psip);
int parseSdp(char *body, struct preparsed_sip *psip);
int parseSdpCLine(miprtcp_t *mp, char *data, int len);
int parseSdpALine(miprtcp_t *mp, char *data, int len);
int parseSdpMLine(miprtcp_t *mp, char *data, int len);
int light_parse_message(char *message, unsigned int blen, unsigned int* bytes_parsed, struct preparsed_sip *psip);
int check_len_message(unsigned char *message, unsigned int blen);
int check_sip_message(unsigned char *message, unsigned int blen);



#endif /* _SIPPARSE_H */
