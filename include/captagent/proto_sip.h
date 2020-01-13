/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or
 * modify
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

#ifndef PROTO_SIP_H_
#define PROTO_SIP_H_

#define SIP_REQUEST 1
#define SIP_REPLY   2

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
#define RESPONSE_METHOD "RESPONSE"
#define SERVICE_METHOD "SERVICE"

#define SIP_VERSION "SIP/2.0"
#define SIP_VERSION_LEN 7

#define INVITE_LEN 6
#define CANCEL_LEN 6
#define ACK_LEN 3
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
#define UAC_LEN 10
#define RESPONSE_LEN 8
#define SERVICE_LEN 7

#define TO_LEN 2
#define PAI_LEN 19
#define FROM_LEN 4
#define EXPIRE_LEN 6
#define CALLID_LEN 7
#define CSEQ_LEN 4
#define VIA_LEN 3
#define PROXY_AUTH_LEN 19
#define WWW_AUTH_LEN 16
#define CONTACT_LEN 7
#define CONTENTLENGTH_LEN 14
#define CONTENTTYPE_LEN 12
#define USERAGENT_LEN 10
#define AUTHORIZATION_LEN 13
#define PPREFERREDIDENTITY_LEN 20
#define PASSERTEDIDENTITY_LEN 19

#define P_NGCP_CALLER_INFO_LEN 18
#define P_NGCP_CALLEE_INFO_LEN 18

#define XOIP_LEN 5
#define PRTPSTAT_LEN 10
#define XRTPSTAT_LEN 10
#define XRTPSTATISTICS_LEN 16
#define XSIEMENSRTPSTAT_LEN 19
#define XNGRTPSTAT_LEN 15
#define RTPRXTXSTAT_LEN 10

/* define for rtp stats type */
#define	 XRTPSTAT_TYPE 1
#define	 XRTPSTATISTICS_TYPE 2
#define	 PRTPSTAT_TYPE 3
#define	 RTPRXSTAT_TYPE 4
#define	 RTPTXSTAT_TYPE 5
#define	 XSIEMENSRTPSTATS_TYPE 6
#define	 XNGRTPSTATS_TYPE 7

#define MAX_MEDIA_HOSTS 20

#define RTCPXR_VQSESSIONREPORT_LEN 15
#define RTCPXR_CALLID_LEN 6
#define RTCPXR_SESSIONDESC_LEN 11
#define RTCPXR_JITTERBUFFER_LEN 12
#define RTCPXR_PACKETLOSS_LEN 10
#define RTCPXR_BURSTGAPLOSS_LEN 12
#define RTCPXR_DELAY_LEN 5
#define RTCPXR_QUALITYEST_LEN 10

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

typedef enum
{
		UNKNOWN = 0,
		CANCEL = 1,
		ACK = 2,
		INVITE = 3,
		BYE = 4,
		INFO = 5,
		REGISTER = 6,
		SUBSCRIBE = 7,
		NOTIFY = 8,
		MESSAGE = 9,
		OPTIONS = 10,
		PRACK = 11,
		UPDATE = 12,
		REFER = 13,
		PUBLISH = 14,
		RESPONSE = 15,
		SERVICE = 16
} method_t;


typedef struct _miprtcp {
        str media_ip;
        int media_port;
        str rtcp_ip;
        int rtcp_port;
        int prio_codec;
} miprtcp_t;

struct _codecmap;

typedef struct _codecmap {
        char name[120];
        int id;
        int rate;
        struct _codecmap* next;
} codecmap_t;

typedef struct sip_msg {

	unsigned int responseCode;
	bool isRequest;
	bool validMessage;
	method_t methodType;
	str methodString;
	int method_len;
	str callId;
	str reason;
	bool hasSdp;
	codecmap_t cdm[MAX_MEDIA_HOSTS];
        miprtcp_t mrp[MAX_MEDIA_HOSTS];
        int cdm_count;
	unsigned int mrp_size;
	unsigned int contentLength;
	unsigned int len;
	unsigned int cSeqNumber;
	bool hasVqRtcpXR;
	str rtcpxr_callid;
	str cSeqMethodString;
	method_t cSeqMethod;

	str cSeq;
	str via;
	str contactURI;
	/* extra */
	str ruriUser;
	str ruriDomain;
	str fromUser;
	str fromDomain;
	str toUser;
	str toDomain;
    str userAgent;
	str paiUser;
	str paiDomain;
	str requestURI;

    str customHeader;
	bool hasCustomHeader;

	str pidURI;
	bool hasPid;

	str fromURI;
	bool hasFrom;

	str toURI;
	bool hasTo;

	str ruriURI;
	bool hasRuri;

	str toTag;
	bool hasToTag;

	str fromTag;
	bool hasFromTag;

} sip_msg_t;



#endif /* PROTO_SIP_H_ */
