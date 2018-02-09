

#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "parser_sip.h"
#include <captagent/proto_sip.h>
#include <captagent/log.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


int
set_hname (str * hname, int len, char *s)
{

  char *end;

  if (hname->len > 0) {
    return 0;
  }

  end = s + len;
  for (; s < end; s++) {
    len--;
    if ((*s != ' ') && (*s != ':') && (*s != '\t')) {
      len--;
      break;
    }
  }

  hname->s = s;
  hname->len = len;
  return 1;
}

int
parseSdpMLine (miprtcp_t * mp, char *data, int len)
{

  enum state
  {
    ST_TYPE, ST_PORT, ST_AVP, ST_CODEC, ST_END
  };

  enum state st;
  int last_offset = 0, i;

  st = ST_TYPE;
  last_offset = 0;

  for (i = 0; i < len; i++) {

    switch (st) {

    case ST_TYPE:
      if (data[i] == ' ') {
	st = ST_PORT;
	last_offset = i;
      }
      break;

    case ST_PORT:
      if (data[i] == ' ') {
	st = ST_AVP;
	mp->media_port = atoi ((char *) data + last_offset);
	if (mp->rtcp_port == 0)
	  mp->rtcp_port = mp->media_port + 1;
	last_offset = i;
      }
      break;

    case ST_AVP:
      if (data[i] == ' ') {
	st = ST_CODEC;
	last_offset = i;
      }
      break;

    case ST_CODEC:
      if (data[i] == ' ') {
	st = ST_END;
	mp->prio_codec = atoi ((char *) data + last_offset);
	last_offset = i;
	return 1;
      }
      break;

    default:
      break;

    }
  }

  return 1;
}

int
parseSdpALine (miprtcp_t * mp, char *data, int len)
{

  enum state
  {
    ST_START, ST_PROTO, ST_TYPE, ST_IP, ST_END
  };

  enum state st;
  int last_offset = 0, i;

  st = ST_START;
  last_offset = 0;

  for (i = 0; i < len; i++) {

    switch (st) {

    case ST_START:
      if (data[i] == ' ') {
	mp->rtcp_port = atoi ((char *) data);
	st = ST_PROTO;
	last_offset = i;
      }
      break;

    case ST_PROTO:
      if (data[i] == ' ') {
	st = ST_TYPE;
	last_offset = i;
      }
      break;

    case ST_TYPE:
      if (data[i] == ' ') {
	st = ST_IP;
	last_offset = i;
      }
      break;

    case ST_IP:
      st = ST_END;
      mp->rtcp_ip.s = (char *) data + last_offset + 1;
      mp->rtcp_ip.len = len - last_offset - 3;
      st = ST_END;
      return 1;

      break;

    default:
      break;

    }
  }

  return 1;
}

int
parseSdpARtpMapLine (codecmap_t * cp, char *data, int len)
{

  enum state
  {
    ST_START, ST_NAME, ST_RATE, ST_END
  };

  enum state st;
  int last_offset = 0, i;

  st = ST_START;
  last_offset = 0;

  for (i = 0; i < len; i++) {

    switch (st) {

    case ST_START:
      if (data[i] == ' ') {
	cp->id = atoi ((char *) data);
	st = ST_NAME;
	last_offset = i;
      }
      break;

    case ST_NAME:
      if (data[i] == '/') {
	st = ST_RATE;
	snprintf (cp->name, sizeof (cp->name), "%.*s", (i - last_offset) - 1, data + last_offset + 1);
	last_offset = i;
      }
      break;

    case ST_RATE:
      st = ST_END;
      cp->rate = atoi ((char *) data + last_offset + 1);
      return 0;
    default:
      break;

    }
  }

  return 1;
}


int
parseSdpCLine (miprtcp_t * mp, char *data, int len)
{

  enum state
  {
    ST_NETTYPE, ST_ADDRTYPE, ST_CONNECTIONADRESS, ST_END
  };

  /* c=IN IP4 224.2.17.12 */

  enum state st;
  int last_offset = 0, i;

  st = ST_NETTYPE;
  last_offset = 0;

  for (i = 0; i < len; i++) {

    switch (st) {

    case ST_NETTYPE:
      if (data[i] == ' ') {
	st = ST_ADDRTYPE;
	last_offset = i;
      }
      break;

    case ST_ADDRTYPE:
      if (data[i] == ' ') {
	st = ST_CONNECTIONADRESS;
	last_offset = i;
      }

      break;
    case ST_CONNECTIONADRESS:
      mp->media_ip.s = (char *) data + last_offset + 1;
      mp->media_ip.len = len - last_offset - 3;
      if (mp->rtcp_ip.len == 0) {
	mp->rtcp_ip.len = mp->media_ip.len;
	mp->rtcp_ip.s = mp->media_ip.s;
      }
      st = ST_END;
      break;

    default:
      break;

    }
  }

  return 1;
}

int
parseVQRtcpXR (char *body, sip_msg_t * psip)
{

  char *c, *tmp;
  int offset, last_offset;

  c = body;
  last_offset = 0;
  offset = 0;


  for (; *c; c++) {
    /* END MESSAGE and START BODY */
    if (*c == '\r' && *(c + 1) == '\n') {	/* end of this line */
      //*c = '\0';
      last_offset = offset;
      offset = (c + 2) - body;
      tmp = (char *) (body + last_offset);

      if (strlen (tmp) < 4)
	continue;

      /* CallID: */
      if (*tmp == 'C' && *(tmp + 4) == 'I' && *(tmp + RTCPXR_CALLID_LEN) == ':') {
	set_hname (&psip->rtcpxr_callid, (offset - last_offset - RTCPXR_CALLID_LEN), tmp + RTCPXR_CALLID_LEN);
	break;
      }
    }
  }

  return 1;
}

bool
getUser (str * user, str * domain, char *s, int len)
{

  enum state
  {
    URI_BEGIN,
    URI_USER,
    URI_PARAM,
    URI_PASSWORD,
    URI_HOST_IPV6,
    URI_HOST,
    URI_HOST_END,
    URI_END,
    URI_OFF
  };

  enum state st;
  int first_offset = 0, host_offset = 0, i;
  bool foundUser = FALSE, foundHost = FALSE, foundAtValue = FALSE;
  st = URI_BEGIN;
  //host_end_offset = len;

  for (i = 0; i < len; i++) {

    switch (st) {

    case URI_BEGIN:

      if (s[i] == ':') {
	first_offset = i;
	st = URI_USER;
      }
      break;

    case URI_USER:
      //user_offset = i;
      if (s[i] == '@') {
	host_offset = i;
	st = URI_HOST;
	user->s = s + (first_offset + 1);
	user->len = (i - first_offset - 1);
	foundUser = TRUE;
	foundAtValue = TRUE;
      }
      else if (s[i] == ':') {
	st = URI_PASSWORD;
	user->s = s + (first_offset + 1);
	user->len = (i - first_offset - 1);
	foundUser = TRUE;
      }
      else if (s[i] == ';' || s[i] == '?' || s[i] == '&') {
	user->s = s + (first_offset + 1);
	user->len = (i - first_offset - 1);
	st = URI_PARAM;
	foundUser = TRUE;
      }
      break;

    case URI_PASSWORD:
      //password_offset = i;
      if (s[i] == '@') {
	host_offset = i;
	st = URI_HOST;
	foundAtValue = TRUE;
      }
      break;

    case URI_PARAM:
      if (s[i] == '@') {
	host_offset = i;
	st = URI_HOST;
	foundAtValue = TRUE;
      }
      if (s[i] == '>')
	st = URI_HOST_END;
      break;

    case URI_HOST:
      if (s[i] == '[')
	st = URI_HOST_IPV6;
      else if (s[i] == ':' || s[i] == '>' || s[i] == ';' || s[i] == ' ') {
	st = URI_HOST_END;
	domain->s = s + host_offset + 1;
	domain->len = (i - host_offset - 1);
	foundHost = TRUE;
      }
      break;

    case URI_HOST_IPV6:
      if (s[i] == ']') {
	domain->s = s + host_offset + 1;
	domain->len = (i - host_offset - 1);
	foundHost = TRUE;
	st = URI_HOST_END;
      }
      break;

    case URI_HOST_END:
      st = URI_END;
      break;

    default:
      i = len;
      break;
    }
  }

  if (st == URI_BEGIN) {
    return FALSE;
  }

  if (foundUser == FALSE)
    user->len = 0;
  else if (foundAtValue == FALSE && foundUser == TRUE) {

    domain->s = user->s;
    domain->len = user->len;

    /*and after set to 0 */
    user->len = 0;
  }
  if (foundUser == FALSE && foundHost == FALSE) {
    domain->s = s + first_offset + 1;
    domain->len = (len - first_offset);
  }

  return TRUE;
}

bool
getTag (str * hname, char *uri, int len)
{

  enum state
  {
    ST_TAG,
    ST_END,
    ST_OFF
  };

  enum state st;
  int first_offset = 0, last_offset = 0, i;

  st = ST_TAG;
  last_offset = len;

  for (i = 0; i < len; i++) {

    switch (st) {

    case ST_TAG:
      if (((i + 4) < len) && (uri[i] == 't' || uri[i] == 'T') && (uri[i + 2] == 'g' || uri[i + 2] == 'G') && uri[i + 3] == '=') {
	first_offset = i + 4;
	st = ST_END;
      }
      break;

    case ST_END:
      last_offset = i;
      if (uri[i] == ';')
	st = ST_OFF;
      break;

    default:
      break;

    }
  }

  if (st == ST_TAG) {
    return FALSE;
  }

  if ((last_offset - first_offset) < 5)
    return FALSE;

  set_hname (hname, (last_offset - first_offset), uri + first_offset);
  return TRUE;
}




int
parseSdp (char *body, sip_msg_t * psip)
{

  char *c, *tmp;
  int offset, last_offset, set_ip = 0;

  c = (char *) body;
  last_offset = 0;
  offset = 0;
  miprtcp_t *mp = NULL;
  codecmap_t *cdm = NULL;
  int i = 0, make_index = 0;

  /* memset */
  for (i = 0; i < MAX_MEDIA_HOSTS; i++) {
    memset (&psip->mrp[i], 0, sizeof (miprtcp_t));
    mp = &psip->mrp[i];
    mp->media_ip.len = 0;
    mp->media_ip.s = NULL;
    mp->rtcp_ip.len = 0;
    mp->rtcp_ip.s = NULL;
    mp->media_port = 0;
    mp->rtcp_port = 0;
    mp->prio_codec = -1;
		/*********/
    cdm = &psip->cdm[i];
    cdm->id = -1;
  }

  psip->cdm_count = 0;

  //m=audio 3000 RTP/AVP 8 0 18 101
  //m=image 49170 udptl t38

  for (; *c; c++) {
    /* END MESSAGE and START BODY */
    if (*c == '\r' && *(c + 1) == '\n') {	/* end of this line */
      //*c = '\0';
      last_offset = offset;
      offset = (c + 2) - body;
      tmp = (char *) (body + last_offset);

      if (strlen (tmp) < 4)
	continue;

      /* c=IN IP4 10.0.0.1 */
      if ((*tmp == 'c' && *(tmp + 1) == '=')) {
	mp = &psip->mrp[psip->mrp_size];
	parseSdpCLine (mp, tmp + 2, (offset - last_offset - 2));
	set_ip = 1;

	if (make_index == 1) {
	  psip->mrp_size++;
	  make_index = 0;
	}
	else {
	  make_index = 1;
	}
      }

      /* m=audio 3000 RTP/AVP 8 0 18 101 */
      if ((*tmp == 'm' && *(tmp + 1) == '=')) {

	if (set_ip == 1)
	  set_ip = 0;
	else {
	  if (psip->mrp_size > 0) {
	    psip->mrp[psip->mrp_size].media_ip.s = psip->mrp[psip->mrp_size - 1].media_ip.s;
	    psip->mrp[psip->mrp_size].media_ip.len = psip->mrp[psip->mrp_size - 1].media_ip.len;
	    mp = &psip->mrp[psip->mrp_size];
	  }
	}

	parseSdpMLine (mp, tmp + 2, (offset - last_offset - 2));

	psip->mrp_size++;

      }
      /* a=rtcp:53020 IN IP4 126.16.64.4 */
      else if ((*tmp == 'a' && *(tmp + 1) == '=')
	       && !memcmp (tmp + 2, "rtcp:", 5)) {
	if (mp == NULL) {
	  printf ("BAD SDP. Couldn't parse it [RTCP]!\n");
	  return 0;
	}

	parseSdpALine (mp, tmp + 7, (offset - last_offset - 7));
      }
       /**/
	/* a=rtcp:53020 IN IP4 126.16.64.4 */
	else if ((*tmp == 'a' && *(tmp + 1) == '=')
		 && !memcmp (tmp + 2, "rtpmap:", 7)) {

	if (psip->cdm_count >= MAX_MEDIA_HOSTS)
	  return 0;
	cdm = &psip->cdm[psip->cdm_count];
	parseSdpARtpMapLine (cdm, tmp + 9, (offset - last_offset - 7));
	//LDEBUG("JOPA: %d RATE: %d, %s, %d\n", psip->cdm_count, cdm->rate, cdm->name, cdm->id);
	psip->cdm_count++;
      }
    }

    if (psip->mrp_size > 10)
      break;
  }

  return 1;
}


method_t
getMethodType (char *s, int len)
{

  if ((*s == 'I' || *s == 'i') && !memcmp (s, INVITE_METHOD, INVITE_LEN)) {
    return INVITE;
  }
  else if ((*s == 'A' || *s == 'a') && !memcmp (s, ACK_METHOD, ACK_LEN)) {
    return ACK;
  }
  else if ((*s == 'R' || *s == 'r')
	   && !memcmp (s, REGISTER_METHOD, REGISTER_LEN)) {
    return REGISTER;
  }
  else if ((*s == 'B' || *s == 'b') && !memcmp (s, BYE_METHOD, BYE_LEN)) {
    return BYE;
  }
  else if ((*s == 'C' || *s == 'c') && !memcmp (s, CANCEL_METHOD, CANCEL_LEN)) {
    return CANCEL;
  }
  else if ((*s == 'P' || *s == 'p') && !memcmp (s, PRACK_METHOD, PRACK_LEN)) {
    return PRACK;
  }
  else if ((*s == 'O' || *s == 'o')
	   && !memcmp (s, OPTIONS_METHOD, OPTIONS_LEN)) {
    return OPTIONS;
  }
  else if ((*s == 'U' || *s == 'u') && !memcmp (s, UPDATE_METHOD, UPDATE_LEN)) {
    return UPDATE;
  }
  else if ((*s == 'R' || *s == 'r') && !memcmp (s, REFER_METHOD, REFER_LEN)) {
    return REFER;
  }
  else if ((*s == 'I' || *s == 'i') && !memcmp (s, INFO_METHOD, INFO_LEN)) {
    return INFO;
  }
  else if ((*s == 'P' || *s == 'p')
	   && !memcmp (s, PUBLISH_METHOD, PUBLISH_LEN)) {
    return PUBLISH;
  }
  else if ((*s == 'S' || *s == 's')
	   && !memcmp (s, SUBSCRIBE_METHOD, SUBSCRIBE_LEN)) {
    return SUBSCRIBE;
  }
  else if ((*s == 'M' || *s == 'm')
	   && !memcmp (s, MESSAGE_METHOD, MESSAGE_LEN)) {
    return MESSAGE;
  }
  else if ((*s == 'N' || *s == 'n') && !memcmp (s, NOTIFY_METHOD, NOTIFY_LEN)) {
    return NOTIFY;
  }
  else if ((*s == 'R' || *s == 'r')
	   && !memcmp (s, RESPONSE_METHOD, RESPONSE_LEN)) {
    return RESPONSE;
  }
  else if ((*s == 'S' || *s == 's')
	   && !memcmp (s, SERVICE_METHOD, SERVICE_LEN)) {
    return SERVICE;
  }
  else {
    return UNKNOWN;
  }
}


bool
splitCSeq (sip_msg_t * sipStruct, char *s, int len)
{

  char *pch;
  int mylen;

  if ((pch = strchr (s, ' ')) != NULL) {

    mylen = pch - s + 1;

    pch++;
    sipStruct->cSeqMethodString.s = pch;
    sipStruct->cSeqMethodString.len = (len - mylen);

    sipStruct->cSeqMethod = getMethodType (pch++, (len - mylen));
    sipStruct->cSeqNumber = atoi (s);

    return TRUE;
  }
  return FALSE;
}



int
parse_message (char *message, unsigned int blen, unsigned int *bytes_parsed, sip_msg_t * psip, unsigned int type)
{
  unsigned int new_len = blen;
  int header_offset = 0;
  char *pch, *ped;
  //bool allowRequest = FALSE;
  bool allowPai = FALSE;
  bool parseVIA = FALSE;
  bool parseContact = FALSE;

  if (blen <= 2)
    return 0;

  int offset = 0, last_offset = 0;
  char *c, *tmp;

  c = message;

  /* Request/Response line */
  for (; *c && c - message < new_len; c++) {
    if (*c == '\n' && *(c - 1) == '\r') {
      offset = (c + 1) - message;
      break;
    }
  }

  if (offset == 0) {		// likely Sip Message Body only...

    *bytes_parsed = c - message;
    return 0;
  }

  psip->responseCode = 0;


  tmp = (char *) message;

  if (!memcmp ("SIP/2.0 ", tmp, 8)) {
    psip->responseCode = atoi (tmp + 8);
    psip->isRequest = FALSE;

    // Extract Response code's reason
    char *reason = tmp + 12;
    for (; *reason; reason++) {
      if (*reason == '\n' && *(reason - 1) == '\r') {
	break;
      }
    }

    psip->reason.s = tmp + 12;
    psip->reason.len = reason - (tmp + 13);


  }
  else {
    psip->isRequest = TRUE;

    if (!memcmp (tmp, INVITE_METHOD, INVITE_LEN)) {
      psip->methodType = INVITE;
      //allowRequest = TRUE;
      allowPai = TRUE;
    }
    else if (!memcmp (tmp, ACK_METHOD, ACK_LEN))
      psip->methodType = ACK;
    else if (!memcmp (tmp, BYE_METHOD, BYE_LEN))
      psip->methodType = BYE;
    else if (!memcmp (tmp, CANCEL_METHOD, CANCEL_LEN))
      psip->methodType = CANCEL;
    else if (!memcmp (tmp, OPTIONS_METHOD, OPTIONS_LEN))
      psip->methodType = OPTIONS;
    else if (!memcmp (tmp, REGISTER_METHOD, REGISTER_LEN))
      psip->methodType = REGISTER;
    else if (!memcmp (tmp, PRACK_METHOD, PRACK_LEN))
      psip->methodType = PRACK;
    else if (!memcmp (tmp, SUBSCRIBE_METHOD, SUBSCRIBE_LEN))
      psip->methodType = SUBSCRIBE;
    else if (!memcmp (tmp, NOTIFY_METHOD, NOTIFY_LEN))
      psip->methodType = NOTIFY;
    else if (!memcmp (tmp, PUBLISH_METHOD, PUBLISH_LEN)) {
      psip->methodType = PUBLISH;
      /* we need via and contact */
      if (type == 2) {
	parseVIA = TRUE;
	parseContact = TRUE;
	//allowRequest = TRUE;
      }

    }
    else if (!memcmp (tmp, INFO_METHOD, INFO_LEN))
      psip->methodType = INFO;
    else if (!memcmp (tmp, REFER_METHOD, REFER_LEN))
      psip->methodType = REFER;
    else if (!memcmp (tmp, MESSAGE_METHOD, MESSAGE_LEN))
      psip->methodType = MESSAGE;
    else if (!memcmp (tmp, UPDATE_METHOD, UPDATE_LEN))
      psip->methodType = UPDATE;
    else {

      psip->methodType = UNKNOWN;
    }

    if ((pch = strchr (tmp + 1, ' ')) != NULL) {

      psip->methodString.s = tmp;
      psip->methodString.len = (pch - tmp);

      if ((ped = strchr (pch + 1, ' ')) != NULL) {
	psip->requestURI.s = pch + 1;
	psip->requestURI.len = (ped - pch - 1);

	LDEBUG ("INVITE RURI: %.*s\n", psip->requestURI.len, psip->requestURI.s);
	/* extract user */
	getUser (&psip->ruriUser, &psip->ruriDomain, psip->requestURI.s, psip->requestURI.len);

      }
    }
  }

  c = message + offset;
  int contentLength = 0;

  for (; *c && c - message < new_len; c++) {

    /* END of Request line and START of all other headers */
    if (*c == '\r' && *(c + 1) == '\n') {	/* end of this line */

      last_offset = offset;
      offset = (c + 2) - message;

      tmp = (message + last_offset);

      /* BODY */
      if (contentLength > 0 && (offset - last_offset) == 2) {

	if (psip->hasSdp) {
	  parseSdp (c, psip);
	}
	else if (psip->hasVqRtcpXR) {
	  parseVQRtcpXR (c, psip);
	}

	break;
      }

      if ((*tmp == 'i' && *(tmp + 1) == ':')
	  || ((*tmp == 'C' || *tmp == 'c')
	      && (*(tmp + 5) == 'I' || *(tmp + 5) == 'i')
	      && *(tmp + CALLID_LEN) == ':')) {

	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = CALLID_LEN;
	set_hname (&psip->callId, (offset - last_offset - CALLID_LEN), tmp + CALLID_LEN);
	continue;
      }
      /* Content-Length */
      if ((*tmp == 'l' && *(tmp + 1) == ':')
	  || ((*tmp == 'C' || *tmp == 'c')
	      && (*(tmp + 8) == 'L' || *(tmp + 8) == 'l')
	      && *(tmp + CONTENTLENGTH_LEN) == ':')) {

	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = CONTENTLENGTH_LEN;

	contentLength = atoi (tmp + header_offset + 1);
	continue;
      }
      else if ((*tmp == 'C' || *tmp == 'c')
	       && (*(tmp + 1) == 'S' || *(tmp + 1) == 's')
	       && *(tmp + CSEQ_LEN) == ':') {

	set_hname (&psip->cSeq, (offset - last_offset - CSEQ_LEN), tmp + CSEQ_LEN);
	splitCSeq (psip, psip->cSeq.s, psip->cSeq.len);
      }
      /* content type  Content-Type: application/sdp  CONTENTTYPE_LEN */
      else if (((*tmp == 'C' || *tmp == 'c') && (*(tmp + 7) == '-')
		&& (*(tmp + 8) == 't' || *(tmp + 8) == 'T')
		&& *(tmp + CONTENTTYPE_LEN) == ':')) {

	if (*(tmp + CONTENTTYPE_LEN + 1) == ' ')
	  header_offset = 1;
	else
	  header_offset = 0;

	if (!strncmp ((tmp + CONTENTTYPE_LEN + 13 + header_offset), "vq-rtcpxr", 9)) {
	  psip->hasVqRtcpXR = TRUE;
	}
	else if (!memcmp ((tmp + CONTENTTYPE_LEN + 13 + header_offset), "sdp", 3)) {
	  psip->hasSdp = TRUE;
	}
        else if (!memcmp ((tmp+CONTENTTYPE_LEN+header_offset+1), "multipart/mixed", 15)) {
          psip->hasSdp = TRUE;
        }

	continue;
      }
      else if (parseVIA && ((*tmp == 'V' || *tmp == 'v')
			    && (*(tmp + 1) == 'i' || *(tmp + 1) == 'i')
			    && *(tmp + VIA_LEN) == ':')) {
	set_hname (&psip->via, (offset - last_offset - VIA_LEN), tmp + VIA_LEN);
	continue;
      }
      else if (parseContact && ((*tmp == 'm' && *(tmp + 1) == ':') || ((*tmp == 'C' || *tmp == 'c')
								       && (*(tmp + 5) == 'C' || *(tmp + 5) == 'c')
								       && *(tmp + CONTACT_LEN) == ':'))) {
	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = CONTACT_LEN;

	set_hname (&psip->contactURI, (offset - last_offset - header_offset), tmp + header_offset);
	continue;
      }
      else if ((*tmp == 'f' && *(tmp + 1) == ':')
	  || ((*tmp == 'F' || *tmp == 'f')
	      && (*(tmp + 3) == 'M' || *(tmp + 3) == 'm')
	      && *(tmp + FROM_LEN) == ':')) {
	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = FROM_LEN;
	set_hname (&psip->fromURI, (offset - last_offset - FROM_LEN), tmp + FROM_LEN);
	psip->hasFrom = TRUE;
	
	if ( !(psip->fromURI.len == 0) && getTag (&psip->fromTag, psip->fromURI.s, psip->fromURI.len) ) {
	    psip->hasFromTag = TRUE;
	  }
	/* extract user */
	getUser (&psip->fromUser, &psip->fromDomain, psip->fromURI.s, psip->fromURI.len);

	continue;
      }
      else if ((*tmp == 't' && *(tmp + 1) == ':')
	       || ((*tmp == 'T' || *tmp == 't')
		   && *(tmp + TO_LEN) == ':')) {

	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = TO_LEN;
	if (set_hname (&psip->toURI, (offset - last_offset - header_offset), tmp + header_offset)) {
	  psip->hasTo = TRUE;
	  if ( !(psip->toURI.len == 0) && getTag (&psip->toTag, psip->toURI.s, psip->toURI.len) ) {
	    psip->hasToTag = TRUE;
	  }
	  /* extract user */
	  getUser (&psip->toUser, &psip->toDomain, psip->toURI.s, psip->toURI.len);
	}
	continue;
      }


      if (allowPai) {

	if (((*tmp == 'P' || *tmp == 'p')
	     && (*(tmp + 2) == 'P' || *(tmp + 2) == 'p')
	     && (*(tmp + 13) == 'i' || *(tmp + 13) == 'I')
	     && *(tmp + PPREFERREDIDENTITY_LEN) == ':')) {

	  set_hname (&psip->pidURI, (offset - last_offset - PPREFERREDIDENTITY_LEN), tmp + PPREFERREDIDENTITY_LEN);
	  psip->hasPid = TRUE;

	  /* extract user */
	  getUser (&psip->paiUser, &psip->paiDomain, psip->pidURI.s, psip->pidURI.len);

	  continue;
	}
	else if (((*tmp == 'P' || *tmp == 'p')
		  && (*(tmp + 2) == 'A' || *(tmp + 2) == 'a')
		  && (*(tmp + 13) == 'i' || *(tmp + 13) == 'I')
		  && *(tmp + PASSERTEDIDENTITY_LEN) == ':')) {

	  set_hname (&psip->pidURI, (offset - last_offset - PASSERTEDIDENTITY_LEN), tmp + PASSERTEDIDENTITY_LEN);
	  psip->hasPid = TRUE;

	  /* extract user */
	  getUser (&psip->paiUser, &psip->paiDomain, psip->pidURI.s, psip->pidURI.len);

	  continue;
	}
      }      
    }
  }

  return 1;
}

int
light_parse_message (char *message, unsigned int blen, unsigned int *bytes_parsed, sip_msg_t * psip)
{
  unsigned int new_len = blen;
  int header_offset = 0;

  psip->contentLength = 0;

  if (blen <= 2)
    return 0;

  int offset = 0, last_offset = 0;
  char *c, *tmp;

  c = message;

  for (; *c && c - message < new_len; c++) {

    /* END of Request line and START of all other headers */
    if (*c == '\r' && *(c + 1) == '\n') {	/* end of this line */

      last_offset = offset;
      offset = (c + 2) - message;

      tmp = (message + last_offset);

      /* BODY */
      if ((offset - last_offset) == 2) {
	psip->len = offset;

	if (psip->contentLength > 0) {
	  psip->len += psip->contentLength;
	}

	break;
      }

      if ((*tmp == 'i' && *(tmp + 1) == ':')
	  || ((*tmp == 'C' || *tmp == 'c')
	      && (*(tmp + 5) == 'I' || *(tmp + 5) == 'i')
	      && *(tmp + CALLID_LEN) == ':')) {
	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = CALLID_LEN;

	set_hname (&psip->callId, (offset - last_offset - CALLID_LEN), tmp + CALLID_LEN);
	continue;
      }
      else if ((*tmp == 'l' && *(tmp + 1) == ':')
	       || ((*tmp == 'C' || *tmp == 'c')
		   && (*(tmp + 8) == 'L' || *(tmp + 8) == 'l')
		   && *(tmp + CONTENTLENGTH_LEN) == ':')) {

	if (*(tmp + 1) == ':')
	  header_offset = 1;
	else
	  header_offset = CONTENTLENGTH_LEN;

	psip->contentLength = atoi (tmp + header_offset + 1);
	continue;
      }
    }
  }

  return 1;
}

int
check_len_message (unsigned char *message, unsigned int blen)
{

  unsigned char *c;
  unsigned int new_len = blen;
  unsigned int count = 0;

  c = message;

  if (message == NULL)
    return 0;

  for (; *c && c - message < new_len; c++) {

    if (*c == '\0') {
      break;
    }

    count++;
  }

  if (count != blen)
    return 0;

  return 1;
}

int
check_sip_message (unsigned char *message, unsigned int blen)
{
  int ret = 0;
  if (blen <= 2)
    return 0;

  char *tmp;

  tmp = (char *) message;

  if (!memcmp ("SIP/2.0 ", tmp, 8)) {
    ret = 1;
  }
  else {

    if (!memcmp (tmp, INVITE_METHOD, INVITE_LEN))
      ret = 1;
    else if (!memcmp (tmp, ACK_METHOD, ACK_LEN))
      ret = 1;
    else if (!memcmp (tmp, BYE_METHOD, BYE_LEN))
      ret = 1;
    else if (!memcmp (tmp, CANCEL_METHOD, CANCEL_LEN))
      ret = 1;
    else if (!memcmp (tmp, OPTIONS_METHOD, OPTIONS_LEN))
      ret = 1;
    else if (!memcmp (tmp, REGISTER_METHOD, REGISTER_LEN))
      ret = 1;
    else if (!memcmp (tmp, PRACK_METHOD, PRACK_LEN))
      ret = 1;
    else if (!memcmp (tmp, SUBSCRIBE_METHOD, SUBSCRIBE_LEN))
      ret = 1;
    else if (!memcmp (tmp, NOTIFY_METHOD, NOTIFY_LEN))
      ret = 1;
    else if (!memcmp (tmp, PUBLISH_METHOD, PUBLISH_LEN))
      ret = 1;
    else if (!memcmp (tmp, INFO_METHOD, INFO_LEN))
      ret = 1;
    else if (!memcmp (tmp, REFER_METHOD, REFER_LEN))
      ret = 1;
    else if (!memcmp (tmp, MESSAGE_METHOD, MESSAGE_LEN))
      ret = 1;
    else if (!memcmp (tmp, UPDATE_METHOD, UPDATE_LEN))
      ret = 1;
  }

  return ret;
}
