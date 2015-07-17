/*
 * parser_sip.h
 *
 *  Created on: Sep 1, 2014
 *      Author: shurik
 */

#ifndef _PARSE_SIP_H
#define _PARSE_SIP_H

#include "src/api.h"

int set_hname(str *hname, int len, char *s);
int parse_message(char *message, unsigned int blen, unsigned int* bytes_parsed, sip_msg_t *psip, unsigned int type);
int parseSdp(char *body, sip_msg_t *psip);
int parseSdpCLine(miprtcp_t *mp, char *data, int len);
int parseSdpALine(miprtcp_t *mp, char *data, int len);
int parseSdpMLine(miprtcp_t *mp, char *data, int len);
int light_parse_message(char *message, unsigned int blen, unsigned int* bytes_parsed, sip_msg_t *psip);
int check_len_message(unsigned char *message, unsigned int blen);
int check_sip_message(unsigned char *message, unsigned int blen);
int w_sip_has_sdp(msg_t *_m);


bool getUser(str *user, str *domain, char *s, int len);
bool getTag(str *hname, char *uri, int len);



extern char* global_config_path;

#endif /* _PARSE_SIP_H */


