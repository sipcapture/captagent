/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2023 (http://www.sipcapture.org)
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

#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h>

#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "protocol_sip.h"
#include <captagent/log.h>

xml_node *module_xml_config = NULL;
char *module_name="protocol_sip";
uint64_t module_serial = 0;
char *module_description = NULL;
uint8_t regexpIndex = 0;

static int load_module(xml_node *config);
static int unload_module(void);
static int description(char *descr);
static int statistic(char *buf, size_t len);
static int free_profile(unsigned int idx);
static uint64_t serial_module(void);

#define MAX_REGEXP_INDEXES 10
pcre *pattern_match[MAX_REGEXP_INDEXES];
char *regexpIndexName[MAX_REGEXP_INDEXES];
unsigned int profile_size = 0;
extern char *customHeaderMatch;
extern int customHeaderLen;


static cmd_export_t cmds[] = {
        {"protocol_sip_bind_api",  (cmd_function)bind_api,   1, 0, 0, 0},
        {"msg_check", (cmd_function) w_proto_check_size, 2, 0, 0, 0 },
        {"sip_check", (cmd_function) w_sip_check, 2, 0, 0, 0 },
        {"header_check", (cmd_function) w_header_check, 2, 0, 0, 0 },
        {"header_regexp_match", (cmd_function) w_header_reg_match, 2, 0, 0, 0 },
        {"set_tag", (cmd_function) w_set_tag, 2, 0, 0, 0 },
        {"sip_is_method", (cmd_function) w_sip_is_method, 0, 0, 0, 0 },
        {"light_parse_sip", (cmd_function) w_light_parse_sip, 0, 0, 0, 0 },
        {"parse_sip", (cmd_function) w_parse_sip, 0, 0, 0, 0 },
        {"parse_full_sip", (cmd_function) w_parse_full_sip, 0, 0, 0, 0 },
        {"clog", (cmd_function) w_clog, 2, 0, 0, 0 },
        /* ================================ */
        {"sip_has_sdp", (cmd_function) w_sip_has_sdp, 0, 0, 0, 0 },
        {"is_flag_set", (cmd_function) w_is_flag_set, 2, 0, 0, 0 },
        {"send_reply", (cmd_function) w_send_reply_p, 2, 0, 0, 0 },
        {"send_reply", (cmd_function) w_send_reply, 0, 0, 0, 0 },
        {"send_rtcpxr_reply", (cmd_function) w_send_reply_p, 2, 0, 0, 0 },
        {"send_rtcpxr_reply", (cmd_function) w_send_reply, 0, 0, 0, 0 },
        {0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
		"protocol_sip",
        cmds,        /* Exported functions */
        load_module,    /* module initialization function */
        unload_module,
        description,
        statistic,
        serial_module
};

int bind_api(protocol_module_api_t* api)
{
	api->parse_only_f = parse_only_packet;
	api->reload_f = reload_config;
	api->module_name = module_name;

        return 0;

}

int w_is_flag_set(msg_t *_m, char *param1, char *param2)
{

   return (_m->flag[atoi(param1)] == atoi(param2)) ? 1 : -1;
}

int w_send_reply_p(msg_t *_m, char *param1, char *param2)
{
   return send_sip_reply(_m, atoi(param1), param2);
}

int w_send_reply(msg_t *_m)
{
   return send_sip_reply(_m, 200, "OK");
}

int w_parse_sip(msg_t *_m)
{
  return parse_sip(_m, 1);

}

int w_light_parse_sip(msg_t *_m)
{

    return light_parse_sip(_m);

}

int w_parse_full_sip(msg_t *_m)
{
    return parse_sip(_m, 2);
}


int w_clog(msg_t *_m, char *param1, char* param2)
{

    if(param1[0] == 'E' || param1[0] == 'e') LERR("%s\n", param2);
    else if(param1[0] == 'N' || param1[0] == 'n') LNOTICE("%s\n", param2);
    else LDEBUG("%s\n", param2);

    return 1;
}

int w_sip_is_method(msg_t *_m)
{
        if(_m->sip.isRequest) return 1;
        else return -1;
}


int w_sip_has_sdp(msg_t *_m)
{

        if(_m->sip.hasSdp) {

        	return 1;
        }

        return -1;
}


int w_set_tag(msg_t *_m, char *param1, char *param2)
{
    if( _m->rcinfo.tags.len > 0) {
        _m->rcinfo.tags.len++;
        _m->rcinfo.tags.s[_m->rcinfo.tags.len] = ';';
	}
    _m->rcinfo.tags.len += snprintf( _m->rcinfo.tags.s + _m->rcinfo.tags.len, sizeof( _m->rcinfo.tags.s) - _m->rcinfo.tags.len, "%s=%s", param1, param2);

    return 1;
}

int w_header_check(msg_t *_m, char *param1, char *param2)
{
    if(!strncmp("User-Agent", param1, strlen("User-Agent")) || strncmp("useragent", param1, strlen("useragent")))
    {
        if(startwith(&_m->sip.userAgent, param2))
        {
            return 1;
        }
    }
    else if(!strncmp("custom", param1, strlen("custom")))
    {
        if(_m->sip.hasCustomHeader && startwith(&_m->sip.customHeader, param2))
        {
            return 1;
        }
    }

    return -1;
}


int w_header_reg_match(msg_t *_m, char *param1, char *param2)
{
    uint8_t index = 0;

    if(param2 != NULL) index = get_pcre_index_by_name(param2);

    if(!strncmp("User-Agent", param1, strlen("User-Agent")) || strncmp("useragent", param1, strlen("useragent")))
    {
        if(_m->sip.userAgent.s && _m->sip.userAgent.len > 0)
        {
			if((re_match_func(pattern_match[index], _m->sip.userAgent.s, _m->sip.userAgent.len)) == 1) {
                LDEBUG(">>>> UserAgent SIP matched: [%.*s]", _m->sip.userAgent.len, _m->sip.userAgent.s);
                return 1;
			}
		}
    }
    else if(!strncmp("custom", param1, strlen("custom")))
    {
        if(_m->sip.customHeader.s && _m->sip.customHeader.len > 0)
        {
			if((re_match_func(pattern_match[index], _m->sip.customHeader.s, _m->sip.customHeader.len)) == 1) {
				LDEBUG(">>>> Custom SIP matched: [%.*s]", _m->sip.customHeader.len, _m->sip.customHeader.s);
                return 1;
			}
        }
    }
    else if(!strncmp("body", param1, strlen("body")) || !strncmp("raw", param1, strlen("raw")))
    {
        if(_m->data && _m->len > 0)
        {
			if((re_match_func(pattern_match[index], _m->data, _m->len)) == 1) {
				LDEBUG(">>>> Body SIP matched");
                return 1;
			}
        }
    }

    return -1;
}


int w_sip_check(msg_t *_m, char *param1, char *param2)
{

        int ret = -1;
        int intval = 0;


        if(!strncmp("method", param1, strlen("method")))
        {
             if(param2 != NULL && _m->sip.methodString.s && _m->sip.methodString.len > 0
                 && !strncmp(_m->sip.methodString.s, param2, strlen(param2)))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("rmethod", param1, strlen("rmethod")))
        {
             if(param2 != NULL && _m->sip.cSeqMethodString.s && _m->sip.cSeqMethodString.len > 0
                 && !strncmp(_m->sip.cSeqMethodString.s, param2, strlen(param2)))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("from_user_suffix", param1, strlen("from_user_suffix")))
        {
             if(endswith(&_m->sip.fromUser, param2))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("to_user_suffix", param1, strlen("to_user_suffix")))
        {
             if(endswith(&_m->sip.toUser, param2))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("from_user_prefix", param1, strlen("from_user_prefix")))
        {
             if(startwith(&_m->sip.fromUser, param2))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("to_user_prefix", param1, strlen("to_user_prefix")))
        {
             if(startwith(&_m->sip.toUser, param2))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("user_agent_prefix", param1, strlen("user_agent_prefix")))
        {
            if(startwith(&_m->sip.userAgent, param2))
            {
                ret = 1;
            }
        }
        else if(!strncmp("user_agent_suffix", param1, strlen("user_agent_suffix")))
        {
            if(endswith(&_m->sip.userAgent, param2))
            {
                ret = 1;
            }
        }
        else if(!strncmp("response", param1, strlen("response")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->sip.responseCode ==  intval) ret = 1;
        }
        else if(!strncmp("response_gt", param1, strlen("response_gt")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->sip.responseCode >=  intval) ret = 1;
        }
        else if(!strncmp("response_lt", param1, strlen("response_lt")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->sip.responseCode <=  intval) ret = 1;
        }
        else {
            LERR("unknown variable [%s]\n", param1);
        }

        return ret;
}


int endswith(str *str, const char *suffix)
{
    if (!str->s || !suffix) return 0;
    if (str->len == 0) return 0;
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  str->len) return 0;
    return strncmp(str->s + str->len - lensuffix, suffix, lensuffix) == 0;
}

int startwith(str *str, const char *suffix)
{
    if (!str->s || !suffix) return 0;
    if (str->len == 0) return 0;
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  str->len) return 0;
    return strncmp(str->s, suffix, lensuffix) == 0;
}

int send_sip_reply(msg_t *_m, int code, char *description)
{
        int n = 0;
	struct sockaddr_in cliaddr;
	char reply[1000];

        n = snprintf(reply, sizeof(reply), "SIP/2.0 %d %s\r\nVia: %.*s\r\nFrom: %.*s\r\nTo: %.*s;tag=%s\r\nContact: %.*s\r\nCall-ID: %.*s\r\nCseq: %.*s\r\n"
                                                          "User-Agent: Captagent\r\nContent-Length: 0\r\n\r\n",
                                                          code, description,
                                                          _m->sip.via.len, _m->sip.via.s,
                                                          _m->sip.fromURI.len, _m->sip.fromURI.s,
                                                          _m->sip.toURI.len, _m->sip.toURI.s,
                                                          "Fg2Uy0r7geBQF",
                                                          _m->sip.contactURI.len, _m->sip.contactURI.s,
                                                          _m->sip.callId.len, _m->sip.callId.s,
                                                          _m->sip.cSeq.len, _m->sip.cSeq.s
        );

        cliaddr.sin_family = _m->rcinfo.ip_family;
        cliaddr.sin_port = htons(_m->rcinfo.dst_port);
        cliaddr.sin_addr.s_addr = inet_addr(_m->rcinfo.dst_ip);

        sendto(*_m->rcinfo.socket, reply, n, 0, (struct sockaddr *)&cliaddr,sizeof(cliaddr));

        return 1;
}




int w_proto_check_size(msg_t *_m, char *param1, char *param2)
{

        int ret = -1;
        int intval = 0;

        if(!strncmp("size", param1, 4))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->len > intval) {
                  ret = 1;
             }
        }
        else if(!strncmp("src_ip", param1, strlen("src_ip")))
        {
             if(param2 != NULL && !strncmp(_m->rcinfo.src_ip, param2, strlen(param2)))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("source_ip", param1, strlen("source_ip")))
        {
             if(param2 != NULL && !strncmp(_m->rcinfo.src_ip, param2, strlen(param2)))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("destination_ip", param1, strlen("destination_ip")))
        {
             if(param2 != NULL && !strncmp(_m->rcinfo.dst_ip, param2, strlen(param2)))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("dst_ip", param1, strlen("dst_ip")))
        {
             if(param2 != NULL && !strncmp(_m->rcinfo.dst_ip, param2, strlen(param2)))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("any_ip", param1, strlen("any_ip")))
        {
             if(param2 != NULL
             		&& (!strncmp(_m->rcinfo.src_ip, param2, strlen(param2))
             		|| !strncmp(_m->rcinfo.dst_ip, param2, strlen(param2))))
             {
                    ret = 1;
             }
        }
        else if(!strncmp("src_port", param1, strlen("src_port")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->rcinfo.src_port ==  intval) ret = 1;
        }
        else if(!strncmp("src_port_gt", param1, strlen("src_port_gt")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->rcinfo.src_port >=  intval) ret = 1;
        }
        else if(!strncmp("src_port_lt", param1, strlen("src_port_lt")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->rcinfo.src_port <=  intval) ret = 1;
        }
        else if(!strncmp("dst_port", param1, strlen("dst_port")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->rcinfo.dst_port ==  intval) ret = 1;
        }
        else if(!strncmp("dst_port_gt", param1, strlen("dst_port_gt")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->rcinfo.dst_port >=  intval) ret = 1;
        }
        else if(!strncmp("dst_port_lt", param1, strlen("dst_port_lt")))
        {
             if(param2 != NULL) intval = atoi(param2);
             if(_m->rcinfo.dst_port <=  intval) ret = 1;
        }
        else {
            LERR("unknown variable [%s]\n", param1);
        }

        return ret;
}


int reload_config (char *erbuf, int erlen) {

	char module_config_name[500];
	xml_node *config = NULL;

	LNOTICE("reloading config for [%s]", module_name);

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, module_name);

	if(xml_parse_with_report(module_config_name, erbuf, erlen)) {
		unload_module();
		load_module(config);
		return 1;
	}

	return 0;
}

int parse_sip(msg_t *msg, unsigned int type) {

	int ret = -1;

	stats.received_packets_total++;

	memset(&msg->sip, 0, sizeof(sip_msg_t));

	msg->sip.hasSdp = FALSE;
	msg->sip.hasTo = FALSE;
	msg->sip.hasPid = FALSE;
	msg->sip.hasFrom = FALSE;
	msg->sip.hasRuri = FALSE;
	msg->sip.hasToTag = FALSE;
	msg->sip.validMessage = FALSE;

	/* check if this is real SIP */
	if (!isalpha(((char * )msg->data)[0])) {
		return -1;
	}

	msg->rcinfo.proto_type = PROTO_SIP;
	msg->parsed_data = NULL;

	if (parse_packet(msg, &msg->sip, type)) {

		ret = 1;
		msg->sip.validMessage = TRUE;
		stats.parsed_packets++;

	} else {

		LERR("SIP PARSE ERROR [%d]\n", ret);

		goto error;
	}

	stats.send_packets++;

	return ret;

	error: return -1;
}

int parse_packet(msg_t *msg, sip_msg_t *sipPacket, unsigned int type) {

	uint32_t bytes_parsed = 0;

	LDEBUG("SIP: [%.*s]\n", msg->len, msg->data);

	if (!parse_message(msg->data, msg->len,  &bytes_parsed,  sipPacket, type)) {
		LERR("bad parsing");
		return 0;
	}

	if (sipPacket->callId.len == 0) {
		LERR("sipPacket CALLID has 0 len");
		return 0;
	}

	if(sipPacket->hasVqRtcpXR) {
             msg->rcinfo.correlation_id.s = sipPacket->rtcpxr_callid.s;
             msg->rcinfo.correlation_id.len = sipPacket->rtcpxr_callid.len;
        }

	return 1;
}

int light_parse_sip(msg_t *msg) {

	int ret = -1;
	uint32_t bytes_parsed = 0;

	stats.received_packets_total++;

	memset(&msg->sip, 0, sizeof(sip_msg_t));

	msg->sip.hasSdp = FALSE;
	msg->sip.hasTo = FALSE;
	msg->sip.hasPid = FALSE;
	msg->sip.hasFrom = FALSE;
	msg->sip.hasRuri = FALSE;
	msg->sip.hasToTag = FALSE;

	/* check if this is real SIP */
	if (!isalpha(((char * )msg->data)[0])) {
		return -1;
	}

	msg->rcinfo.proto_type = PROTO_SIP;
	msg->parsed_data = NULL;


	if (!light_parse_message(msg->data, msg->len,  &bytes_parsed,  &msg->sip)) {
		LERR("bad parsing");
		return -1;
	}

	if (msg->sip.callId.len == 0) {
		LERR("sipPacket CALLID has 0 len");
		return -1;
	}

	stats.send_packets++;

	return ret;
}


int8_t re_match_func (pcre *pattern, char *data, uint32_t len)
{

    char escapeData[250];
    int escapeLen = 0, pcreExtRet = 0;
#ifdef USE_PCRE2
    pcre2_match_data *match_data;
#else
    int subStrVec[30];
#endif

    makeEscape(data, len, escapeData, 200);

    LDEBUG("Match function: [%s] Len:[%d]", escapeData, escapeLen);

    if(pattern && len > 0)
    {

#ifdef USE_PCRE2
        match_data = pcre2_match_data_create_from_pattern(pattern, NULL);
        pcreExtRet = pcre2_match(pattern, (PCRE2_SPTR)escapeData, strlen(escapeData), 0, 0, match_data, NULL);
        pcre2_match_data_free(match_data);

        if(pcreExtRet < 0)
        {
            switch (pcreExtRet) {
            case PCRE2_ERROR_NULL:
            case PCRE2_ERROR_BADOPTION:
            case PCRE2_ERROR_BADMAGIC:
            case PCRE2_ERROR_NOMEMORY:
                LDEBUG ("bad result of regexp match");
                break;
            case PCRE2_ERROR_NOMATCH:
                LDEBUG ("NOT MATCHED: [%d]\n", pcreExtRet);
                return -1;
            }

            LDEBUG ("NOT MATCHED: [%.*s] [%d]\n", len, data, pcreExtRet);

            return -1;
        }
        else {
            LDEBUG ("MATCHED: [%.*s]\n", len, data);
            return 1;
        }
#else
        pcreExtRet = pcre_exec(pattern, 0, escapeData, strlen(escapeData), 0, 0, subStrVec, 30);

        if(pcreExtRet < 0)
        {
            switch (pcreExtRet) {
            case PCRE_ERROR_NULL:
            case PCRE_ERROR_BADOPTION:
            case PCRE_ERROR_BADMAGIC:
            case PCRE_ERROR_UNKNOWN_NODE:
            case PCRE_ERROR_NOMEMORY:
                LDEBUG ("bad result of regexp match");
                break;
            case PCRE_ERROR_NOMATCH:
                LDEBUG ("NOT MATCHED: [%d]\n", pcreExtRet);
                return -1;
            }

            LDEBUG ("NOT MATCHED: [%.*s] [%d]\n", len, data, pcreExtRet);

            return -1;
        }
        else {
            LDEBUG ("MATCHED: [%.*s]\n", len, data);
            return 1;
        }
#endif
    }
    else if(pattern) {
        LDEBUG ("LEN BAD\n");
        return -1;
    }

    LDEBUG ("PATTERN BAD: [%.*s]\n", len, data);

    return -1;
}


int makeEscape(const char *s, int len, char *out, int max)
{
    int i = 0, y = 0;
    for(i = 0; i < len; i++)
    {
        if (s[i] == '\\' || s[i] == '\'')
        {
            out[y] = '\\';
            y++;
        }
        else if (s[i] == '+')
        {
            out[y] = '\\';
            y++;
        }

        out[y] = s[i];
        y++;

        if(y >= max) break;
    }

    out[y]='\0';
    return 1;
}


int parse_only_packet(msg_t *msg, void* packet) {

	parse_packet(msg, (sip_msg_t *) packet, 1);

	return 1;
}


int set_value(unsigned int idx, msg_t *msg) {

    return 1;
}


uint8_t get_pcre_index_by_name(char *name) {

	unsigned int i = 0;

	if(regexpIndex == 1) return 0;

	for (i = 0; i < regexpIndex; i++) {

		if(!strncmp(regexpIndexName[i], name, strlen(regexpIndexName[i]))) {
			return i;
		}
	}

	return -1;
}


profile_protocol_t* get_profile_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return &profile_protocol[0];

	for (i = 0; i < profile_size; i++) {

		if(!strncmp(profile_protocol[i].name, name, strlen(profile_protocol[i].name))) {
			return &profile_protocol[1];
		}
	}

	return NULL;
}

unsigned int get_profile_index_by_name(char *name) {

	unsigned int i = 0;

	if(profile_size == 1) return 0;

	for (i = 0; i < profile_size; i++) {
		if(!strncmp(profile_protocol[i].name, name, strlen(profile_protocol[i].name))) {
			return i;
		}
	}
	return 0;
}


void free_regexp() {

	unsigned int i = 0;
	for (i = 0; i < profile_size; i++) {
		if(regexpIndexName[i]) free(regexpIndexName[i]);
#ifdef USE_PCRE2
		if(pattern_match[i]) pcre2_code_free(pattern_match[i]);
#else
		pcre_free(pattern_match[i]);
#endif
	}
}


int load_module_xml_config() {

	char module_config_name[500];
	xml_node *next;
	int i = 0;

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, module_name);

	if ((module_xml_config = xml_parse(module_config_name)) == NULL) {
		LERR("Unable to open configuration file: %s", module_config_name);
		return -1;
	}

	/* check if this module is our */
	next = xml_get("module", module_xml_config, 1);

	if (next == NULL) {
		LERR("wrong config for module: %s", module_name);
		return -2;
	}

	for (i = 0; next->attr[i]; i++) {
			if (!strncmp(next->attr[i], "name", 4)) {
				if (strncmp(next->attr[i + 1], module_name, strlen(module_name))) {
					return -3;
				}
			}
			else if (!strncmp(next->attr[i], "serial", 6)) {
				module_serial = atol(next->attr[i + 1]);
			}
			else if (!strncmp(next->attr[i], "description", 11)) {
				module_description = next->attr[i + 1];
			}
	}

	return 1;
}

void free_module_xml_config() {

	/* now we are free */
	if(module_xml_config) xml_free(module_xml_config);
}

/* modules external API */

static int load_module(xml_node *config) {
	xml_node *params, *profile, *settings;
	char *key, *value = NULL;

	LNOTICE("Loaded %s", module_name);

	load_module_xml_config();
	/* READ CONFIG */
	profile = module_xml_config;

	/* reset profile */
	profile_size = 0;

	while (profile) {

		profile = xml_get("profile", profile, 1);

		if (profile == NULL)
			break;

		if (!profile->attr[4] || strncmp(profile->attr[4], "enable", 6)) {
			goto nextprofile;
		}

		/* if not equals "true" */
		if (!profile->attr[5] || strncmp(profile->attr[5], "true", 4)) {
			goto nextprofile;
		}

		/* set values */
		profile_protocol[profile_size].name = strdup(profile->attr[1]);
		profile_protocol[profile_size].description = strdup(profile->attr[3]);
		profile_protocol[profile_size].serial = atoi(profile->attr[7]);
		profile_protocol[profile_size].dialog_type = 0;
		profile_protocol[profile_size].dialog_timeout = 180;

		/* SETTINGS */
		settings = xml_get("settings", profile, 1);

		if (settings != NULL) {

			params = settings;

			while (params) {

				params = xml_get("param", params, 1);
				if (params == NULL)
					break;

				if (params->attr[0] != NULL) {

					/* bad parser */
					if (strncmp(params->attr[0], "name", 4)) {
						LERR("bad keys in the config");
						goto nextparam;
					}

					key = params->attr[1];

					if (params->attr[2] && params->attr[3] && !strncmp(params->attr[2], "value", 5)) {
						value = params->attr[3];
					} else {
						value = params->child->value;
					}

					if (key == NULL || value == NULL) {
						LERR("bad values in the config");
						goto nextparam;

					}

					if (!strncmp(key, "ignore", 6))
						profile_protocol[profile_size].ignore = strdup(value);
					else if (!strncmp(key, "dialog-type", 11))
						profile_protocol[profile_size].dialog_type = atoi(value);
					else if (!strncmp(key, "dialog-timeout", 14))
						profile_protocol[profile_size].dialog_timeout = atoi(value);
                    else if (!strncmp(key, "custom-header", strlen("custom-header")))
					{
						customHeaderMatch = strdup(value);
						customHeaderLen = strlen(customHeaderMatch);
					}
					else if (!strncmp(key, "regexp-name", strlen("regex-name")))
					{
						if(regexpIndex < MAX_REGEXP_INDEXES) {
							regexpIndexName[regexpIndex] = strdup(value);
						}
					}
					else if (!strncmp(key, "regexp-value", strlen("regex-value")))
					{
						if(regexpIndex < MAX_REGEXP_INDEXES) {

#ifdef USE_PCRE2
							int errcode;
							PCRE2_SIZE erroffset;
							pattern_match[regexpIndex] = pcre2_compile(
								(PCRE2_SPTR)regexpIndexName[regexpIndex],
								PCRE2_ZERO_TERMINATED,
								pcre_options,
								&errcode,
								&erroffset,
								NULL);
							if (!pattern_match[regexpIndex]) {
								PCRE2_UCHAR buffer[256];
								pcre2_get_error_message(errcode, buffer, sizeof(buffer));
								LERR("pattern_match I:[%d] compile failed: %s\n", regexpIndex, buffer);
							}
							else regexpIndex++;
#else
							pattern_match[regexpIndex] = pcre_compile (regexpIndexName[regexpIndex], pcre_options, (const char **) &re_err, &err_offset, 0);
                            if (!pattern_match[regexpIndex]) {
                                LERR("pattern_match I:[%d] compile failed: %s\n", regexpIndex, re_err);
                            }
                            else regexpIndex++;
#endif
						}
					}
				}

            nextparam: params = params->next;

			}
		}

		profile_size++;

    nextprofile: profile = profile->next;
	}

	/* free it */
	free_module_xml_config();

	return 0;
}

static int unload_module(void)
{

	LNOTICE("unloaded module %s\n", module_name);

	unsigned int i = 0;

	for (i = 0; i < profile_size; i++) {

		free_profile(i);
	}

	 /* Close socket */
       //pcap_close(sniffer_proto);

    return 0;
}

static uint64_t serial_module(void)
{
	 return module_serial;
}


static int free_profile(unsigned int idx) {

	/*free profile chars **/

	if (profile_protocol[idx].name)	 free(profile_protocol[idx].name);
	if (profile_protocol[idx].description) free(profile_protocol[idx].description);
	if (profile_protocol[idx].ignore) free(profile_protocol[idx].ignore);

	return 1;
}


static int description(char *descr)
{
    LNOTICE("Loaded description");
    descr = module_description;
    return 1;
}


static int statistic(char *buf, size_t len)
{
	int ret = 0;

    ret += snprintf(buf+ret, len-ret, "Total received: [%" PRId64 "]\r\n", stats.received_packets_total);
    ret += snprintf(buf+ret, len-ret, "Parsed packets: [%" PRId64 "]\r\n", stats.parsed_packets);
    ret += snprintf(buf+ret, len-ret, "Total sent: [%" PRId64 "]\r\n", stats.send_packets);

    return 1;
}
