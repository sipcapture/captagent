/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Holger Hans Peter Freyther <help@moiji-mobile.com>
 *  (C) Homer Project 2016 (http://www.sipcapture.org)
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2019 (http://www.sipcapture.org)
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

#include <captagent/api.h>
#include <captagent/structure.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>
#include <captagent/xmlread.h>

#include <sys/types.h>
#include <limits.h>

#include "isup_parsed.h"

#define MTP_L2		0
#define SCTP_M2UA_PPID	2
#define SCTP_M3UA_PPID	3
#define SCTP_M2PA_PPID	5

#define M2UA_MSG	6
#define M2UA_DATA	1
#define M2UA_IE_DATA	0x0300
#define M2PA_CLASS	11
#define M2PA_DATA	1

#define M3UA_MSG	1
#define M3UA_DATA	1
#define M3UA_IE_DATA	0x0210

#define MTP_ISUP	0x05

/* hep defines */
#define HEP_M2UA                0x08
#define HEP_M3UA                0x09
#define HEP_M2PA                0x0d

#define DLT_MTP2		140

//54
#define PROTO_M2UA_JSON		0x36

struct mtp_level_3_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t ser_ind : 4,
		spare : 2,
		ni : 2;
	uint32_t dpc : 14,
		opc : 14,
		sls : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ni : 2,
		spare : 2,
		ser_ind : 4;
	uint32_t sls : 4,
		opc : 14,
		dpc : 14;
#else
	#error "Unknown endian type"
#endif
	uint8_t data[0];
} __attribute__((packed));

struct m3ua_protocol_data {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t opc;
	uint32_t dpc;
	uint8_t ser_ind;
	uint8_t ni;
	uint8_t mp;
	uint8_t sls;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t sls;
	uint8_t mp;
	uint8_t ni;
        uint8_t ser_ind;
        uint32_t dpc;
        uint32_t opc;
#else
	#error "Unknown endian type"
#endif
	uint8_t data[0];
} __attribute__((packed));

static int ss7_parse_isup(msg_t *, char *, char *);
static int ss7_parse_isup_to_json(msg_t *, char *, char *);
static int w_isup_to_json(msg_t *, char *, char *);
static int ss7_load_module(xml_node *config);
static int ss7_unload_module(void);
static int ss7_description(char *description);
static int ss7_statistic(char *buf, size_t len);
static uint64_t ss7_serial_module(void);
static void free_module_xml_config();
static int load_module_xml_config();
static int free_profile(unsigned int idx);

#define MAX_PROTOCOLS 10
profile_protocol_t profile_protocol[MAX_PROTOCOLS];

char correlation[100];
bool enableCorrelation = FALSE;
static const char *isup_last = NULL;
static srjson_doc_t *isup_json = NULL;
static uint64_t module_serial = 0;
xml_node *module_xml_config = NULL;
char *module_description = NULL;
unsigned int profile_size = 0;

extern char* global_config_path;


static cmd_export_t ss7_cmds[] = {
	{
		.name		= "parse_isup",
		.function	= ss7_parse_isup,
		.param_no	= 0,
		.flags		= 0,
		.fixup_flags	= 0,
	},
	{
		.name		= "parse_isup_to_json",
		.function	= ss7_parse_isup_to_json,
		.param_no	= 0,
		.flags		= 0,
		.fixup_flags	= 0,
	},
	{
		.name		= "isup_to_json",
		.function	= w_isup_to_json,
		.param_no	= 0,
		.flags		= 0,
		.fixup_flags	= 0,
	},
	{ 0, },
};

struct module_exports exports = {
	.name		= "protocol_ss7",
        .cmds		= ss7_cmds,
        .load_f		= ss7_load_module,
        .unload_f	= ss7_unload_module,
        .description_f	= ss7_description,
        .stats_f	= ss7_statistic,
        .serial_f	= ss7_serial_module,
};

static uint8_t *extract_from_m2ua(msg_t *msg, size_t *len)
{
	uint8_t *data;
	uint32_t data_len;

	if (msg->len < 8) {
		LERR("M2UA hdr too short %u", msg->len);
		return NULL;
	}
	data = msg->data;

	/* check the header */
	if (data[0] != 0x01) {
		LERR("M2UA unknown version number %d", data[0]);
		return NULL;
	}
	if (data[1] != 0x00) {
		LERR("M2UA unknown reserved fields %d", data[1]);
		return NULL;
	}
	if (data[2] != M2UA_MSG) {
		LDEBUG("M2UA unhandled message class %d", data[2]);
		return NULL;
	}
	if (data[3] != M2UA_DATA) {
		LDEBUG("M2UA not data msg but %d", data[3]);
		return NULL;
	}

	/* check the length */
	memcpy(&data_len, &data[4], sizeof(data_len));
	data_len = ntohl(data_len);
	if (msg->len < data_len) {
		LERR("M2UA data can't fit %u vs. %u", msg->len, data_len);
		return NULL;
	}

	/* skip the header */
	data += 8;
	data_len -= 8;
	while (data_len > 4) {
		uint16_t ie_tag, ie_len, padding;
		memcpy(&ie_tag, &data[0], sizeof(ie_tag));
		memcpy(&ie_len, &data[2], sizeof(ie_len));
		ie_tag = ntohs(ie_tag);
		ie_len = ntohs(ie_len);

		if (ie_len > data_len) {
			LERR("M2UA premature end %u vs. %u", ie_len, data_len);
			return NULL;
		}

		if (ie_tag != M2UA_IE_DATA)
			goto next;

		*len = ie_len - 4;
		return &data[4];

next:
		data += ie_len;
		data_len -= ie_len;

		/* and now padding... */
                padding = (4 - (ie_len % 4)) & 0x3;
		if (data_len < padding) {
			LERR("M2UA no place for padding %u vs. %u", padding, data_len);
			return NULL;
		}
		data += padding;
		data_len -= padding;
	}
	/* No data IE was found */
	LERR("M2UA no data element found");
	return NULL;
}

static uint8_t *extract_from_m3ua(msg_t *msg, size_t *len)
{
	uint8_t *data;
	uint32_t data_len;

	if (msg->len < 8) {
		LERR("M3UA hdr too short %u", msg->len);
		return NULL;
	}
	data = msg->data;

	/* check the header */
	if (data[0] != 0x01) {
		LERR("M3UA unknown version number %d", data[0]);
		return NULL;
	}
	if (data[1] != 0x00) {
		LERR("M3UA unknown reserved fields %d", data[1]);
		return NULL;
	}
	if (data[2] != M3UA_MSG) {
		LDEBUG("M3UA unhandled message class %d", data[2]);
		return NULL;
	}
	if (data[3] != M3UA_DATA) {
		LDEBUG("M3UA not data msg but %d", data[3]);
		return NULL;
	}

	/* check the length */
	memcpy(&data_len, &data[4], sizeof(data_len));
	data_len = ntohl(data_len);
	
	if (msg->len < data_len) {
		LERR("M3UA data can't fit %u vs. %u", msg->len, data_len);
		return NULL;
	}

	/* skip the header */
	data += 8;
	data_len -= 8;
	while (data_len > 4) {
		uint16_t ie_tag, ie_len, padding;
		memcpy(&ie_tag, &data[0], sizeof(ie_tag));
		memcpy(&ie_len, &data[2], sizeof(ie_len));
		ie_tag = ntohs(ie_tag);
		ie_len = ntohs(ie_len);

		if (ie_len > data_len) {
			LERR("M3UA premature end %u vs. %u", ie_len, data_len);
			return NULL;
		}
			
		if (ie_tag != M3UA_IE_DATA)
			goto next;

		*len = ie_len - 4;
		
		return &data[4];

next:
		data += ie_len;
		data_len -= ie_len;

		/* and now padding... */
                padding = (4 - (ie_len % 4)) & 0x3;
		if (data_len < padding) {
			LERR("M3UA no place for padding %u vs. %u", padding, data_len);
			return NULL;
		}
		data += padding;
		data_len -= padding;
	}
	/* No data IE was found */
	LERR("M3UA no data element found");
	return NULL;
}


static uint8_t *extract_from_mtp2(msg_t *msg, size_t *len)
{
	uint8_t *data;

	if (msg->len < 3) {
		LERR("MTP2 hdr too short %u", msg->len);
		return NULL;
	}

	data = msg->data;
	*len = msg->len - 3;
	return &data[3];
}


static uint8_t *extract_from_m2pa(msg_t *msg, size_t *len)
{
	uint8_t *data;
	uint32_t data_len;

	if (msg->len < 8) {
		LERR("M2PA hdr too short %u", msg->len);
		return NULL;
	}
	data = msg->data;

	/* check the header */
	if (data[0] != 0x01) {
		LERR("M2PA unknown version number %d", data[0]);
		return NULL;
	}
	if (data[1] != 0x00) {
		LERR("M2PA unknown reserved fields %d", data[1]);
		return NULL;
	}
	if (data[2] != M2PA_CLASS) {
		LDEBUG("M2PA unhandled message class %d", data[2]);
		return NULL;
	}
	if (data[3] != M2PA_DATA) {
		LDEBUG("M2PA not data msg but %d", data[3]);
		return NULL;
	}

	/* check the length */
	memcpy(&data_len, &data[4], sizeof(data_len));
	data_len = ntohl(data_len);
	if (msg->len < data_len) {
		LERR("M2PA data can't fit %u vs. %u", msg->len, data_len);
		return NULL;
	}

	/* skip the header */
	data += 8;
	data_len -= 8;

	/* BSN, FSN and then priority */
	if (data_len < 8) {
		LERR("M2PA no space for BSN/FSN %u\n", data_len);
		return NULL;
	}
	data += 8;
	data_len -= 8;
	if (data_len == 0)
		return NULL;
	else if (data_len < 1) {
		LERR("M2PA no space for prio %u\n", data_len);
		return NULL;
	}
	data += 1;
	data_len -= 1;

	*len = data_len;
	return data;
}

static uint8_t *extract_from_mtp(uint8_t *data, size_t *len, int *opc, int *dpc, int *type)
{
	struct mtp_level_3_hdr *hdr;

	*opc = INT_MAX;
	*dpc = INT_MAX;

	if (!data)
		return NULL;
	if (*len < sizeof(*hdr)) {
		LERR("MTP not enough space for mtp hdr %zu vs. %zu", *len, sizeof(*hdr));
		return NULL;
	}

	hdr = (struct mtp_level_3_hdr *) data;
	*opc = hdr->opc;
	*dpc = hdr->dpc;
	*type = hdr->ser_ind;
	*len -= sizeof(*hdr);
	
	return &hdr->data[0];
}

static uint8_t *extract_from_m3ua_mtp(uint8_t *data, size_t *len, int *opc, int *dpc, int *type)
{
	struct m3ua_protocol_data *hdr;

	*opc = INT_MAX;
	*dpc = INT_MAX;

	if (!data)
		return NULL;
	if (*len < sizeof(*hdr)) {
		LERR("MTP not enough space for mtp hdr %zu vs. %zu", *len, sizeof(*hdr));
		return NULL;
	}

	hdr = (struct m3ua_protocol_data *) data;
	*opc = ntohl(hdr->opc);
	*dpc = ntohl(hdr->dpc);
	*type = hdr->ser_ind;
	*len -= sizeof(*hdr);
	
	return &hdr->data[0];
}

static uint8_t *ss7_extract_payload(msg_t *msg, size_t *len, int *opc, int *dpc, int *type)
{

	switch (msg->sctp_ppid) {
	case SCTP_M2UA_PPID:
		msg->rcinfo.proto_type = 0x08;
		return extract_from_mtp(extract_from_m2ua(msg, len), len, opc, dpc, type);
		break;
	case SCTP_M3UA_PPID:
		msg->rcinfo.proto_type = 0x09;
		return extract_from_m3ua_mtp(extract_from_m3ua(msg, len), len, opc, dpc, type);
		break;				
	case SCTP_M2PA_PPID:
		msg->rcinfo.proto_type = 0x0d;		
		return extract_from_mtp(extract_from_m2pa(msg, len), len, opc, dpc, type);
	default:
		{
			/* FRAME MTPL2 */
			if(msg->rcinfo.ip_proto == DLT_MTP2)
		        {
        		        msg->rcinfo.proto_type = 0x08;
		                return extract_from_mtp(extract_from_mtp2(msg, len), len, opc, dpc, type);
	                }
		
			LDEBUG("SS7 SCTP PPID(%u) not known", msg->sctp_ppid);
			return NULL;
		}
	}
}

static int ss7_parse_isup(msg_t *msg, char *param1, char *param2)
{
	uint8_t *data;
	size_t len;
	int opc, dpc, type;

	data = ss7_extract_payload(msg, &len, &opc, &dpc, &type);
	if (!data)
		return -1;
	if (type != MTP_ISUP) {
		LDEBUG("ISUP service indicator not ISUP but %d", type);
		return -1;
	}

	/* data[0:1] is now the CIC and data[2] the type */
	return 1;
}

static int ss7_parse_isup_to_json(msg_t *msg, char *param1, char *param2)
{
	uint8_t *data;
	size_t len;
	int opc, dpc, type, rc;
	uint16_t cic;
	struct isup_state isup_state = { 0, };
        
	data = ss7_extract_payload(msg, &len, &opc, &dpc, &type);
	if (!data)
		return -1;
	if (type != MTP_ISUP) {
		LDEBUG("ISUP service indicator not ISUP but %d", type);
		return -1;		
	}

	free((char *) isup_last);
        srjson_DeleteDoc(isup_json);

        /* parse isup... */
        isup_state.json = srjson_NewDoc(NULL);
        if (!isup_state.json) {
                LERR("Failed to allocate JSON document\n");
                return -1;
        }
        
        isup_state.json->root = srjson_CreateObject(isup_state.json);
        if (!isup_state.json->root) {
                LERR("Failed to allocate JSON object\n");
                srjson_DeleteDoc(isup_state.json);
                return -1;
        }

        rc = isup_parse(data, len, &isup_state, &cic);
        if (rc != 0) {
                srjson_DeleteDoc(isup_state.json);
                return rc;
        }
        srjson_AddNumberToObject(isup_state.json, isup_state.json->root, "opc", opc);
        srjson_AddNumberToObject(isup_state.json, isup_state.json->root, "dpc", dpc);
        isup_last = srjson_PrintUnformatted(isup_state.json, isup_state.json->root);
        isup_json = isup_state.json;
        
        msg->rcinfo.proto_type = PROTO_M2UA_JSON;
        msg->len = strlen(isup_last);
        msg->data = isup_last;
        
        /* if the correlation_id has been enabled */
        if(enableCorrelation) 
        {
        	msg->rcinfo.correlation_id.len = snprintf(correlation, sizeof(correlation), "%d:%d:%d", opc <= dpc ? opc : dpc, opc > dpc ? opc : dpc, cic);
                msg->rcinfo.correlation_id.s = correlation;
	}

	/* data[0:1] is now the CIC and data[2] the type */
	return 1;
}

static int w_isup_to_json(msg_t *msg, char *param1, char *param2)
{
	/* data[0:1] is now the CIC and data[2] the type */
	return 1;
}


static int load_module_xml_config() {

	char module_config_name[500];
	xml_node *next;
	int i = 0;

	snprintf(module_config_name, 500, "%s/%s.xml", global_config_path, exports.name);

	if ((module_xml_config = xml_parse(module_config_name)) == NULL) {
		LERR("Unable to open configuration file: %s", module_config_name);
		return -1;
	}

	/* check if this module is our */
	next = xml_get("module", module_xml_config, 1);

	if (next == NULL) {
		LERR("wrong config for module: %s", exports.name);
		return -2;
	}

	for (i = 0; next->attr[i]; i++) {
			if (!strncmp(next->attr[i], "name", 4)) {
				if (strncmp(next->attr[i + 1], exports.name, strlen(exports.name))) {
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

static void free_module_xml_config() {

	/* now we are free */
	if(module_xml_config) xml_free(module_xml_config);
}



static int ss7_load_module(xml_node *config) {

	xml_node *params, *profile, *settings;
	char *key, *value = NULL;

	LNOTICE("Loaded %s", exports.name);

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

					if (!strncmp(key, "ignore", strlen("ignore"))) 
						profile_protocol[profile_size].ignore = strdup(value);
					else if (!strncmp(key, "dialog-type", strlen("dialog-type")))
						profile_protocol[profile_size].dialog_type = atoi(value);
					else if (!strncmp(key, "dialog-timeout", strlen("dialog-timeout")))
						profile_protocol[profile_size].dialog_timeout = atoi(value);
					else if (!strncmp(key, "generate-sid", strlen("generate-sid")) && !strncmp(value, "true", 4))
					         enableCorrelation = TRUE;
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

static int ss7_unload_module(void)
{

	LNOTICE("unloaded module protocol_ss7");

	unsigned int i = 0;

	for (i = 0; i < profile_size; i++) {

		free_profile(i);
	}
	
	return 0;
}

static int free_profile(unsigned int idx) {

        /*free profile chars **/

        if (profile_protocol[idx].name)  free(profile_protocol[idx].name);
        if (profile_protocol[idx].description) free(profile_protocol[idx].description);
        if (profile_protocol[idx].ignore) free(profile_protocol[idx].ignore);

        return 1;
}

static int ss7_description(char *description)
{
	return 1;
}

static int ss7_statistic(char *buf, size_t len)
{
	return 1;
}

static uint64_t ss7_serial_module(void)
{
	return module_serial;
}
