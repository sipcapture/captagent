/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Michele Campus <mcampus@qxip.net>
 *
 *  (C) QXIP BV 2012-2023 (http://www.sipcapture.org)
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

// Macro to check if the k-th bit is set (1) or not (0)
#define CHECK_BIT(var, k) ((var) & (1<<(k-1)))

/* Array of string definition for commands (used for convertion from enum to string) */
static const char* com_diam_base_arr[] = { "AC", "AS", "CE", "DW", "DP", "RA", "ST" };
static const char* com_diam_3gpp_arr[] = { "UA", "SA", "LI", "MA", "RT", "PP", "UD", "PU", "SN", "PN", "BI", "MP", "UL", "CL", "AI", "ID", "DS", "PE", "NO", "EC" };
static const char* com_diam_CC_arr[]   = { "CC" };
static const char* com_diam_sip_arr[]  = { "UA", "SA", "LI", "MA", "RT", "PP" };


/**
   Swap endian value of passed variable
   @param  number to be change
   @return number after endian swap
**/
static u_int32_t swap_endian(u_int32_t num) {

    // Swap endian (big to little) or (little to big)
    uint32_t z0, z1, z2, z3;
    uint32_t res;

    z0 = (num & 0x000000ff) << 24;
    z1 = (num & 0x0000ff00) << 8;
    z2 = (num & 0x00ff0000) >> 8;
    z3 = (num & 0xff000000) >> 24;
    res = z0 | z1 | z2 | z3;

    return res;
}

/**
   check if the passed variable is a diameter command
   @param  command code to check
   @return the num >= 0 associated to class of command (Base, 3GPP, SIP, CC) and #com_string associated to com_code
   @return -1 in case of invalid command
**/
static int check_command(u_int16_t com_code, const char* com_string) {

    int i, j;

    // check for CC command
    if(com_code == CCC) {
        snprintf(com_string, 3, "CC");
        return CC;
    }

    // check for DIAM_BASE command
    switch(com_code) {
     case CE: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[2]);
         return DIAM_BASE;
     }
     case RA: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[5]);
         return DIAM_BASE;
     }
     case AC: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[0]);
         return DIAM_BASE;
     }
     case AS: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[1]);
         return DIAM_BASE;
     }
     case ST: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[6]);
         return DIAM_BASE;
     }
     case DW: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[3]);
         return DIAM_BASE;
     }
     case DP: {
         snprintf(com_string, 3, "%s", com_diam_base_arr[4]);
         return DIAM_BASE;
     }
    }

    // check for 3GPP command
    for (i = UA, j = 0; i <= EC; i++, j++) {
        if(i == com_code) {
            if(i <= MP)
                snprintf(com_string, 3, "%s", com_diam_3gpp_arr[j]);
            else
                snprintf(com_string, 3, "%s", com_diam_3gpp_arr[j-4]);
            return _3GPP;
        }
    }

    // check for SIP command
    for (i = UAS, j = 0; i <= PPS; i++, j++) {
        if(i == com_code) {
            snprintf(com_string, 3, "%s", com_diam_sip_arr[j]);
            return SIP;
        }
    }

    return -1;
}

/**
   check if the passed variable is a diameter application ID
   @param  application ID to check
   @return the num >= 0 associated to class of command (Base, 3GPP, SIP, CC)
   @return -1 in case of invalid command
**/
static int check_appID(u_int32_t app_id) {

    int i;

    // check for CREDIT_CTRL app ID
    if(app_id == CREDIT_CTRL) return CC;
    // check for SIP command
    if(app_id == SIP_ID) return SIP;
    // check for DIAM_BASE command
    for (i = COMMON_MSG; i <= ERP; i++)
        if(i == app_id)
            return DIAM_BASE;
    // check for 3GPP command
    for (i = _3GPP_CX; i <= _3GPP_SLg; i++)
        if(i == app_id)
            return _3GPP;

    return -1;
}


/**
   Parse packet and fill JSON buffer
   @param  packet, size_payload, json_buffer, buffer_len
   @return >= 0 (Json length) if pkt is diameter and JSON buffer is created
   @return -1 in case of errors
**/
int diameter_dissector(const u_char *packet, int size_payload, char *json_buffer, int buffer_len)
{
    /* int offset = 0, ret; */
    int js_ret = 0;
    // header field var for JSON
    int classCom = -1, classApp = -1;
    u_int8_t flag;
    u_int16_t command;
    u_int32_t app_id;
    char type[20] = {0};
    char class[20] = {0};
    // string for JSON command and app IDs
    const char com_string[5] = {0};
    
    // check param
    if(!packet || size_payload == 0) {
        LERR("::Error:: parameters not valid\n");
        return -1;
    }

    // cast to diameter header
    struct diameter_header_t *diameter = (struct diameter_header_t *) packet;

    // check if the version is correct
    if(diameter->version != 0x01) {
        LERR("::Error:: Wrong version for Diameter protocol\n");
        return -1;
    }

    // check if Flag bit R is set to 0 or 1 (Answer or Request)
    flag = (CHECK_BIT(diameter->flags, 8)) ? REQ : ANSW;
    if(flag != REQ && flag != ANSW) {
        LERR("::Error:: Wrong flags value for Diameter protocol\n");
        return -1;
    }

    // check if the Command is correct
    command = diameter->com_code[2] + (diameter->com_code[1] << 8) + (diameter->com_code[0] << 8);
    classCom = check_command(command, com_string);
    if(classCom == UNK) {
        LERR("::Warning:: Command unknown for Diameter protocol\n");
        snprintf(com_string, (strlen("Unknown")+1), "Unknown");
    }

    // check if Applicaption ID is correct
    app_id = diameter->app_id;
    app_id = swap_endian(app_id);
    classApp = check_appID(app_id);
    if(classApp == UNK) {
        LERR("::Warning:: Command unknown for Diameter protocol\n");
        app_id = UNK;
    }

    /* check for the Class */
    if(classCom != classApp) {
        LERR("::Warning:: Class is different in Command and Application ID. Command or Application ID is unknown\n");
        /* return -1; */
    }

    // From int to string
    if(flag == REQ) snprintf(type, (strlen("Request")+1), "Request");
    else snprintf(type, (strlen("Answer")+1), "Answer");
    if(classCom == DIAM_BASE) snprintf(class, (strlen("Diameter")+1), "Diameter");
    else if(classCom == _3GPP) snprintf(class, (strlen("3GPP")+1), "3GPP");
    else if(classCom == SIP) snprintf(class, (strlen("SIP")+1), "SIP");
    else if(classCom == CC) snprintf(class, (strlen("Credit Control")+1), "Credit Control");
    else snprintf(class, (strlen("Unknown")+1), "Unknown");


    /*** CREATE JSON BUFFER ***/
    js_ret += snprintf(json_buffer, buffer_len,
                       DIAMETER_HEADER_JSON, class, type, com_string, app_id);


    // Calculate the length of payload from header field
    /* u_int16_t length = diameter->length[2] + (diameter->length[1] << 8) + (diameter->length[0] << 8); */

    return js_ret; // OK
}
