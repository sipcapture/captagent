/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Michele Campus <mcampus@qxip.net>
 *
 *  (C) QXIP BV 2012-2019 (http://www.sipcapture.org)
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

/* Definition of Diameter common info JSON */
#define DIAMETER_HEADER_JSON "\"diameter_info\": { [\"class\":\"%s\",\"type\":\"%s\",\"command\":\"%s\",\"app-ID\":%d] }"
#define JSON_BUFFER_LEN 5000

#define UNK      -1
// Flags
#define REQ       1
#define ANSW      0
// Classes
#define DIAM_BASE 0
#define _3GPP     1
#define SIP       2
#define CC        3

/** ############################## COMMANDS ############################## **/

/**
   A Command Code is used to determine the action that is to be taken for a particular message.
   Each command Request/Answer pair is assigned a command code.
**/
// Diameter protocol base
typedef enum {
    CE = 257,
    RA = 258,
    AC = 271,
    AS = 274,
    ST = 275,
    DW = 280,
    DP = 282
} com_diam_base_t;

// 3GPP
typedef enum {
    // Diameter base
    UA = 300,
    SA = 301,
    LI = 302,
    MA = 303,
    RT = 304,
    PP = 305,
    UD = 306,
    PU = 307,
    SN = 308,
    PN = 309,
    BI = 310,
    MP = 311,
    // 3GPP
    UL = 316,
    CL = 317,
    AI = 318,
    ID = 319,
    DS = 320,
    PE = 321,
    NO = 323,
    EC = 324
} com_diam_3gpp_t;

// Credit control
typedef enum {
    CCC = 272
} com_diam_CC_t;

// SIP
typedef enum {
    UAS  = 283,
    SAS  = 284,
    LIS  = 285,
    MAS  = 286,
    RTS  = 287,
    PPS  = 288
} com_diam_sip_t;


/** ############################## APPLICATION-ID ############################## **/

/**
   Application-ID is used to identify for which Diameter application the message is belong to.
   The application can be an authentication application, an accounting application, or a vendor-specific application.
**/
// Diameter protocol base (establishment/teardown/maintenance)
typedef enum {
    COMMON_MSG  = 0,
    NASREQ      = 1,
    BASE_ACC    = 3,
    CREDIT_CTRL = 4,         // CREDIT CONTROL
    SIP_ID      = 6,         // SIP
    QOS         = 9,
    NAT_CA      = 12,
    ERP         = 13
    /* add more if necessary */
} diam_app_id_t;

// 3GPP protocol
typedef enum {
    _3GPP_CX    = 16777216,  // IMS I/S-CSCF to HSS interface
    _3GPP_SH    = 16777217,  // VoIP/IMS SIP Application Server to HSS interface
    _3GPP_RE    = 16777218,
    _3GPP_WX    = 16777219,
    _3GPP_ZN    = 16777220,
    _3GPP_ZH    = 16777221,
    _3GPP_GQ    = 16777222,
    _3GPP_GMB   = 16777223,
    _3GPP_GX    = 16777224,
    _3GPP_GXoGY = 16777225,
    _3GPP_MM10  = 16777226,
    _3GPP_PR    = 16777230,
    _3GPP_RX    = 16777236,  // Policy and charging control
    _3GPP_S6t   = 16777345,   // Interface between SCEF and HSS
    _3GPP_Sta   = 16777250,
    _3GPP_S6ad  = 16777251,  // LTE Roaming signaling
    _3GPP_S13   = 16777252,  // Interface between EIR and MME
    _3GPP_SLg   = 16777255   // Location services
    /* add more if necessary */
} diam_3gpp_app_id_t;

/******** HEADER STRUCUTRES ********/

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

/**
   Functions for the dissection
**/
// Parse packet, check if it's Diameter and create JSON buffer with protocol information
int diameter_dissector(const u_char *packet, int size_payload, char *json_buffer, int buffer_len);

#endif
