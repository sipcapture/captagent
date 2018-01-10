/**
   Header containing macros and struct for tls/ssl session
   
   Copyright (C) 2016-2017 Michele Campus <fci1908@gmail.com>
             (C) QXIP BV 2012-2017 (http://qxip.net)
   
   Homer capture agent is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version
   
   Homer capture agent is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
**/

#ifndef TLS_SSL_H_
#define TLS_SSL_H_

#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <net/ethernet.h>
#include "decryption.h"


#define T  0
#define F  1

#define DECR_LEN 5000

#define SERVER_NAME_LEN   256
#define TLS_HEADER_LEN      5
#define HANDSK_HEADER_LEN   4
#define RANDOM             32

// Version values
#define TLS1    0x0301
#define TLS11   0x0302
#define TLS12   0x0303

// Record Type values
enum {
  CHANGE_CIPHER_SPEC = 20,
  ALERT              = 21,
  HANDSHAKE          = 22,
  APPLICATION_DATA   = 23
} Record_Type;

// Handshake Type values
enum {
  HELLO_REQUEST       = 0,
  CLIENT_HELLO        = 1,
  SERVER_HELLO        = 2,
  NEW_SESSION_TICKET  = 4,
  CERTIFICATE         = 11,
  CERTIFICATE_REQUEST = 13,
  CERTIFICATE_STATUS  = 22,
  SERVER_KEY_EXCHANGE = 12,
  SERVER_DONE         = 14,
  CERTIFICATE_VERIFY  = 15,
  CLIENT_KEY_EXCHANGE = 16,
  FINISHED            = 20
} Handshake_Type;

// Client Certificate types for Certificate Request
enum {
  RSA_SIGN                  = 1,
  DSS_SIGN                  = 2,
  RSA_FIXED_DH              = 3,
  DSS_FIXED_DH              = 4,
  RSA_EPHEMERAL_DH_RESERVED = 5,
  DSS_EPHEMERAL_DH_RESERVED = 6,
  FORTEZZA_DMS_RESERVED     = 20
} Client_Certificate_Type;


// Chipher Suite availlable for decription
#define TLS_RSA_WITH_AES_256_GCM_SHA384   0x009d // work case
#define TLS_RSA_WITH_AES_128_GCM_SHA256   0x009c

#define TLS_RSA_WITH_AES_256_CBC_SHA256   0x003d
#define TLS_RSA_WITH_AES_128_CBC_SHA256   0x003c

#define TLS_RSA_WITH_AES_256_CBC_SHA      0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA      0x002f

//
#define CLI     1
#define SRV     2
#define CERT_S  11
#define CKE_PMS 16
#define CKE_MS  17


/**
   - Header tls/ssl Type values
   
   Record Type Values       dec      hex
   -------------------------------------
   CHANGE_CIPHER_SPEC        20     0x14
   ALERT                     21     0x15
   HANDSHAKE                 22     0x16
   APPLICATION_DATA          23     0x17
**/

/**
   Version Values            dec     hex
   -------------------------------------
   TLS 1.0                   3,1  0x0301
   TLS 1.1                   3,2  0x0302
   TLS 1.2                   3,3  0x0303
**/

// header tls (5 byte)
struct header_tls_record
{
  u_int8_t  type;
  u_int16_t version;
  u_int16_t len;
} PACK_OFF;


/**
   The following headers are important to decode and extract handshake.
   HANDSHAKE (value 22 or 0x16) is made by:

   - Client Hello           -------->   - Server Hello
                                          Certificate S
                                          Server Key Exchange
					  Server Hello Done
     Certificate C          <--------
     Client Key Exchange
     [Change Chipher Spec]
     Finished               -------->    [Change Chipher Spec]
                                         Finished
**/

/**** Handshake header ****/
struct handshake_header {
  u_int8_t msg_type;
  u_int8_t len[3];
} PACK_OFF;

/**
   Handshake Type Values    dec      hex
   -------------------------------------
   HELLO_REQUEST              0     0x00
   CLIENT_HELLO               1     0x01
   SERVER_HELLO               2     0x02
   CERTIFICATE               11     0x0b
   CERTIFICATE STATUS        22     0x16
   CERTIFICATE_REQUEST       13     0x0d
   CERTIFICATE_VERIFY        15     0x0f
   SERVER_KEY_EXCHANGE       12     0x0c
   CLIENT_KEY_EXCHANGE       16     0x10
   SERVER_DONE               14     0x0e
   FINISHED                  20     0x14
**/

// CERTIFICATE REQUEST
struct Cert_Req {
  u_int8_t type_count;
  u_int16_t types;
  u_int16_t dist_name_len;
};


// CLIENT KEY EXCHANGE 
struct client_key_exch {
  u_int8_t p_len;
  u_int8_t * p_data;
} __attribute__ ((__packed__));

/**
   Function to dissect a TLS packet
**/
int dissector_tls(const u_char *payload,
		  int size_payload,
		  char decrypted_buff[],
		  int msg_len,
		  u_int16_t src_port,
		  u_int16_t dst_port,
		  const u_int8_t proto_id_l3,
		  struct Flow *flow,
		  int KEY,
		  unsigned char *PVTkey);

#endif
