/**
   Header containing macros and struct for tls/ssl session
   
   Author: 2016-2017 Michele Campus <fci1908@gmail.com>
   (C) Homer Project 2012-2017 (http://www.sipcapture.org)
   
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
#include <sys/types.h>
#include <net/ethernet.h>
#include "structures.h"
#include "decription.h"

#define JSON_BUFFER_LEN 5000

/****************************************************
 *  NOTE:
 *  The headers in this module follow the RFC 5246
 *  and the pcap analyzed to have a real conformity
 *  from theory and real traffic.
****************************************************/


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
   SSL 3.0                   3,0  0x0300
   TLS 1.0                   3,1  0x0301
   TLS 1.1                   3,2  0x0302
   TLS 1.2                   3,3  0x0303
**/

// header tls/ssl (5 byte)
struct header_tls_record
{
  u_int8_t  type;
  u_int16_t version;
  u_int16_t len;
} __attribute__ ((__packed__));


/**
   The following headers are importat to decode and extract handshake.
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
} __attribute__ ((__packed__));

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
  //u_int8_t * dist_name;
} __attribute__ ((__packed__));


// CLIENT KEY EXCHANGE 
struct client_key_exch {
  u_int8_t p_len;
  u_int8_t * p_data;
} __attribute__ ((__packed__));

/**
   Function to dissect a TLS packet
**/
int parse_tls(char ** payload,
	      int size_payload,
	      char json_buffer[],
	      int buffer_len,
	      u_int8_t ip_family,
	      u_int16_t src_port,
	      u_int16_t dst_port,
	      u_int8_t proto_id_l3,
	      struct Flow_key * flow_key);


/**
   Function to read FILE and return string
**/
char * read_file(char *name) {
  FILE *file;
  unsigned long fileLen;
  char *buffer;
  
  // Open file
  file = fopen(name, "rb");
  if (!file) {
    fprintf(stderr, "Unable to open file %s", name);
    return NULL;
  }
  
  // Get file length
  fseek(file, 0, SEEK_END);
  fileLen = ftell(file);
  fseek(file, 0, SEEK_SET);
  
  // Allocate memory
  buffer = (char *) malloc(fileLen + 1);
  if (!buffer) {
    fprintf(stderr, "Memory error!");
    fclose(file);
    return NULL;
  }
  
  // Read file contents into buffer
  fread(buffer, fileLen, 1, file);
  fclose(file);
  
  return buffer;
  
}

#endif
