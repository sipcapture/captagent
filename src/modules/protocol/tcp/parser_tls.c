/**
  This TLS dissector parse the pkt and extract the handshake (if present)
  
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
#ifdef USE_SSL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <time.h>
#include <math.h>
#include <unistd.h>


#include "protocol_tcp.h"
#include "parser_tls.h"
#include "structures.h"


#define SERVER_NAME_LEN   256
#define TLS_HEADER_LEN      5
#define HANDSK_HEADER_LEN   4
#define RANDOM             32

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

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

// Value used in dissection
#define SHA_256_RSA_ENCR   0x2a864886f70d01010b
#define RSA_ENCR           0x2a864886f70d010101

// Chipher Suite availlable for decription
#define TLS_RSA_WITH_AES_256_GCM_SHA384   0x009d
#define TLS_RSA_WITH_AES_128_GCM_SHA256   0x009c

#define TLS_RSA_WITH_AES_256_CBC_SHA256   0x003d
#define TLS_RSA_WITH_AES_128_CBC_SHA256   0x003c

#define TLS_RSA_WITH_AES_256_CBC_SHA      0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA      0x002f

#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ff
//

#define TRUE  0
#define FALSE 1

#define CLI     1
#define SRV     2
#define CERT_S  11
#define CKE     16


/** ###### FunctionS for the HASH TABLE (uthash) ###### **/
struct Hash_Table *HT_Flows = NULL; // # HASH TABLE


/**
   Function to read FILE and return string
**/
static unsigned char * read_file(char *name) {
  FILE *file;
  unsigned long fileLen;
  unsigned char *buffer;
  
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
  buffer = malloc(fileLen + 1);
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

/** ###### FunctionS to save and split the certificate(s) ###### **/

// SAVE CERTIFICATE AS .DER FILE
static void save_certificate_FILE(const unsigned char *cert, u_int16_t cert_len)
{
  FILE *fw;
  X509 *x_cert;
  char filename[cert_len];
  char buff[cert_len];
  struct tm *timeinfo;
  struct timeval tv;
  int millisec;
  
  x_cert = d2i_X509(NULL, &cert, cert_len);
  if (!x_cert) {
    fprintf(stderr, "Error on d21_X509 funtion\n");
    return;
  }

  gettimeofday(&tv, NULL);

  // trick to have milliseconds (thanks to a Stack Overflow answer)
  millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
  if(millisec >= 1000) {               // Allow for rounding up to nearest second
    millisec -= 1000;
    tv.tv_sec++;
  }

  timeinfo = localtime(&tv.tv_sec);

  memset(filename, 0, cert_len);
  memset(buff, 0, cert_len);
  struct stat st = {0};

  if (stat("certificates/", &st) == -1) {
    mkdir("certificates/", 0555);
  }

  /* save every file with the time certificate was catched */
  strftime(filename, sizeof(filename), "certificates/cert_%Y-%m-%d_%H-%M-%S-%%03u.der", timeinfo);
  snprintf(buff, sizeof(buff), filename, tv.tv_usec);
  
  if(!(fw = fopen(buff,"w"))) {
    fprintf(stderr, "Error on opening file descriptor fw\n");
    return;
  }

  // function to convert raw data (DER) to PEM certificate (good for parsing with openssl)
  i2d_X509_fp(fw, x_cert);

  // free cert and close file descriptor
  X509_free(x_cert);
  fclose(fw);
}

// SPLIT CERTIFICATE FUNCTION
/* static struct Certificate split_Server_Certificate(char * certificate, u_int16_t cert_len) */
/* {  */
/* } */

/* // ADD CLI ID */
/* static void add_cli_id(struct Hash_Table **flow_in, struct Handshake **handshake, u_int8_t len_id) */
/* { */
/*   // copy cli_rand */
/*   memcpy((*flow_in)->handshake->cli_rand, (*handshake)->cli_rand, 32); */
/*   // copy sessID_c */
/*   if(len_id > 1) { */
/*     (*flow_in)->handshake->sessID_c = malloc(sizeof(char) * len_id); */
/*     memcpy((*flow_in)->handshake->sessID_c, (*handshake)->sessID_c, len_id); */
/*   } */
/*   else */
/*     (*flow_in)->handshake->sessID_c = NULL; */
/* } */

/* // ADD SRV ID */
/* static void add_srv_id(struct Hash_Table **flow_in, struct Handshake **handshake, u_int8_t len_id) */
/* { */
/*   // copy srv_rand */
/*   memcpy((*flow_in)->handshake->srv_rand, (*handshake)->srv_rand, 32); */
/*   // copy sessID_c */
/*   if(len_id > 1) { */
/*     (*flow_in)->handshake->sessID_s = malloc(sizeof(char) * len_id); */
/*     memcpy((*flow_in)->handshake->sessID_s, (*handshake)->sessID_s, len_id); */
/*   } */
/*   else */
/*     (*flow_in)->handshake->sessID_s = NULL; */
/* } */

// UPDATE CERT (used o update the certificate)
static void update_cert(struct Hash_Table **flow_in, struct Handshake **handshake, u_int8_t len_cert, u_int8_t cc)
{
  // copy certificate_S
  if(len_cert > 1) {
    if(cc == CERT_S) {
      (*flow_in)->handshake->certificate_S = malloc(sizeof(unsigned char) * len_cert);
      memcpy((*flow_in)->handshake->certificate_S, (*handshake)->certificate_S, len_cert);
    }
  }
  else
    (*flow_in)->handshake->sessID_s = NULL;
}


// ADD FLOW
static void add_flow(struct Flow *flow, int KEY, struct Handshake *handshake, u_int8_t flag, u_int8_t len_id)
{
  struct Hash_Table * flow_in;

  /* key already in the hash? */
  HASH_FIND_INT(HT_Flows, &KEY, flow_in);
  
  /* new flow: add the flow if the key is not used */
  if(!flow_in) {
    /**
       NOTE: we consider a new flow just if we process a Client Hello pkt;
       if another pkt arrived for a new flow
       discard it because the handshake will be incomplete
     */
    if(flag == CLI) {

      // alloc mem for new elem
      flow_in = malloc(sizeof(struct Hash_Table));
      // set memory to 0 
      memset(flow_in, 0, sizeof(struct Hash_Table));
      // alloc mem for handshake field of flow
      flow_in->handshake = malloc(sizeof(struct Handshake));
      
      // set FLOW
      flow_in->flow = *flow;

      // set KEY
      flow_in->KEY = KEY;
      
      // set handshake fin to FALSE
      flow_in->is_handsk_fin = FALSE;
      
      /* // se cli hello -> ADD_CLI_ID */
      /* add_cli_id(&flow_in, &handshake, len_id); */
      
      // if cli hello -> ADD_CLI_RAND
      memcpy(&flow_in->handshake->cli_rand, handshake->cli_rand, 32);
      
      // add new elem in Hash Table
      HASH_ADD_INT(HT_Flows, KEY, flow_in);
    }
  }
  /* update flow or discard */
  else {

    /* the handshake is not complete, so it must be fill with new value(s) */
    if(flow_in->is_handsk_fin == FALSE) {
      
      // if cli hello -> ADD_CLI_RAND
      if(flag == CLI)
	memcpy(&flow_in->handshake->cli_rand, handshake->cli_rand, 32);
	/* add_cli_id(&flow_in, &handshake, len_id); */

      // if serv hello -> ADD_SRV_RAND
      else if(flag == SRV) {
	memcpy(&flow_in->handshake->srv_rand, handshake->srv_rand, 32);
	memcpy(&flow_in->handshake->chiph_serv, handshake->chiph_serv, 2);
      }
	/* add_srv_id(&flow_in, &handshake, len_id); */

      // if cert hello -> UPDATE_CERT
      else if(flag == CERT_S) {
	update_cert(&flow_in, &handshake, len_id, flag);
	// set handshake fin to TRUE
	flow_in->is_handsk_fin = TRUE;
      }
      // if Client Key Exch -> encrypted Pre-Master secret
      else if(flag == CKE) {
	memcpy(&flow_in->handshake->pre_master_secret, handshake->pre_master_secret, len_id);
      }
    }
 
    /* THE HANDSHAKE FOR THIS KEY IS COMPLETE */
    else if (flow_in->is_handsk_fin == TRUE) {
      
      /* if the pkt is a Client Hello, open a new flow for handshake */
      if(flag == CLI) {
	memcpy(&flow_in->handshake->cli_rand, handshake->cli_rand, 32);
	/* add_cli_id(&flow_in, &handshake, len_id); */
	
	/* **** IMPORTANT!!! CHECK IF FLOW IS OVERWRITTEN **** */
	
	// add new elem in Hash Table
	HASH_ADD_INT(HT_Flows, KEY, flow_in);
      }
      else {
	/* discard pkt */
	/* look also if flow is too old:
	   if yes, delete it */
	/* --TODO-- */
      }
    }
  }
}

///////////////////////// FUNCTIONS ////////////////////////////////////


// Function to dissect TLS/SSL
int tls_packet_dissector(const u_char **payload,
			 const u_int16_t size_payload,
			 const u_int8_t ip_version,
			 struct Flow *flow,
			 int KEY,
			 const u_int16_t src_port,
			 const u_int16_t dst_port,
			 const u_int8_t proto_id_l3,
			 u_int8_t s
			 /* struct Hash_Table ** HT_Flows */)
{
  struct Hash_Table *el;
  struct Handshake *handshake;
  const u_int8_t *pp = *payload;

  /**
     # HANDSHAKE #
     initialize the handshake structure
  */
  handshake = malloc(sizeof(struct Handshake) * 1);
  if(!handshake) {
    fprintf(stderr, "error on malloc handshake\n");
    return -1;
  }
  memset(handshake, 0, sizeof(struct Handshake));
  
  /**
     NOTE:
     port 443 is for HTTP over TLS/SSL
     port 636 is for LDAP proto tunneling on SSL (or TLSv1
     port 389 is for LDAP proto tunneling on TLS (>= TLSv1.2)
  */
  if(proto_id_l3 == IPPROTO_TCP &&
     ((src_port == 443 || dst_port == 443) ||
      (src_port == 636 || dst_port == 636) ||
      (src_port == 389 || dst_port == 389) ||
      (src_port == 5061 || dst_port == 5061) ||
      (src_port == 5081 || dst_port == 5081))) {

    /** dissect the packet **/
  
    struct header_tls_record *hdr_tls_rec = (struct header_tls_record*)(*payload);
      
    u_int16_t type = 0;
    u_int8_t more_records = 0;
    
    // Record Type
    switch(hdr_tls_rec->type) {
      
    case 0x16:   // HANDSHAKE
      type = HANDSHAKE;
      break;
    case 0x14:   // CHANGE_CIPHER_SPEC
      type = CHANGE_CIPHER_SPEC;
      break;
    case 0x15:   // ALERT
      type = ALERT;
      break;
    case 0x17:   // APPLICATION_DATA
      type = APPLICATION_DATA;
      break;
    default:
      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
      return -1;
    }
    
    // Record Version
    if(ntohs(hdr_tls_rec->version) != TLS1  &&
       ntohs(hdr_tls_rec->version) != TLS11 &&
       ntohs(hdr_tls_rec->version) != TLS12) {
      
      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
      return -1; 
    }

    /**
       HANDSHAKE Type = 22 
    **/
    if(type == HANDSHAKE) {
      
      do {
	// move the pointer everytime part of the payload is detected
	pp = pp + TLS_HEADER_LEN;
	struct handshake_header * hand_hdr = (struct handshake_header*) pp;
	pp = pp + HANDSK_HEADER_LEN;
	int offset = 0;
	u_int8_t is_cert_status = 0;

	switch(hand_hdr->msg_type) {
      
	case CLIENT_HELLO:
	  {	    
	    // check version  
	    if(pp[0] != 0x03 && (pp[1] != 0x01 || pp[1] != 0x02 || pp[1] != 0x03)) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }
	    // move foward of 2 bytes
	    pp = pp + 2;
	    // copy cli random bytes
	    memcpy(handshake->cli_rand, pp, 32);
	    // move forward
	    pp = pp + RANDOM;
	    // check session ID
	    u_int8_t len_id = 1;
	    
	    // 2 cases: len_id = 0; len_id > 0
	    if(*pp != 0) {
	      // read and save ID
	      len_id = *pp;
	      handshake->sessID_c = malloc(sizeof(char) * len_id);
	      memcpy(handshake->sessID_c, pp+1, len_id);
	      pp = pp + len_id + 1;
	    }
	    else
	      pp = pp + len_id;
	    
	    // check cipher suite
	    u_int16_t cipher_len =  pp[1] + (pp[0] << 8);

	    // set the offset correct value till here
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + 2 + RANDOM + len_id + 2 + cipher_len;
	    pp = pp + 2 + cipher_len;

	    if(offset < size_payload) {
	
	      u_int16_t compression_len = pp[0];

	      offset += compression_len + 1;
	      pp = pp + compression_len + 1;

	      if(offset < size_payload) {
		/* ******* */
		//extensions_len = pp[0];
		/* ******* */
		u_int16_t extensions_len =  pp[1] + (pp[0] << 8);

		offset += extensions_len + 2;

		pp = pp + extensions_len + 2;

		/* *** TO CHECK *** */
		if(offset < size_payload) {
		  /**
		     More extensions
		     Note: u_int to avoid possible overflow on extension_len addition */	    
		  u_int exts_offset = 1;

		  offset += exts_offset;
		  pp = pp + exts_offset;
	    
		  while(exts_offset < extensions_len) {
	      
		    u_int16_t exts_id, exts_len = 0;
	      
		    memcpy(&exts_id, pp, 2);
		    exts_offset += 2;
		    offset += exts_offset;
		    pp = pp + exts_offset;
	      
		    memcpy(&exts_len, pp, 2);
		    exts_offset += 2;
		    offset += exts_offset;
		    pp = pp + exts_offset;

		    exts_id = ntohs(exts_id);
		    exts_len = ntohs(exts_len);

		    exts_offset += exts_len;
		    offset += exts_offset;
		    pp = pp + exts_offset;
		  }
		  // search flow and eventually insert new one in HT or update old
		  // 10 CLI
		  add_flow(flow, KEY, handshake, CLI, len_id);
		  more_records = 1;
		  break;
		}
		else {
		  more_records = 1;
		  // search flow and eventually insert new in HT update old
		  add_flow(flow, KEY, handshake, CLI, len_id);
		  break;
		}
		
		// search flow and eventually inser new in HT update old
		add_flow(flow, KEY, handshake, CLI, len_id);
		
	      }
	      else {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      };
	    }
	    else {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    };
	  }
	case SERVER_HELLO:
	  {
	    // check version
	    if(pp[0] != 0x03 && (pp[1] != 0x01 || pp[1] != 0x02 || pp[1] != 0x03)) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }	
	    // move foward of 2 bytes
	    pp = pp + 2;
	    // copy serv random bytes
	    memcpy(handshake->srv_rand, pp, 32);
	    // move foward
	    pp = pp + RANDOM;
	    // check session ID
	    u_int8_t len_id = 1;
	    if(*pp != 0) {
	      // read and save ID
	      len_id = ntohs(*pp);
	      handshake->sessID_s = malloc(sizeof(char) * len_id);
	      memcpy(handshake->sessID_s, pp+1, len_id);	
	    }
	    // every time move foward of n bytes
	    pp = pp + len_id;
      
	    // check cipher suite
	    u_int16_t cipher_len = 2;
	    if(pp[0] != 0x00 && (pp[1] != 0x9d ||
				 pp[1] != 0x9c ||
				 pp[1] != 0x3d ||
				 pp[1] != 0x3c ||
				 pp[1] != 0x35 ||
				 pp[1] != 0x2f ||
				 pp[1] != 0xff)) {
	      fprintf(stderr, "Invalid Chipher Suite. No DHE/EDH availlable for decription\n");
	      return -1;	      
	    }

	    // add Chipher Suite Server to handshake
	    memcpy(handshake->chiph_serv, pp, 2);

	    // set the offset correct value till here
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + 2 + RANDOM + len_id + cipher_len;
	    pp = pp + 1 + cipher_len;

	    if(offset < size_payload) {
	      /* ******* */
	      //extensions_len = pp[0];
	      /* ******* */
	      u_int16_t extensions_len =  pp[1] + (pp[0] << 8);

	      offset += extensions_len + 2;

	      pp = pp + extensions_len + 2;

	      /* *** TO CHECK *** */
	      if(offset < size_payload) {

		/**
		   In Server Hello, if the offset is less than payload,
		   we can have 3 scenarios:
		   1) Certificate
		   2) Change Chiper Spec (pkt after end of Handshake)
		   3) more extensions
		*/
		
		// 1
		if(pp[5] == 0x0b) {
		  more_records = 0;
		  // search flow and eventually insert new in HT update old
		  add_flow(flow, KEY, handshake, SRV, len_id);
		  break;
		}
		// 2
		else if(pp[5] == 0x14) {
		  more_records = 1;
		  // search flow and eventually insert new in HT update old
		  add_flow(flow, KEY, handshake, SRV, len_id);
		  break;
		}
	      
		// 3
		u_int exts_offset = 1;

		offset += exts_offset;
		pp = pp + exts_offset;
	    
		while(exts_offset < extensions_len) {
	      
		  u_int16_t exts_id, exts_len = 0;

		  memcpy(&exts_id, pp, 2);
		  exts_offset += 2;
		  offset += exts_offset;
		  pp = pp + exts_offset;
	      
		  memcpy(&exts_len, pp, 2);
		  exts_offset += 2;
		  offset += exts_offset;
		  pp = pp + exts_offset;

		  exts_id = ntohs(exts_id);
		  exts_len = ntohs(exts_len);

		  exts_offset += exts_len;
		  offset += exts_offset;
		  pp = pp + exts_offset;
		}
		
		// search flow and eventually insert new in HT or update old
		add_flow(flow, KEY, handshake, SRV, len_id);
		
		more_records = 1;
		break;
	      }
	      else {
		// search flow and eventually insert new in HT or update old
		add_flow(flow, KEY, handshake, SRV, len_id);
		more_records = 1;
		break;
	      }
	      
	      // search flow and eventually insert new in HT or update old
	      add_flow(flow, KEY, handshake, SRV, len_id);
	      
	    }
	    else {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    };
	  }
	case CERTIFICATE:
	  {	    
	    u_int16_t hh_len = hand_hdr->len[2] + (hand_hdr->len[1] << 8 ) + (hand_hdr->len[0] << 8);
	    u_int16_t cert_len_total = pp[2] + (pp[1] << 8) + (pp[0] << 8);

	    if((cert_len_total + 3) != hh_len) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }

	    pp = pp + 3; // add the 3 bytes for certficates total length

	    u_int16_t subcert_len_total = 0;

	    if(cert_len_total > 0) {

	      /* TODO: SAVE MORE CERTIFICATES IN HANDSHAKE OF A FLOW */

	      do { // more than one certificate

		u_int16_t subcert_len = pp[2] + (pp[1] << 8) + (pp[0] << 8);
		
	        unsigned char cert[subcert_len];
		
		// Copy the Certificate from Server
		memcpy(cert, pp + 3, subcert_len);
		// Save the certificate in a file "cert.der"
		if(s == 1)
		  save_certificate_FILE(cert, subcert_len);
		/***
		    --- TODO function to split the certificate chain ---
		***/
		//handshake.certificate_S = split_Server_Certificate(cert, cert_len);
		pp = pp + 3 + subcert_len;

		subcert_len_total += subcert_len + 3;
		
	      } while(subcert_len_total < cert_len_total);
	    }
	    else
	      pp = pp + cert_len_total + 3;
	    
	    offset += TLS_HEADER_LEN + HANDSK_HEADER_LEN + 3 + cert_len_total;
	    
	    if(offset < size_payload) {
	      if(cert_len_total > 0) {
		if(pp[5] != 0x0c && pp[5] != 0x16 && pp[5] != 0x10 && pp[5] != 0x0e) {
		  fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		  return -1;
		}
		else if(pp[5] == 0x0e) {
		  offset += TLS_HEADER_LEN + HANDSK_HEADER_LEN;
		  more_records = 1;
		  break;
		}
		  // search flow and eventually inser new in HT update old
		  add_flow(flow, KEY, handshake, CERT_S, cert_len_total);
	      }
	      more_records = 0;
	      break;
	    }
	    else {
	      if(cert_len_total > 0)
		// search flow and eventually inser new in HT update old
		add_flow(flow, KEY, handshake, CERT_S, cert_len_total);
	      more_records = 1;
	      break;
	    }
	  }
	case CERTIFICATE_STATUS:
	  {
	    pp = pp + 1; // Certificate Status Type OCSP (1)
	    u_int16_t cert_status_len = pp[2] + (pp[1] << 8) + (pp[0] << 8);
	    is_cert_status = 1;
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + 1 + 3 + cert_status_len;
	    if(offset < size_payload) {
	      pp = pp + 3 + cert_status_len;
	      if(pp[5] != 0x0c && pp[5] != 0x16 && pp[5] != 0x10) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      }
	      more_records = 0;
	      break;
	    }
	    else {
	      more_records = 1;
	      break;
	    }
	  }
	case CLIENT_KEY_EXCHANGE:
	  {
	    int hand_hdr_len = (hand_hdr->len[2]) + (hand_hdr->len[1] << 8) + (hand_hdr->len[0] << 8);
	    int enc_pms_len;
	    int pms_len;

	    if(hand_hdr_len > 33) {

	      /** PREPARE THE KEY **/
	      while(profile_protocol[index] == NULL) // search the profile protocol TLS
		index++;
	      is_pub_key = 0;
	      // copy the key path to buffer key_path_buff
	      memcpy(pvtkey_path_buff, profile_protocol[index].pvt_key_path, sizeof(key_path));
	      
	      /**
		 1) RSA: the server's key is of type RSA. 
		 The client generates a random value (the "pre-master secret" of 48 bytes, out of which 46 are random) and encrypts it with the server's public key.
		 There is no ServerKeyExchange.
	      */
	      enc_pms_len = hand_hdr_len - 2;
	      
	      u_int8_t *enc_pre_master_secret = malloc(sizeof(u_int8_t) * enc_pms_len);
	      // save the enc_pre-master secret
	      memcpy(enc_pre_master_secret, pp + 2, enc_pms_len);
	      
	      /** DECRYPT PRE-MASTER SECRET USING SERVER PVT KEY **/
	      /* char *pvtkey_path_buff = "cakey.pem"; */
	      unsigned char *pvtkey = read_file(pvtkey_path_buff);
	      unsigned char PMS[48];
	      
	      pms_len = private_decrypt(enc_pre_master_secret, enc_pms_len, pvtkey, PMS);
	      if(pms_len != 48)
		{
		  printLastError("Private Decrypt failed for PreMaster Secret ");
		  return -2; // Error on decription PMS
		}
	      // copy pre_master_secret in flow
	      memcpy(handshake->pre_master_secret, PMS, pms_len);
	      add_flow(flow, KEY, handshake, CKE, pms_len);
	    }
	    	    
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + hand_hdr_len;
	    pp = pp + hand_hdr_len;
	
	    if(offset < size_payload) {
	      if(pp[0] == 0x14) {
		more_records = 1;
		//extract key
		break;
	      }
	      if (pp[0] != 0x0f) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      }
	      more_records = 0;
	      //extract key
	      break;
	    }
	    else {
	      more_records = 1;
	      //extract key
	      break;
	    }
	  }
	case CERTIFICATE_REQUEST:
	  {	  
	    struct Cert_Req *cert_req = (struct Cert_Req*) pp;

	    int hand_hdr_len = (hand_hdr->len[2]) + (hand_hdr->len[1] << 8) + (hand_hdr->len[0] << 8);
	    pp = pp + hand_hdr_len;
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + sizeof(cert_req) + cert_req->dist_name_len;
	  
	    if(offset < size_payload) {
	      if(pp[0] != 0x0e) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      }
	      more_records = 0;
	      break;
	    }
	    else {
	      more_records = 1;
	      break;
	    }
	  }
	case SERVER_DONE:
	  {
	    int hand_hdr_len = (hand_hdr->len[2]) + (hand_hdr->len[1] << 8) + (hand_hdr->len[0] << 8);
	
	    if(hand_hdr_len != 0) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }
	    more_records = 1;
	    break;
	  }
	case CERTIFICATE_VERIFY:
	  break;
	  
	case FINISHED:
	  {
	    struct Hash_Table *old; 
	    old = malloc(sizeof(struct Hash_Table));

	    memcpy(&old->flow, flow, sizeof(struct Flow));
	    /* old->flow = flow_key; */
	    
	    // set handshake fin to TRUE
	    HASH_FIND_INT(HT_Flows, &KEY, old);
	    if(old) {
	      old->is_handsk_fin = TRUE;
	      HASH_REPLACE_INT(HT_Flows, KEY, old, el);
	    }
	    more_records = 1;
	    break;
	  }
	  
	} // switch
      } while(more_records == 0);
    }
    
    /**
       CHANGE_CIPHER_SPEC = 20
    **/
    else if(type == CHANGE_CIPHER_SPEC) {
      pp = pp + TLS_HEADER_LEN;
      if(pp[0] != 0x01) {
	fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	return -1;
      }
    }
    else if(type == ALERT) {
      /* TODO IF NECESSARY */
    }
    else if(type == APPLICATION_DATA) {

      /* unsigned char encrypted[4098]; // CHECK if dimension is too short */
      /* unsigned char decrypted[4098]; */
      /* char *key_path_buff = "cakey.pem"; */
      /* u_int16_t len = 0; */
      /* int is_pub_key = 0; // 1 PUB 0 PVT */
      /* int count = 0, decrypted_length = 0; */
      /* unsigned char *Key; */

      /* // init buffers */
      /* memset(encrypted, '\0', sizeof(encrypted)); */
      /* memset(decrypted, '\0', sizeof(decrypted)); */
      /* /\* memset(key_path, '\0', sizeof(key_path)); *\/ */

      /* /\** PREPARE THE KEY **\/ */
      /* while(profile_protocol[index] == NULL) // search the profile protocol TLS */
      /* 	index++; */
      /* // set flag is_pub_key */
      /* if(profile_protocol[index].pub_key_path) { */
      /* 	is_pub_key = 1; */
      /* 	// copy the key path to buffer key_path_buff */
      /* 	memcpy(key_path_buff, profile_protocol[index].pub_key_path, sizeof(key_path)); */
      /* } */
      /* else */
      /* 	// copy the key path to buffer key_path_buff */
      /* 	memcpy(key_path_buff, profile_protocol[index].pvt_key_path, sizeof(key_path)); */
      
      /* // call READ_FILE to get the string from key */
      /* Key = read_file(key_path_buff); */

      /* /\* ***** *\/ */

      /* /\* CHECK -- FIND SOLUTION IF THERE ARE MORE APP DATA IN THE SAME PKT *\/ */
      /* do { */
      /* 	if(count != 0) */
      /* 	  hdr_tls_rec = (struct header_tls_record*)((*payload)+count); */
      /* 	// move the pointer everytime part of the payload is detected */
      /* 	pp = pp + TLS_HEADER_LEN; */
      /* 	len = ntohs(hdr_tls_rec->len); */
      /* 	count = count + TLS_HEADER_LEN + len; */

      /* 	// copy the ENCRIPTED application data into "encrypted" buffer */
      /* 	memcpy(encrypted, pp, len); */
	
      /* 	/\* --- DECRYPTION OF PAYLOAD DATA --- *\/ */

      /* 	if(is_pub_key == 1) { // decrypt using PUB KEY */
      /* 	  decrypted_length = public_decrypt(encrypted, len, Key, decrypted); */
      /* 	  if(decrypted_length == -1) */
      /* 	    { */
      /* 	      printLastError("Public Decrypt failed "); */
      /* 	      return -2; // Error on decription */
      /* 	    } */
      /* 	} */
      /* 	else { // decrypt using PVT KEY */
      /* 	  decrypted_length = private_decrypt(encrypted, len, Key, decrypted); */
      /* 	  if(decrypted_length == -1) */
      /* 	    { */
      /* 	      printLastError("Private Decrypt failed "); */
      /* 	      return -2; // Error on decription */
      /* 	    } */
      /* 	} */
	
      /* 	pp = pp + len; */
	
      /* } while(count < size_payload); */
      /* // it's TLS and return the len of decripted payload */
      /* memcpy(decrypted, decrypted, decrypted_length); */
      /* for (int i = 0; i < decrypted_length; i++) */
      /*   printf(" %02x", decrypted[i]); */
      /* printf("decrypted buffer = %s\n\n", decrypted); */
    } 
    return 0; // it it's TLS
  }
  return -1;
}

#endif
