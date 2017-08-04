/**
   TLS dissector: parse the pkt and extract the handshake (if present)
   TLS version supported: TLSv1 TLSv1.2
   
   Copyright (C) 2016-2017 Michele Campus
   
   This file is part of captagent.
   
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "structures.h"
#include "tls_ssl.h"

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
  SERVER_KEY_EXCHANGE = 12,
  CERTIFICATE_REQUEST = 13,
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


#define TRUE  0
#define FALSE 1

#define CLI     10
#define SRV     11
#define CERT_S  12
#define CERT_C  13



/** ### FunctionS for the HASH TABLE (uthash) ### **/

struct Hash_Table *HT_Flows = NULL; // # HASH TABLE

// ADD CLI RAND
static void add_cli_rand_id(struct Hash_Table **flow_in, struct Handshake **handshake, u_int8_t len_id)
{
  // copy cli_rand
  memcpy((*flow_in)->handshake->cli_rand, (*handshake)->cli_rand, 32);
  // copy sessID_c
  if(len_id > 1) {
    (*flow_in)->handshake->sessID_c = malloc(sizeof(char) * len_id);
    memcpy((*flow_in)->handshake->sessID_c, (*handshake)->sessID_c, len_id);	
  }
  else
    (*flow_in)->handshake->sessID_c = NULL;
}

// ADD SRV RAND
static void add_srv_rand_id(struct Hash_Table **flow_in, struct Handshake **handshake, u_int8_t len_id)
{
  // copy srv_rand
  memcpy((*flow_in)->handshake->srv_rand, (*handshake)->srv_rand, 32);
  // copy sessID_c
  if(len_id > 1) {
    (*flow_in)->handshake->sessID_s = malloc(sizeof(char) * len_id);
    memcpy((*flow_in)->handshake->sessID_s, (*handshake)->sessID_s, len_id);	
  }
  else
    (*flow_in)->handshake->sessID_s = NULL;
}

// ADD CERT
static void add_cert(struct Hash_Table **flow_in, struct Handshake **handshake, u_int8_t len_cert, u_int8_t cc)
{
  // copy certificate_S
  if(len_cert > 1) {
    if(cc == CERT_S) {
      (*flow_in)->handshake->certificate_S = malloc(sizeof(char) * len_cert);
      memcpy((*flow_in)->handshake->certificate_S, (*handshake)->certificate_S, len_cert);
    }
    else if(len_cert == CERT_C) {
      (*flow_in)->handshake->certificate_C = malloc(sizeof(char) * len_cert);
      memcpy((*flow_in)->handshake->certificate_C, (*handshake)->certificate_C, len_cert);
    }
  }
  else
    (*flow_in)->handshake->sessID_s = NULL;
}


// ADD FLOW
static void add_flow(/* struct Hash_Table * HT_Flows,  */struct Flow_key *key, struct Handshake *handshake, u_int8_t flag, u_int8_t len_id)
{
  struct Hash_Table * flow_in;

  /* key already in the hash? */
  HASH_FIND(hh, HT_Flows, &key, sizeof(struct Flow_key), flow_in);
  
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
      flow_in->handshake = malloc(sizeof(struct Flow_key));
      
      // set KEY
      memcpy(&flow_in->flow_key_hash, key, sizeof(struct Flow_key));
      
      // set handshake fin to FALSE
      flow_in->is_handsk_fin = FALSE;
      
      // se cli hello -> ADD_CLI_RAND_ID
      add_cli_rand_id(&flow_in, &handshake, len_id);
      
      // add new elem in Hash Table
      HASH_ADD(hh, HT_Flows, flow_key_hash, sizeof(struct Flow_key), flow_in);
    }
  }
  /* update flow or discard */
  else {

    /* the handshake is not complete, so it must be fill with new value(s) */
    if(flow_in->is_handsk_fin == FALSE) {
      
      // se cli hello -> ADD_CLI_RAND_ID
      if(flag == CLI)
	add_cli_rand_id(&flow_in, &handshake, len_id);
      // se serv hello -> ADD_SRV_RAND_ID
      else if(flag == SRV)
	add_srv_rand_id(&flow_in, &handshake, len_id);
      // se cert hello -> ADD_CERT_IN
      else if(flag == CERT_S) {
	add_cert(&flow_in, &handshake, len_id, flag);
	// set handshake fin to TRUE
	flow_in->is_handsk_fin = TRUE;
      }
    }
    /* the handshake for this key is complete */
    else if (flow_in->is_handsk_fin == TRUE) {
      
      /* if the pkt is a Client Hello, open a new flow for handshake */
      if(flag == CLI) {
	add_cli_rand_id(&flow_in, &handshake, len_id);
	
	/* **** IMPORTANT!!! CHECK IF FLOW IS OVERWRITTEN **** */
	
	// add new elem in Hash Table
	HASH_ADD(hh, HT_Flows, flow_key_hash, sizeof(struct Flow_key), flow_in);
      }
      else {
	/* discard pkt */
	/* look also if flow is too old:
	   if yes, delete it */
      }
    }
  }
}

///////////////////////// FUNCTIONS ////////////////////////////////////

// Function to dissect TLS/SSL
u_int8_t tls_packet_dissector(const u_char ** payload,
			      const u_int16_t size_payload,
			      const u_int8_t ip_version,
			      struct Handshake * handshake,
			      struct Flow_key * flow_key,
			      const u_int16_t src_port,
			      const u_int16_t dst_port,
			      const u_int8_t proto_id_l3/* , */
			      /* struct Hash_Table ** HT_Flows */)
{
  struct Hash_Table *el;
  const u_int8_t * pp = *payload;

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
      (src_port == 5061 || dst_port == 5061))) {

    /** dissect the packet **/
  
    struct header_tls_record *hdr_tls_rec = (struct header_tls_record*)(*payload);
      
    u_int16_t type = 0;
    u_int8_t more_records = TRUE;
    
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
	int offset;

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
	    // copy random bytes move foward
	    memcpy(handshake->cli_rand, pp, 32);	
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
		     Note: u_int to avoid possible overflow on extension_len addition 
		  */	    
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
		  // search flow and eventually inser new in HT or update old
		  // 10 CLI
		  add_flow(/* HT_Flows, */ flow_key, handshake, CLI, len_id);
		  more_records = FALSE;
		  break;
		}
		else {
		  more_records = FALSE;
		  // search flow and eventually inser new in HT update old
		  add_flow(/* HT_Flows, */ flow_key, handshake, CLI, len_id);
		  break;
		}
		
		// search flow and eventually inser new in HT update old
		add_flow(/* HT_Flows, */ flow_key, handshake, CLI, len_id);
		
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
	    // copy random bytes move foward
	    memcpy(handshake->srv_rand, pp, 32);
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
	    /* ** TODO check the cipher suite list ** */
	    u_int16_t cipher_len = 2;

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
		   If Server Hello, if the offset is less than payload,
		   we can have 3 scenarios:
		   1) Certificate
		   2) Change Chiper Spec (pkt after end of Handshake)
		   3) more extensions
		*/
		
		// 1
		if(pp[5] == 0x0b) {
		  more_records = TRUE;
		  break;
		}
		// 2
		else if(pp[5] == 0x14) {
		  more_records = FALSE;
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
		
		// search flow and eventually inser new in HT update old
		add_flow(/* HT_Flows, */ flow_key, handshake, SRV, len_id);
		
		more_records = FALSE;
		break;
	      }
	      else {
		// search flow and eventually inser new in HT update old
		add_flow(/* HT_Flows,  */flow_key, handshake, SRV, len_id);
		more_records = FALSE;
		break;
	      }
	      
	      // search flow and eventually inser new in HT update old
	      add_flow(/* HT_Flows, */ flow_key, handshake, SRV, len_id);
	      
	    }
	    else {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    };
	  }
	case CERTIFICATE:
	  {
	    
	    u_int16_t hh_len = hand_hdr->len[2] + (hand_hdr->len[1] <<8 ) + (hand_hdr->len[0] << 8);
	    u_int16_t cert_len = pp[2] + (pp[1] << 8) + (pp[0] << 8);

	    if((cert_len + 3) != hh_len) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }

	    if(cert_len > 0) {
	      
	      // Copy the Certificate from Server
	      handshake->certificate_S = malloc(cert_len * sizeof(char));
	      /* TODO function to split the certificate chain */
	      memcpy(handshake->certificate_S, pp, cert_len);

	    }
	    
	    pp = pp + cert_len + 3;
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + 3 + cert_len;
	    
	    if(offset < size_payload) {
	      if(cert_len > 0) {
		if(pp[5] != 0x0c || pp[5] != 0x16 || pp[5] != 0x10) {
		  fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		  return -1;
		}
		else
		  // search flow and eventually inser new in HT update old
		  add_flow(/* HT_Flows,  */flow_key, handshake, CERT_S, cert_len);
	      }
	      more_records = TRUE;
	      break;
	    }
	    else {
	      if(cert_len > 0)
		// search flow and eventually inser new in HT update old
		add_flow(/* HT_Flows, */ flow_key, handshake, CERT_S, cert_len);
	      more_records = FALSE;
	      break;
	    }
	  }
	case SERVER_KEY_EXCHANGE:
	  {
#ifdef ECDH
	    struct server_key_exch_tls_12_ECDH s_key_exc = (struct server_key_exch_tls_12_ECDH) pp;
#endif
#ifdef DH
	    struct server_key_exch_tls_12_ECDH s_key_exc = (struct server_key_exch_tls_12_ECDH) pp;
#endif
	    int hand_hdr_len = (hand_hdr->len[0] << 8) | (hand_hdr->len[1]) | (hand_hdr->len[2]);
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + hand_hdr_len;
	    pp = pp + hand_hdr_len;
	
	    if(offset < size_payload) {
	      if(pp[0] != 0x0e) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      }
	      more_records = TRUE;
	      break;
	    }
	    else {
	      more_records = FALSE;
	      break;
	    }
	  }
	case CLIENT_KEY_EXCHANGE:
	  {
	    int hand_hdr_len = (hand_hdr->len[0] << 8) | (hand_hdr->len[1]) | (hand_hdr->len[2]);
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + hand_hdr_len;
	    pp = pp + hand_hdr_len;
	
	    if(offset < size_payload) {
	      if(pp[0] == 0x14) {
		more_records = FALSE;
		//extract key
		break;
	      }
	      if (pp[0] != 0x0f) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      }
	      more_records = TRUE;
	      //extract key
	      break;
	    }
	    else {
	      more_records = FALSE;
	      //extract key
	      break;
	    }
	  }
	case CERTIFICATE_REQUEST:
	  {
	  
	    struct Cert_Req *cert_req = (struct Cert_Req*) pp;

	    int hand_hdr_len = (hand_hdr->len[0] << 8) | (hand_hdr->len[1]) | (hand_hdr->len[2]);
	    pp = pp + hand_hdr_len;
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + sizeof(cert_req) + cert_req->dist_name_len;
	  
	    if(offset < size_payload) {
	      if(pp[0] != 0x0e) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		return -1;
	      }
	      more_records = TRUE;
	      break;
	    }
	    else {
	      more_records = FALSE;
	      break;
	    }
	  }
	case SERVER_DONE:
	  {
	    int hand_hdr_len = (hand_hdr->len[0] << 8) | (hand_hdr->len[1]) | (hand_hdr->len[2]);
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + hand_hdr_len;
	
	    if(hand_hdr_len != 0) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }
	    if(offset < size_payload) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      return -1;
	    }
	    else {
	      more_records = FALSE;
	      break;
	    }
	  }
	case CERTIFICATE_VERIFY:
	  break;
	  
	case FINISHED:
	  {
	    struct Hash_Table *old; 
	    old = malloc(sizeof(struct Hash_Table));

	    memcpy(&old->flow_key_hash, flow_key, sizeof(struct Flow_key));
	    
	    // set handshake fin to TRUE
	    HASH_FIND(hh, HT_Flows, &flow_key,
		      sizeof(struct Flow_key), old);
	    if(old) {
	      old->is_handsk_fin = TRUE;
	      HASH_REPLACE(hh, HT_Flows, flow_key_hash,
			   sizeof(struct Flow_key), old, el);
	    }
	    more_records = FALSE;
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
    
    return 0; // it it's TLS
  }
  return -1;
}
