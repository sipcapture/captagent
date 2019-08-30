/**
  This TLS dissector parse the pkt and extract the handshake (if present)
  
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <captagent/log.h>
#include "config.h"

/* #include <openssl/md5.h> */

#ifdef USE_SSL

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <gcrypt.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include "parser_tls.h"

#define IMPLICIT_NONCE_LEN  4
#define EXPLICIT_NONCE_LEN  8

/** ###### FunctionS for the HASH TABLE (uthash) ###### **/
struct Hash_Table *HT_Flows = NULL; // # HASH TABLE

static u_int16_t client_;

// ciphers
const char *ciphers[] = {
  "AES",
  "AES256",
  "*UNKNOWN*"
};


// PRF function to reproduce the Master Secret or Key BLock
static int PRF(struct Handshake *handshake, unsigned char *PMS, const char *master_string, unsigned char *MS, int out_len)
{
  int ret;

  // SHA384
  if(handshake->cipher_suite.number == SHA384) {
    if(strncmp(master_string, "master secret", 13) == 0)
      ret = tls12_prf(GCRY_MD_SHA384, PMS, master_string, handshake->cli_rand, handshake->srv_rand, MS, out_len);
    else
      ret = tls12_prf(GCRY_MD_SHA384, PMS, master_string, handshake->srv_rand, handshake->cli_rand, MS, out_len);
  }
  // SHA286
  else {
    if(strncmp(master_string, "master secret", 13) == 0)
      ret = tls12_prf(GCRY_MD_SHA256, PMS, master_string, handshake->cli_rand, handshake->srv_rand, MS, out_len);
    else
      ret = tls12_prf(GCRY_MD_SHA256, PMS, master_string, handshake->srv_rand, handshake->cli_rand, MS, out_len);
  }
  
  if(ret == -1)
    return -1;
  return 0;
}


// Function to perform the decryption
static int tls_decrypt_aead_record(struct Handshake *h, const unsigned char *in,
				   u_int16_t inl, unsigned char *out_str,
				   int *outl, u_int8_t direction) {
  /**
     in = data encrypted
     inl = data encrypted length
     out_str = place for data decrypted
     outl = data decrypted length
     direction = 0 (from client to server) 
               = 1 (from server to client)
  */
  
  gcry_error_t err;
  const unsigned char *explicit_nonce = NULL, *ciphertext = NULL;
  int ciphertext_len, auth_tag_len;
  unsigned char nonce[12];
  const ssl_cipher_mode_t cipher_mode = h->cipher_suite.mode;
  
  switch(cipher_mode) {
  case MODE_GCM:
  case MODE_CCM:
  case MODE_POLY1305:
    auth_tag_len = 16;
    break;
  case MODE_CCM_8:
    auth_tag_len = 8;
    break;
  default:
    fprintf(stderr, "unsupported cipher!\n");
    return F;
  }

  /* Parse input into explicit nonce (TLS 1.2 only), ciphertext and tag. */
  if(cipher_mode != MODE_POLY1305) {
    if(inl < EXPLICIT_NONCE_LEN + auth_tag_len) {
      fprintf(stderr, "Input %d is too small for explicit nonce %d and auth tag %d\n", inl, EXPLICIT_NONCE_LEN, auth_tag_len);
      return -1;
    }
    explicit_nonce = in;
    ciphertext = explicit_nonce + EXPLICIT_NONCE_LEN;
    ciphertext_len = inl - EXPLICIT_NONCE_LEN - auth_tag_len;
  } else {
    fprintf(stderr, "Unexpected TLS cipher_mode %#x\n", cipher_mode);
    return -1;
  }

  /*
   * Nonce construction is version-specific. Note that AEAD_CHACHA20_POLY1305
   * (RFC 7905) uses a nonce construction similar to TLS 1.3.
   */
  if(cipher_mode != MODE_POLY1305) {
      /* Implicit (4) and explicit (8) part of nonce. */
    /* IV in our case is 4 bytes */
    if(direction == 0)
      memcpy(nonce, h->ssl_decoder_cli.iv, IMPLICIT_NONCE_LEN);
    else
      memcpy(nonce, h->ssl_decoder_srv.iv, IMPLICIT_NONCE_LEN);
    
    memcpy(nonce + IMPLICIT_NONCE_LEN, explicit_nonce, EXPLICIT_NONCE_LEN);

  }

  /* Set nonce and additional authentication data */
  if(direction == 0) {
    gcry_cipher_reset(h->ssl_decoder_cli.evp);
    err = gcry_cipher_setiv(h->ssl_decoder_cli.evp, nonce, 12);
    if(err) {
      fprintf(stderr, "Failed to set nonce: %s\n", gcry_strerror(err));
      return -1;
    }
  }
  else {
    gcry_cipher_reset(h->ssl_decoder_srv.evp);
    err = gcry_cipher_setiv(h->ssl_decoder_srv.evp, nonce, 12);
    if(err) {
      fprintf(stderr, "Failed to set nonce: %s\n", gcry_strerror(err));
      return -1;
    }
  }

  /* --- DECRYPTION --- */
  if(direction == 0) {
    err = gcry_cipher_decrypt(h->ssl_decoder_cli.evp, out_str, (size_t) outl, ciphertext, ciphertext_len);
    if(err) {
      fprintf(stderr, "Decrypt failed: %s\n", gcry_strerror(err));
      return -1;
    }
  }
  else {
    err = gcry_cipher_decrypt(h->ssl_decoder_srv.evp, out_str, (size_t) outl, ciphertext, ciphertext_len);
    if(err) {
      fprintf(stderr, "Decrypt failed: %s\n", gcry_strerror(err));
      return -1;
    }
  }
  
  //printf("Plaintext = %s of len %d\n\n", out_str, ciphertext_len);
  *outl = ciphertext_len;
  return 0;
}


/* Initialize a cipher handle */
static int ssl_cipher_init(gcry_cipher_hd_t *cipher, int algo, unsigned char *sk,
			   unsigned char *iv, int mode)
{
  if(algo == -1) {
    /* NULL mode */
    *(cipher) = (gcry_cipher_hd_t)-1;
    return 0;
  }

  int err;
  /**
     This function creates the context handle required for most of the other cipher functions and returns a handle to it in `hd'. 
     In case of an error, an according error code is returned.
     The ID of algorithm to use must be specified via algo
  */
    err = gcry_cipher_open(cipher, algo, GCRY_CIPHER_MODE_GCM, 0);
    if(err != 0)
      return -1;
  
  err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen(algo));
  if(err != 0)
    return -1;
  
  /* AEAD cipher suites will set the nonce later */

  if(mode == MODE_CBC) {
    err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen(algo));
    if (err != 0)
      return -1;
  }
  
  return 0;
}

/* Create context for the decoding (ONLY FOR MODE_GCM) */
static int ssl_create_decoder(struct _SslDecoder *dec,
			      int cipher_algo, u_int8_t *sk,
			      u_int8_t *iv, ssl_cipher_mode_t mode)
{
  int ret;

  struct _SslDecoder *d = calloc(1, sizeof(struct _SslDecoder));

  // MODE_GCM
  ret = ssl_cipher_init(&d->evp, cipher_algo, sk, iv, mode);
  if(ret < 0) {
    fprintf(stderr, "Can't create cipher id: %d mode: %d\n", cipher_algo, mode);
    // clean up memory
    free(d);
    return -1;
  }

  dec->evp = d->evp;

  // clean up memory
  free(d);
  
  return 0;
}

/** ###### FunctionS to save the certificate(s) ###### **/

// SAVE CERTIFICATE AS .DER FILE
/* static void save_certificate_FILE(const unsigned char *cert, u_int16_t cert_len) */
/* { */
/*   FILE *fw; */
/*   X509 *x_cert; */
/*   char filename[cert_len]; */
/*   char buff[cert_len]; */
/*   struct tm *timeinfo; */
/*   struct timeval tv; */
/*   int millisec; */
  
/*   x_cert = d2i_X509(NULL, &cert, cert_len); */
/*   if (!x_cert) { */
/*     fprintf(stderr, "Error on d21_X509 funtion\n"); */
/*     return; */
/*   } */

/*   gettimeofday(&tv, NULL); */

/*   // trick to have milliseconds (thanks to a Stack Overflow answer) */
/*   millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec */
/*   if(millisec >= 1000) {               // Allow for rounding up to nearest second */
/*     millisec -= 1000; */
/*     tv.tv_sec++; */
/*   } */

/*   timeinfo = localtime(&tv.tv_sec); */

/*   memset(filename, 0, cert_len); */
/*   memset(buff, 0, cert_len); */
/*   struct stat st = {0}; */

/*   if (stat("certificates/", &st) == -1) { */
/*     mkdir("certificates/", 0555); */
/*   } */

/*   /\* save every file with the time certificate was catched *\/ */
/*   strftime(filename, sizeof(filename), "certificates/cert_%Y-%m-%d_%H-%M-%S-%%03u.der", timeinfo); */
/*   snprintf(buff, sizeof(buff), filename, tv.tv_usec); */
  
/*   if(!(fw = fopen(buff,"w"))) { */
/*     fprintf(stderr, "Error on opening file descriptor fw\n"); */
/*     return; */
/*   } */
/*   // function to convert raw data (DER) to PEM certificate (good for parsing with openssl) */
/*   i2d_X509_fp(fw, x_cert); */

/*   // free cert and close file descriptor */
/*   X509_free(x_cert); */
/*   fclose(fw); */
/* } */


// UPDATE CERT (used o update the certificate)
static void update_cert(struct Hash_Table **elem_flow, struct Handshake **handshake, u_int8_t len_cert, u_int8_t cc)
{
  // copy certificate_S
  if(len_cert > 1) {
    if(cc == CERT_S) {
      (*elem_flow)->handshake->certificate_S = malloc(sizeof(unsigned char) * len_cert);
      memcpy((*elem_flow)->handshake->certificate_S, (*handshake)->certificate_S, len_cert);
    }
  }
  else
    (*elem_flow)->handshake->sessID_s = NULL;
}


// ADD FLOW
static void add_flow(struct Flow *flow, int KEY, struct Handshake *handshake, u_int8_t flag, u_int8_t len_id)
{
  struct Hash_Table * elem_flow;

  LDEBUG("KEY CKE flow = %d", KEY);

  /* key already in the hash? */
  HASH_FIND_INT(HT_Flows, &KEY, elem_flow);
  
  /* new flow: add the flow if the key is not used */
  if(!elem_flow) {
    /**
       NOTE: we consider a new flow just if we process a Client Hello pkt;
       if another pkt arrived for a new flow
       discard it because the handshake will be incomplete
    */
    if(flag == CLI) {

      // alloc mem for new elem
      elem_flow = malloc(sizeof(struct Hash_Table));
      // set memory to 0 
      memset(elem_flow, 0, sizeof(struct Hash_Table));
      // alloc mem for handshake field of flow
      elem_flow->handshake = malloc(sizeof(struct Handshake));
      
      // set FLOW
      elem_flow->flow = *flow;

      // set KEY
      elem_flow->KEY = KEY;
      
      // set handshake fin to F
      elem_flow->is_handsk_fin = F;
      
      /* // se cli hello -> ADD_CLI_ID */
      /* add_cli_id(&flow_in, &handshake, len_id); */
      
      // if cli hello -> ADD_CLI_RAND
      memcpy(&elem_flow->handshake->cli_rand, handshake->cli_rand, 32);
      
      // add new elem in Hash Table
      HASH_ADD_INT(HT_Flows, KEY, elem_flow);
    }
  }
  /* update flow or discard */
  else {

    /* the handshake is not complete, so it must be fill with new value(s) */
    if(elem_flow->is_handsk_fin == F) {
      
      // if cli hello -> ADD_CLI_RAND
      if(flag == CLI) {
	memcpy(&elem_flow->handshake->cli_rand, handshake->cli_rand, 32);
	elem_flow->handshake->cli_rand[32] = '\0';
      }
      /* add_cli_id(&flow_in, &handshake, len_id); */

      // if serv hello -> ADD_SRV_RAND
      else if(flag == SRV) {
	memcpy(&elem_flow->handshake->srv_rand, handshake->srv_rand, 32);
	elem_flow->handshake->srv_rand[32] = '\0';
	/* memcpy(&elem_flow->handshake->cipher_suite, handshake->cipher_suite, 2); */
	elem_flow->handshake->cipher_suite = handshake->cipher_suite;
      }
      /* add_srv_id(&flow_in, &handshake, len_id); */

      // if cert hello -> UPDATE_CERT
      else if(flag == CERT_S) {
	update_cert(&elem_flow, &handshake, len_id, flag);
	// set handshake fin to T
        elem_flow->is_handsk_fin = T;
      }
      // if Client Key Exch -> (Pre)Master secret
      else if(flag == CKE_PMS) {
	memcpy(&elem_flow->handshake->pre_master_secret, handshake->pre_master_secret, len_id);
	elem_flow->handshake->pre_master_secret[48] = '\0';
      }
      else if(flag == CKE_MS) {
	memcpy(&elem_flow->handshake->master_secret, handshake->master_secret, len_id);
	elem_flow->handshake->master_secret[48] = '\0';
      }
    }
 
    /* THE HANDSHAKE FOR THIS KEY IS COMPLETE */
    else if(elem_flow->is_handsk_fin == T) {
      
      /* if the pkt is a Client Hello, open a new flow for handshake */
      if(flag == CLI) {
	memcpy(&elem_flow->handshake->cli_rand, handshake->cli_rand, 32);
	elem_flow->handshake->cli_rand[32] = '\0';
	/* add_cli_id(&flow_in, &handshake, len_id); */
	
	/* **** IMPORTANT!!! CHECK IF FLOW IS OVERWRITTEN **** */
	
	// add new elem in Hash Table
	HASH_ADD_INT(HT_Flows, KEY, elem_flow);
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
int dissector_tls(const u_char *payload,
		  int size_payload,
		  char decrypted_buff[],
		  int msg_len,
		  u_int16_t src_port,
		  u_int16_t dst_port,
		  const u_int8_t proto_id_l3,
		  struct Flow *flow,
		  int KEY,
		  unsigned char *PVTkey
		  /* char *pvtkey_path */)
{
  struct Hash_Table *el = NULL;
  struct Handshake *handshake = NULL;
  const u_int8_t *pp = payload;
  /* unsigned char *PVTkey = NULL; // PVT KEY path */
  int decrLen = 0;
  int is_tls = 0;

  // call READ_FILE to get the string from key
  /* PVTkey = read_file(pvtkey_path); */
  
  /**
     # HANDSHAKE #
     initialize the handshake structure
  */
  handshake = calloc(1, sizeof(struct Handshake));
  if(!handshake) {
    fprintf(stderr, "error on malloc handshake\n");
    return -1;
  }
  // initialization of handshake struct pointers
  handshake->sessID_c = NULL;
  handshake->sessID_s = NULL;
  handshake->certificate_S = NULL;
  
  /**
     NOTE:
     port 443 is for HTTP over TLS
     port 636 is for LDAP proto tunneling on TLSv1
     port 389 is for LDAP proto tunneling on TLSv1.2
     port 5061 and 5081 is for SIP protocol over TLS
  */
  if(proto_id_l3 == IPPROTO_TCP &&
     ((src_port == 443 || dst_port == 443) ||
      (src_port == 636 || dst_port == 636) ||
      (src_port == 389 || dst_port == 389) ||
      (src_port == 5061 || dst_port == 5061) ||
      (src_port == 5081 || dst_port == 5081))) {

    /** DISSECT THE PACKET **/
  
    struct header_tls_record *hdr_tls_rec = (struct header_tls_record*)(payload);
      
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
    default: {
      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
      goto error; 
    }
    }
    
    // Record Version
    if(ntohs(hdr_tls_rec->version) != TLS1  &&
       ntohs(hdr_tls_rec->version) != TLS11 &&
       ntohs(hdr_tls_rec->version) != TLS12) {
      
      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
      goto error;
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

	switch(hand_hdr->msg_type) {
      
	case CLIENT_HELLO:
	  {
	    is_tls = 1;
	    
	    // set client port direction (need for decryption)
	    client_ = flow->src_port;
	    
	    // check version  
	    if(pp[0] != 0x03 && (pp[1] != 0x01 || pp[1] != 0x02 || pp[1] != 0x03)) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      goto error;
	    }
	    // move foward of 2 bytes
	    pp = pp + 2;
	    // copy cli random bytes
	    memcpy(handshake->cli_rand, pp, 32);
	    handshake->cli_rand[32] = '\0';
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
		goto error;
	      };
	    }
	    else {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      goto error;
	    };
	  }
	case SERVER_HELLO:
	  {
	    is_tls = 1;
	    
	    // check version
	    if(pp[0] != 0x03 && (pp[1] != 0x01 || pp[1] != 0x02 || pp[1] != 0x03)) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      goto error;
	    }	
	    // move foward of 2 bytes
	    pp = pp + 2;
	    // copy serv random bytes
	    memcpy(handshake->srv_rand, pp, 32);
	    handshake->cli_rand[32] = '\0';
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
				 pp[1] != 0x9c)) {

	      fprintf(stderr, "Invalid Chipher Suite. No DHE/EDH availlable for decription\n");
	      goto error;
	    }

	    // add Chipher Suite Server to handshake
	    /* memcpy(handshake->cipher_suite, pp, 2); */
	    if(pp[1] == 0x9d)
	      handshake->cipher_suite = cipher_suites[1];
	    else
	      handshake->cipher_suite = cipher_suites[0];

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
	      goto error;
	    };
	  }
	case CERTIFICATE:
	  {
	    is_tls = 1;
	    
	    u_int16_t hh_len = hand_hdr->len[2] + (hand_hdr->len[1] << 8 ) + (hand_hdr->len[0] << 8);
	    u_int16_t cert_len_total = pp[2] + (pp[1] << 8) + (pp[0] << 8);

	    if((cert_len_total + 3) != hh_len) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      goto error;
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
		/* if(s == 1) */
		/*   save_certificate_FILE(cert, subcert_len); */
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
		  goto error;
		}
		else if(pp[5] == 0x0e) { // jump the SERVER_HELLO_DONE
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
	    is_tls = 1;
	    
	    pp = pp + 1; // Certificate Status Type OCSP (1)
	    u_int16_t cert_status_len = pp[2] + (pp[1] << 8) + (pp[0] << 8);
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + 1 + 3 + cert_status_len;
	    if(offset < size_payload) {
	      pp = pp + 3 + cert_status_len;
	      if(pp[5] != 0x0c && pp[5] != 0x16 && pp[5] != 0x10) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		goto error;
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
	    is_tls = 1;
	    
	    int hand_hdr_len = (hand_hdr->len[2]) + (hand_hdr->len[1] << 8) + (hand_hdr->len[0] << 8);
	    // variable for (Pre) Master Secret
	    int enc_pms_len;
	    int pms_len, ms_ret;
	    // variable for keys
	    int ret, needed = 0, cipher_algo = 0;
	    unsigned char *key_block = NULL, *ptr;
	    unsigned int encr_key_len, write_iv_len = 0;
	    struct _SslDecoder SslDecoder_Client = {0};
	    struct _SslDecoder SslDecoder_Server = {0};
	    
	    
	    if(hand_hdr_len > 33) {
	      /**
		 - RSA: the server's key is of type RSA. 
		 The client generates a random value (the "pre-master secret" of 48 bytes, out of which 46 are random) and encrypts it with the server's public key.
		 There is no ServerKeyExchange.
	      */
	      enc_pms_len = hand_hdr_len - 2;
	      
	      u_int8_t *enc_pre_master_secret = malloc(sizeof(u_int8_t) * enc_pms_len);
	      memset(enc_pre_master_secret, 0, enc_pms_len);
	      
	      // save the enc_pre-master secret
	      memcpy(enc_pre_master_secret, pp + 2, enc_pms_len);
	      
	      /**
		 1) DECRYPT PRE-MASTER SECRET USING SERVER PVT KEY
		 2) CALCULATION OF MASTER SECRET
		 3) DERIVE KEYS NEEDED FROM MASTER SECRET
	      **/

	      // PRE-MASTER SECRET buffer
	      unsigned char PMS[MS_LENGTH+1] = {0}; // 48 + 1
	      // MASTER SECRET buffer
	      unsigned char MS[MS_LENGTH+1] = {0};  // 48 + 1
	      // "master secret" name
	      const char *master_string = "master secret";
	      // "key expansion" name
	      const char *key_string = "key expansion";
	      
	      /**
		 Decription of ENCRYPTED PRE-MASTER SECRET 
	      */
	      pms_len = private_decrypt(enc_pre_master_secret, enc_pms_len, PVTkey, PMS);
	      if(pms_len != MS_LENGTH)
		{
		  fprintf(stderr, "Private Decrypt failed for PreMaster Secret\n");
		  goto error2;
		}
	      // copy pre_master_secret in flow
	      memcpy(handshake->pre_master_secret, PMS, pms_len);
	      handshake->pre_master_secret[48] = '\0';
	      LDEBUG("KEY CKE 1 = %d", KEY);
	      add_flow(flow, KEY, handshake, CKE_PMS, pms_len);

	      /* key already in the hash? */
	      HASH_FIND_INT(HT_Flows, &KEY, el);
	      if(el == NULL) {
		fprintf(stderr, "error! No open flow found\n");
		goto error2;
	      }

	      /**
		 calculate the MASTER SECRET from PRE-MASTER SECRET
	      */
	      ms_ret = PRF(el->handshake, PMS, master_string, MS, MS_LENGTH);
	      if(ms_ret == 0) {
		/* printf("MASTER SECRET = %s\n", MS); */
		// copy master_secret in flow
		memcpy(handshake->master_secret, MS, MS_LENGTH);
		handshake->master_secret[48] = '\0';
		add_flow(flow, KEY, handshake, CKE_MS, MS_LENGTH);
	      }
	      else {
		fprintf(stderr, "error on Master Secret\n");
		goto error2;
	      }
	      
	      /**
		 Calculate KEYS from MASTER SECRET 
	      */
	      const char *cipher_name = NULL;
	      /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
	      if(el->handshake->cipher_suite.enc != ENC_NULL) {
		if(el->handshake->cipher_suite.enc == ENC_AES256)
		  cipher_name = ciphers[1]; /* AES256 */
		else
		  cipher_name = ciphers[0]; /* AES */
		
		cipher_algo = gcry_cipher_map_name(cipher_name);
		if(cipher_algo == 0) {
		  fprintf(stderr, "error on find cipher %s\n", cipher_name);
		  goto error2;
		}
	      }

	      // enc key length
	      encr_key_len = (unsigned int) gcry_cipher_get_algo_keylen(cipher_algo);
	      // block IV len
	      if(el->handshake->cipher_suite.mode == MODE_GCM ||
		 el->handshake->cipher_suite.mode == MODE_CCM ||
		 el->handshake->cipher_suite.mode == MODE_CCM_8)
		write_iv_len = 4;

	      /**
		 Compute the key block. First figure out how much data we need
	      */
	      
	      needed = ssl_cipher_suite_dig(&el->handshake->cipher_suite)->len * 2; /* MAC key */
	      needed += 2 * encr_key_len;                                           /* encryption key */
	      needed += 2 * write_iv_len;                                           /* write IV */

	      // alloc memory for key_block
	      key_block = calloc(needed+1, sizeof(unsigned char));
	      ret = PRF(el->handshake, MS, key_string, key_block, needed);
	      if(ret == -1) {
		fprintf(stderr, "Can't generate key_block\n");
		goto error2;
	      }
	      /* printf("key expansion = %s\n", key_block); */

	      /* alloc memory for write keys and IVs */
	      SslDecoder_Client.w_key = calloc(encr_key_len + 1, sizeof(unsigned char));
	      SslDecoder_Server.w_key = calloc(encr_key_len + 1, sizeof(unsigned char));
	      SslDecoder_Client.iv = calloc(write_iv_len + 1, sizeof(unsigned char));
	      SslDecoder_Server.iv = calloc(write_iv_len + 1, sizeof(unsigned char));
	      
	      ptr = key_block;
	      /* client/server write encryption key */
	      memcpy(SslDecoder_Client.w_key, ptr, encr_key_len);
	      /* c_wk = ptr; */ ptr += encr_key_len;
	      memcpy(SslDecoder_Server.w_key, ptr, encr_key_len);
	      /* s_wk = ptr; */ ptr += encr_key_len;

	      /**
		 client/server write IV (used as IV (for CBC) or salt (for AEAD))
	      */
	      
	      if (write_iv_len > 0) {
		memcpy(SslDecoder_Client.iv, ptr, write_iv_len);
		/* c_iv = ptr; */ ptr += write_iv_len;
		memcpy(SslDecoder_Server.iv, ptr, write_iv_len);
		/* s_iv = ptr; */ /* ptr += write_iv_len; */
	      }

	      // clean up memory
	      free(key_block);
	     
	      /* CREATE DECODER CLIENT */
	      ret = ssl_create_decoder(&SslDecoder_Client, cipher_algo, SslDecoder_Client.w_key, SslDecoder_Client.iv, el->handshake->cipher_suite.mode);
	      if(ret < 0) {
		fprintf(stderr, "Can't create DECODER CLIENT !\n");
		goto error2;
	      }

	      /* CREATE DECODER SERVER */
	      ret = ssl_create_decoder(&SslDecoder_Server, cipher_algo, SslDecoder_Server.w_key, SslDecoder_Server.iv, el->handshake->cipher_suite.mode);
	      if(ret < 0) {
		fprintf(stderr, "Can't create DECODER SERVER !\n");
		goto error2;
	      }

	      // Assign SSL DECODER to Handshake
	      el->handshake->ssl_decoder_cli = SslDecoder_Client;
	      el->handshake->ssl_decoder_srv = SslDecoder_Server;
	      
	      /* ******* */

	    error2: {
		// clean up memory
		free(handshake);
		free(enc_pre_master_secret);
		return -2;
	      }
	      
	      // clean up memory
	      free(enc_pre_master_secret);
	    }	    
	    
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + hand_hdr_len;
	    pp = pp + hand_hdr_len;
	
	    if(offset < size_payload) {
	      if(pp[0] == 0x14) {
		more_records = 1;
		/* break; */
	      }
	      else if (pp[0] != 0x0f) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		goto error;
	      }
	      else {
		more_records = 0;
		break;
	      }
	    }
	    else {
	      more_records = 1;
	      break;
	    }
	    break;
	  }
	case CERTIFICATE_REQUEST:
	  {
	    is_tls = 1;
	    
	    struct Cert_Req *cert_req = (struct Cert_Req*) pp;

	    int hand_hdr_len = (hand_hdr->len[2]) + (hand_hdr->len[1] << 8) + (hand_hdr->len[0] << 8);
	    pp = pp + hand_hdr_len;
	    offset = TLS_HEADER_LEN + HANDSK_HEADER_LEN + sizeof(cert_req) + cert_req->dist_name_len;
	  
	    if(offset < size_payload) {
	      if(pp[0] != 0x0e) {
		fprintf(stderr, "This is not a valid TLS/SSL packet\n");
		goto error;
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
	    is_tls = 1;
	    
	    int hand_hdr_len = (hand_hdr->len[2]) + (hand_hdr->len[1] << 8) + (hand_hdr->len[0] << 8);
	
	    if(hand_hdr_len != 0) {
	      fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	      goto error;
	    }
	    more_records = 1;
	    break;
	  }
	case CERTIFICATE_VERIFY:
	  is_tls = 1;
	  break;

	case NEW_SESSION_TICKET:
	  is_tls = 1;
	  more_records = 1;
	  break;
	  
	case FINISHED:
	  {
	    is_tls = 1;
	    more_records = 1;
	    // THE PAYLOAD IS ECRYPTED
	    break;
	  }
	  
	default:
	  is_tls = 1; // maybe Finished
	  more_records = 1;
	  break;
	  
	} // switch
      } while(more_records == 0);
    }
    
    /**
       CHANGE_CIPHER_SPEC = 20
    **/
    else if(type == CHANGE_CIPHER_SPEC) {
      is_tls = 1;
      pp = pp + TLS_HEADER_LEN;
      if(pp[0] != 0x01) {
	fprintf(stderr, "This is not a valid TLS/SSL packet\n");
	goto error;
      }
    }
    else if(type == ALERT) {
      is_tls = 1;
      /* TODO IF NECESSARY */
    }
    else if(type == APPLICATION_DATA) {

      is_tls = 1;
      
      /* key already in the hash? */
      HASH_FIND_INT(HT_Flows, &KEY, el);
      
      if(el) {
	unsigned char *encrypted = NULL;
	unsigned char *decrypted = NULL;
	u_int16_t len = 0;
	u_int8_t direction = 0; // 0 -> Client/Server  1 -> Server/Client
	int count = 0;

	
	/* CHECK -- FIND SOLUTION IF THERE ARE MORE APP DATA IN THE SAME PKT */
	do {
	  if(count != 0)
	    hdr_tls_rec = (struct header_tls_record*)(payload+count);
	  // move the pointer everytime part of the payload is detected
	  pp = pp + TLS_HEADER_LEN;
	  len = ntohs(hdr_tls_rec->len);
	  count = count + TLS_HEADER_LEN + len;

	  // allocate space for encryption and decryption buffers
	  encrypted = calloc(len+1, sizeof(unsigned char));
	  decrypted = calloc(len+1, sizeof(unsigned char));
	  
	  // copy the ENCRIPTED application data into "encrypted" buffer
	  memcpy(encrypted, pp, len);
	  
	  /* --- DECRYPTION OF PAYLOAD DATA --- */

	  // determine the direction of the data
	  if(flow->src_port == client_) direction = 0;
	  else direction = 1;
	  
	  /**
	     TO PERFORM DECRIPTION WE NEED TO USE THIS FUNCTION
	     INTERNALLY IT IS USED FUNCTION OF GCRYPT LIBRARY
	  **/
	  if(tls_decrypt_aead_record(el->handshake, encrypted, len, decrypted, &decrLen, direction) == -1) {
	    /*** decryption failed ***/
	    
	    // clean up memory
	    free(encrypted);
	    free(decrypted);
	    free(handshake);
	    return -1;
	  }

	  /* copy decrypted buffer to decrypted_buff */
	  memcpy(decrypted_buff, decrypted, decrLen);
	     
	  pp = pp + len;
	  
	} while(count < size_payload);
	// clean up memory
	free(encrypted);
	free(decrypted);
      }
      if(el != NULL)
	return decrLen; // it's TLS
      return 0;
    }
  }
  
 error: {
    // clean up memory
    if(handshake->sessID_c)
      free(handshake->sessID_c);
    if(handshake->sessID_s)
      free(handshake->sessID_s);
    free(handshake);
    return -1;
  }
  
  if(is_tls == 1)
    return 0;
  return -1;
}

#endif
