/**
   decoder - decode TLS/SSL traffic - save handshake and extract certificate
   Copyright (C) 2016-2018 Michele Campus <fci1908@gmail.com>
             (C) QXIP BV 2012-2017 (http://qxip.net)
   
   This file is part of decoder.
   
   decoder is free software: you can redistribute it and/or modify it under the
   terms of the GNU General Public License as published by the Free Software
   Foundation, either version 3 of the License, or (at your option) any later
   version.
   
   decoder is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE. See the GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License along with
   decoder. If not, see <http://www.gnu.org/licenses/>.
**/

#include "config.h"

#ifdef USE_SSL

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "decryption.h"

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

/* #define PADDING RSA_PKCS1_OAEP_PADDING */
/* #define PADDING RSA_NO_PADDING */
#define PADDING RSA_PKCS1_PADDING

#define SSL_HMAC gcry_md_hd_t


/* ******************** EXTERN *************************** */

const SslDigestAlgo digests[] = {
  { "SHA256", 32 },
  { "SHA384", 48 },
};

const SslCipherSuite cipher_suites[] = {
  /* TLS_RSA_WITH_AES_128_GCM_SHA256 (4,128,128) */
  { 0x009c, KEX_RSA, ENC_AES, DIG_SHA256, MODE_GCM },
  /* TLS_RSA_WITH_AES_256_GCM_SHA384 (4,256,256) */ 
  { 0x009d, KEX_RSA, ENC_AES256, DIG_SHA384, MODE_GCM },
};

const SslDigestAlgo *ssl_cipher_suite_dig(const SslCipherSuite *cs) {
  if(cs->number == 0x009d)
    return &digests[1];
  else
    return &digests[0];
}
/* ******************************************************* */

/* *********** RSA  with private/public key ************** */
RSA *createRSA(unsigned char * key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio = NULL;

  keybio = BIO_new_mem_buf(key, -1);

  if(keybio == NULL) {
    printf( "Failed to create key BIO");
    return NULL;
  }
  
  if(public)
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, /* &rsa */NULL, NULL, NULL);
  else
    rsa = PEM_read_bio_RSAPrivateKey(keybio, /* &rsa */NULL, NULL, NULL);
  
  if(rsa == NULL) {
    printf("Failed to create RSA");
    // clean up memory
    free(keybio);
    return NULL;
  }

  // clean up memory
  free(keybio);
  
  return rsa;
}

// PRIVATE ENCRIPTION
/* int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted) */
/* { */
/*     RSA * rsa = createRSA(key, 0); */
/*     int result = RSA_private_encrypt(data_len, data, encrypted, rsa, PADDING); */
/*     return result; */
/* } */

/* // PUBLIC ENCRIPTION */
/* int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted) */
/* { */
/*   RSA * rsa = createRSA(key, 1); */
/*   int result = RSA_public_encrypt(data_len, data, encrypted, rsa, PADDING); */
/*   return result; */
/* } */

// PRIVATE DECRIPTION
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
  RSA * rsa = createRSA(key, 0);
  if(rsa == NULL)
    return -1;
  int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, PADDING);
  if(result == -1) {
    fprintf(stderr, "error on RSA_private_decrypt\n");
    free(rsa);
    return -1;
  }
  // clean up memory
  free(rsa);
  
  return result;
}

// PUBLIC DECRIPTION
/* int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted) */
/* { */
/*     RSA * rsa = createRSA(key, 1); */
/*     int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, PADDING); */
/*     return result; */
/* } */
/* ************************************************************************************************* */

/******************** FUNCTIONS FOR TLS_HASH ********************/

// SSL_HMAC_INIT
static inline int ssl_hmac_init(SSL_HMAC *hm, const void *key, int len, int algo)
{
  gcry_error_t err;
  const char *err_str = NULL, *err_src = NULL;
  
  err = gcry_md_open(hm, algo, GCRY_MD_FLAG_HMAC);
  if(err != 0) {
    err_str = gcry_strerror(err);
    err_src = gcry_strsource(err);
    printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
    return -1;
  }
  
  gcry_md_setkey(*(hm), key, len);
  return 0;
}
// SSL_HMAC_UPDATE
static inline void ssl_hmac_update(SSL_HMAC *hm, const void *data, int len)
{
  gcry_md_write(*(hm), data, len);
}
// SSL_HMAC_FINAL
static inline void ssl_hmac_final(SSL_HMAC *hm, unsigned char *data, unsigned int *datalen)
{
  int algo;
  unsigned int len;

  algo = gcry_md_get_algo (*(hm));
  len = gcry_md_get_algo_dlen(algo);
  /* DISSECTOR_ASSERT(len <= *datalen); */
  memcpy(data, gcry_md_read(*(hm), algo), len);
  *datalen = len;
}
// SSL_HMAC_CLEANUP
static inline void ssl_hmac_cleanup(SSL_HMAC *hm)
{
  gcry_md_close(*(hm));
}
/* ********************************************** */

/**
   HASH FUNCTION (RFC 2246):
   
   P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
   A(0) = seed
   A(i) = HMAC_hash(secret, A(i - 1))
*/
static void tls_hash(unsigned char *secret, unsigned char *seed,
		     u_int8_t seed_len, int md, unsigned char *out,
		     int out_len)
{
  u_int8_t  *ptr = NULL;
  u_int32_t residual, tocpy;
  u_int8_t  *A = NULL;
  u_int8_t  _A[MS_LENGTH], tmp[MS_LENGTH]; // 48
  u_int32_t A_l, tmp_l;
  SSL_HMAC  hm;

  ptr = out;
  residual = out_len;

  /* A(0) = seed */
  A = seed;
  A_l = seed_len;

  while(residual) {
    /* A(i) = HMAC_hash(secret, A(i-1)) */
    ssl_hmac_init(&hm, secret, MS_LENGTH, md);
    ssl_hmac_update(&hm, A, A_l);
    A_l = sizeof(_A); /* upper bound len for hash output */
    ssl_hmac_final(&hm, _A, &A_l);
    ssl_hmac_cleanup(&hm);
    A = _A;
    
    /* HMAC_hash(secret, A(i) + seed) */
    ssl_hmac_init(&hm, secret, MS_LENGTH, md);
    ssl_hmac_update(&hm, A, A_l);
    ssl_hmac_update(&hm, seed, seed_len);
    tmp_l = sizeof(tmp); /* upper bound len for hash output */
    ssl_hmac_final(&hm, tmp, &tmp_l);
    ssl_hmac_cleanup(&hm);
    
    /* ssl_hmac_final puts the actual digest output size in tmp_l */
    tocpy = MIN(residual, tmp_l);
    memcpy(ptr, tmp, tocpy);
    ptr += tocpy;
    residual -= tocpy;
  }
  
}

// Internal function for PRF pseudo-random function
int tls12_prf(int md, unsigned char *secret, const char *usage,
		     u_int8_t *rnd1, u_int8_t *rnd2, unsigned char *out,
		     u_int8_t out_len)
{
  u_int8_t usage_len, seed_len, tot;
  unsigned char *_seed = NULL;
  unsigned char *ptr = NULL;

  usage_len = strlen(usage);
  tot = usage_len + 32 + 32; // 32 length of cli_rand and srv_rand

  // allocation data for seed buffer (need for Master Secret)
  _seed = malloc(sizeof(unsigned char) * tot);
  if(!_seed) {
    errno = ENOMEM;
    perror("error %d on malloc in tls12_prf\n");
    return -1;
  }
  ptr = _seed;
  
  // concatenation of seed + random client + random server
  memcpy(ptr, usage, usage_len); ptr += usage_len;
  memcpy(ptr, rnd1, 32); ptr += 32;
  memcpy(ptr, rnd2, 32); ptr += 32;

  seed_len = (int) strlen((char*) _seed);

  // apply the hash function (HMAC and the Pseudo Random function)
  tls_hash(secret, _seed, seed_len, md, out, out_len);

  return 0;
}

#endif

/* ********************************************************************** */
