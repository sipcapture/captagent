/**
   decoder - decode TLS/SSL traffic - save handshake and extract certificate
   Copyright (C) 2016-2017 Michele Campus <fci1908@gmail.com>
   
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
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decription.h"

/* #define PADDING RSA_PKCS1_OAEP_PADDING */
/* #define PADDING RSA_NO_PADDING */
#define PADDING RSA_PKCS1_PADDING
 
RSA * createRSA(unsigned char * key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio ;

  keybio = BIO_new_mem_buf(key, -1);

  if (keybio==NULL) {
    printf( "Failed to create key BIO");
    return 0;
  }
  
  if(public)
      rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  else
      rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  if(rsa == NULL)
    printf("Failed to create RSA");
 
  return rsa;
}

// PRIVATE ENCRIPTION
/* int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted) */
/* { */
/*     RSA * rsa = createRSA(key, 0); */
/*     int result = RSA_private_encrypt(data_len, data, encrypted, rsa, PADDING); */
/*     return result; */
/* } */

// PUBLIC ENCRIPTION
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
  int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, PADDING);
  return result;
}

// PUBLIC DECRIPTION
int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 1);
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, PADDING);
    return result;
}
 
void printLastError(char *msg)
{
  char * err = malloc(130);
  ERR_load_crypto_strings();
  ERR_error_string(ERR_get_error(), err);
  printf("%s ERROR: %s\n", msg, err);
  free(err);
}
