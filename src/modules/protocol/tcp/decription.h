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
#ifndef DECRIPTION_H_
#define DECRIPTION_H_

#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>


/* Create a RSA structure */
RSA * createRSA(unsigned char * key, int public);

// PRIVATE ENCRIPTION
int private_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);

// PUBLIC ENCRIPTION
int public_encrypt(unsigned char * data, int data_len, unsigned char * key, unsigned char *encrypted);

// PRIVATE DECRIPTION
int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted);

// PUBLIC DECRIPTION
int public_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted);

// Print error
void printLastError(char *msg);

#endif
