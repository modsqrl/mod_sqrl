/*
Copyright 2013 modsqrl

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "httpd.h"
#include "apr_tables.h"
#include "sodium/crypto_stream_aes256estream.h"
#include "sodium/crypto_sign_ed25519.h"


#ifndef SQRL_H
#define SQRL_H


#define SQRL_OK 0
#define SQRL_MISSING_CLIENTARG 1
#define SQRL_INVALID_CLIENTARG 2
#define SQRL_MISSING_SERVERURL 3
#define SQRL_INVALID_SERVERURL 4
#define SQRL_MISSING_NUT 5
#define SQRL_INVALID_NUT 6
#define SQRL_MISSING_SID 7
#define SQRL_INVALID_SID 8
#define SQRL_MISSING_KEY 9
#define SQRL_INVALID_KEY 10
#define SQRL_MISSING_SIG 11
#define SQRL_INVALID_SIG 12
#define SQRL_INVALID_VER 13
#define SQRL_EXPIRED_NUT 14
#define SQRL_MISMATCH_IP 15

#define SQRL_NONCE_BYTES crypto_stream_aes256estream_NONCEBYTES
#define SQRL_ENCRYPTION_KEY_BYTES crypto_stream_aes256estream_KEYBYTES
#define SQRL_SIGN_BYTES crypto_sign_ed25519_BYTES
#define SQRL_PUBLIC_KEY_BYTES crypto_sign_ed25519_PUBLICKEYBYTES
#define SQRL_PRIVATE_KEY_BYTES crypto_sign_ed25519_SECRETKEYBYTES

#define sqrl_crypto_sign_keypair(pk, sk)\
        crypto_sign_ed25519_keypair(pk, sk)
#define sqrl_crypto_sign(sm, smlen, m, mlen, sk)\
        crypto_sign_ed25519(sm, smlen, m, mlen, sk)
#define sqrl_crypto_sign_open(m, mlen, sm, smlen, pk)\
        crypto_sign_ed25519_open(m, mlen, sm, smlen, pk)

typedef struct
{
    apr_int32_t timestamp;
    apr_int32_t counter;
    unsigned char *nonce;
    unsigned char *ip_hash;
} sqrl_nut_rec;

typedef struct
{
    const char *uri;
    const sqrl_nut_rec *nut;
    const char *nut64;
    const char *nonce;
} sqrl_rec;

typedef struct
{
    const char *version;
    const apr_array_header_t *options;
    const unsigned char *key;
} sqrl_client_args_rec;

typedef struct
{
    const char *raw_clientarg;
    const sqrl_client_args_rec *client_args;
    const char *raw_serverurl;
    const char *server_uri;
    const sqrl_rec *sqrl;
    const char *raw_usrsig;
    const unsigned char *usr_sig;
    const char *raw_newsig;
    const unsigned char *new_sig;
    const char *raw_iuksig;
    const unsigned char *iuk_sig;
} sqrl_req_rec;


sqrl_rec *sqrl_create(request_rec * r);

apr_status_t sqrl_parse(request_rec * r, sqrl_rec ** sqrl,
                        const char *sqrl_uri);

int sqrl_verify(apr_pool_t * pool, const sqrl_req_rec * sqrl_req);


#endif
