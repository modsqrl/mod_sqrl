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

#include "apr_tables.h"
#include "sodium/crypto_stream_aes256estream.h"
#include "sodium/crypto_sign_ed25519.h"


#define SQRL_OK 0
#define SQRL_MISSING_NUT 1
#define SQRL_INVALID_NUT 2
#define SQRL_MISSING_SID 3
#define SQRL_INVALID_SID 4
#define SQRL_MISSING_KEY 5
#define SQRL_INVALID_KEY 6
#define SQRL_MISSING_SIG 7
#define SQRL_INVALID_SIG 8
#define SQRL_INVALID_VER 9

#define SQRL_SESSION_ID_BYTES crypto_stream_aes256estream_NONCEBYTES
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
    apr_time_t timestamp;
    apr_int32_t counter;
    unsigned char *nonce;
    unsigned char *ip_hash;
} sqrl_nut_rec;

typedef struct
{
    const char *url;
    const sqrl_nut_rec *nut;
    const char *session_id;
    float version;
    const apr_array_header_t *options;
    int key_len;
    const unsigned char *key;
    int sig_len;
    const unsigned char *sig;
} sqrl_rec;


const char *sqrl_to_string(apr_pool_t * pool, sqrl_rec * sqrl);

int sqrl_create(apr_pool_t * pool, sqrl_rec ** sqrl, const char *scheme,
                const char *domain, const char *additional, const char *path,
                const char *ip_addr, apr_int32_t counter);

int sqrl_verify(apr_pool_t * pool, const sqrl_rec * sqrl);
