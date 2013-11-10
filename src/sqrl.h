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


#define SQRL_OK 0

#define SQRL_SESSION_ID_BYTES crypto_stream_aes256estream_NONCEBYTES

typedef struct
{
    apr_time_t timestamp;
    apr_int32_t counter;
    unsigned char *nonce;
    unsigned char *ip_hash;
} sqrl_nut_rec;

typedef struct
{
    char *url;
    sqrl_nut_rec *nut;
    char *session_id;
    float version;
    apr_array_header_t *options;
    unsigned char *key;
    apr_size_t sig_len;
    unsigned char *sig;
} sqrl_rec;


const char *sqrl_to_string(apr_pool_t * pool, sqrl_rec * sqrl);

int sqrl_create(apr_pool_t * pool, sqrl_rec ** sqrl, const char *scheme,
                const char *domain, const char *additional, const char *path,
                const char *ip_addr, apr_int32_t counter);
