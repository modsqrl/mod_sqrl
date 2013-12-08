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

#include "http_protocol.h"
#include "apr_base64.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "sodium/utils.h"

#include "sqrl.h"
#include "utils.h"


char *get_client_ip(request_rec * r)
{
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
    return r->useragent_ip;
#else
    return r->connection->remote_ip;
#endif
}

char *sqrl_base64url_encode(apr_pool_t * p, const unsigned char *plain,
                            unsigned int plain_len)
{
    char *encoded;
    char *i;
    int base64_len;

    /* Use apache to generate the standard base64 string */
    encoded = apr_palloc(p, apr_base64_encode_len(plain_len) + 1);
    base64_len = apr_base64_encode_binary(encoded, plain, plain_len);
    encoded[base64_len] = '\0';

    /* Make the base64 string URL-safe */
    i = encoded;
    while (*i != '\0') {
        switch (*i) {
        case '+':
            *i = '-';
            break;
        case '/':
            *i = '_';
            break;
        case '=':
            *i = '\0';
            goto loop_end;
            /* default: Valid character */
        }
        ++i;
    }
  loop_end:

    return encoded;
}

unsigned char *sqrl_base64url_decode(apr_pool_t * p, const char *encoded,
                                     int *plain_len)
{
    char *enc = apr_pstrdup(p, encoded);
    unsigned char *plain = apr_palloc(p, strlen(encoded));
    int len;
    register char *i;

    /* Convert the URL-safe version back to normal */
    i = enc;
    while (*i != '\0') {
        switch (*i) {
        case '-':
            *i = '+';
            break;
        case '_':
            *i = '/';
            break;
            /* default: Valid character */
        }
        ++i;
    }

    /* Use apache to generate the standard base64 string */
    len = apr_base64_decode_binary(plain, enc);

    if (plain_len != NULL) {
        *plain_len = len;
    }

    return plain;
}

char *bin2hex(apr_pool_t * p, const unsigned char *bin,
              const apr_size_t binlen, apr_size_t * hexlen)
{
    apr_size_t hexlen0 = binlen * 2U;
    char *hex = apr_palloc(p, hexlen0 + 1U);

    if (hexlen != NULL) {
        *hexlen = hexlen0;
    }

    sodium_bin2hex(hex, hexlen0, bin, binlen);
    *(hex + hexlen0) = '\0';

    return hex;
}

apr_int32_t bytes_to_int32(const unsigned char bytes[4])
{
    return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) |
            (bytes[3]));
}

void int32_to_bytes(unsigned char bytes[4], apr_int32_t integer)
{
    *(bytes + 0) = integer >> 24 & 0xff;
    *(bytes + 1) = integer >> 16 & 0xff;
    *(bytes + 2) = integer >> 8 & 0xff;
    *(bytes + 3) = integer >> 0 & 0xff;
}

#define str_or_null(str) (str ? str : "null")
#define hex_or_null(pool, data, sz) \
    (data ? bin2hex(pool, data, sz, NULL) : "null")

static const char *ck_null(const char *val)
{
    if (val) {
        return val;
    }
    else {
        return "null";
    }
}

const char *sqrl_nut_to_string(apr_pool_t * pool, const sqrl_nut_rec * nut)
{
    char *timestamp;

    if (nut->timestamp) {
        timestamp = apr_palloc(pool, APR_RFC822_DATE_LEN);
        apr_rfc822_date(timestamp, apr_time_from_sec(nut->timestamp));
    }
    else {
        timestamp = "null";
    }

    return apr_psprintf(pool,
                        "sqrl_nut_rec{timestamp=%s,counter=%d,"
                        "nonce=%s,ip_hash=%s}",
                        timestamp, (nut->counter ? nut->counter : 0),
                        hex_or_null(pool, nut->nonce, 4U),
                        hex_or_null(pool, nut->ip_hash, 4U));
}

const char *sqrl_to_string(apr_pool_t * pool, const sqrl_rec * sqrl)
{
    const char *nut;

    if (sqrl->nut) {
        nut = sqrl_nut_to_string(pool, sqrl->nut);
    }
    else {
        nut = "null";
    }

    return apr_psprintf(pool,
                        "sqrl_rec{uri=%s,nut=%s,nut64=%s,nonce=%s}",
                        ck_null(sqrl->uri), nut,
                        str_or_null(sqrl->nut64), ck_null(sqrl->nonce));
}

const char *sqrl_client_args_to_string(apr_pool_t * pool,
                                       const sqrl_client_args_rec * args)
{
    char *options;

    options =
        (args->
         options ? apr_array_pstrcat(pool, args->options, ',') : "null");
    /*if (args->key) {
       key = bin2hex(pool, args->key, SQRL_PUBLIC_KEY_BYTES, NULL);
       }
       else {
       key = "null";
       } */
    //hex_or_null(pool, key, args->key, SQRL_PUBLIC_KEY_BYTES);

    return apr_psprintf(pool,
                        "sqrl_client_args_rec{version=%s,options=%s,key=%s}",
                        ck_null(args->version), options,
                        hex_or_null(pool, args->key, SQRL_PUBLIC_KEY_BYTES));
}

const char *sqrl_req_to_string(apr_pool_t * pool, const sqrl_req_rec * req)
{
    const char *client_args, *sqrl;

    if (req->client_args) {
        client_args = sqrl_client_args_to_string(pool, req->client_args);
    }
    else {
        client_args = "null";
    }
    if (req->sqrl) {
        sqrl = sqrl_to_string(pool, req->sqrl);
    }
    else {
        sqrl = "null";
    }

    return apr_psprintf(pool,
                        "sqrl_req_rec{raw_clientarg=%s,client_args=%s,"
                        "raw_serverurl=%s,server_uri=%s,sqrl=%s,"
                        "raw_usrsig=%s,usr_sig=%s}",
                        str_or_null(req->raw_clientarg),
                        client_args,
                        str_or_null(req->raw_serverurl),
                        str_or_null(req->server_uri),
                        sqrl,
                        str_or_null(req->raw_usrsig),
                        hex_or_null(pool, req->usr_sig, SQRL_SIGN_BYTES));
}

apr_status_t write_out(request_rec * r, const char *response)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    b = apr_bucket_immortal_create(response, strlen(response),
                                   bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));
    return ap_pass_brigade(r->output_filters, bb);
}
