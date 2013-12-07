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

static const char *ck_null(const char *val)
{
    if (val) {
        return val;
    }
    else {
        return "null";
    }
}

const char *sqrl_to_string(apr_pool_t * pool, sqrl_rec * sqrl)
{
    char *timestamp, *nonce, *ip_hash, *key, *sig;

    if (sqrl->nut->timestamp) {
        timestamp = apr_palloc(pool, APR_RFC822_DATE_LEN);
        apr_rfc822_date(timestamp, apr_time_from_sec(sqrl->nut->timestamp));
    }
    else {
        timestamp = "null";
    }
    if (sqrl->nut->nonce) {
        nonce = bin2hex(pool, sqrl->nut->nonce, 4U, NULL);
    }
    else {
        nonce = "null";
    }
    if (sqrl->nut->nonce) {
        ip_hash = bin2hex(pool, sqrl->nut->ip_hash, 4U, NULL);
    }
    else {
        ip_hash = "null";
    }
    if (sqrl->key) {
        key = bin2hex(pool, sqrl->key, sqrl->key_len, NULL);
    }
    else {
        key = "null";
    }
    if (sqrl->sig) {
        sig = bin2hex(pool, sqrl->sig, sqrl->sig_len, NULL);
    }
    else {
        sig = "null";
    }

    return apr_psprintf(pool,
                        "sqrl_rec{url=%s,sqrl_nut_rec{timestamp=%s,counter=%d,"
                        "nonce=%s,ip_hash=%s},nonce=%s,version=%f,"
                        "options=%s,key_len=%d,key=%s,sig_len=%d,sig=%s}",
                        ck_null(sqrl->url), timestamp,
                        (sqrl->nut->counter ? sqrl->nut->counter : 0), nonce,
                        ip_hash, ck_null(sqrl->nonce),
                        (sqrl->version ? sqrl->version : 0.0),
                        (sqrl->options ?
                         apr_array_pstrcat(pool, sqrl->options,
                                           ',') : "null"),
                        (sqrl->key_len ? sqrl->key_len : 0), key,
                        (sqrl->sig_len ? sqrl->sig_len : 0), sig);
}
