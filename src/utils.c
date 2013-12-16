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

#include "ctype.h"
#include "http_protocol.h"
#include "apr_base64.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"
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

char *trim(char *str)
{
    register char *s = str;

    if(str == NULL){
        return NULL;
    }

    /* Scan over the leading whitespace */
    while(isspace(*s)) {
        ++s;
    }
    str = s;

    /* Scan to the end */
    while(*s != '\0') {
        ++s;
    }

    /* Scan over the trailing whitespace */
    while(isspace(*(s-1))) {
        --s;
    }
    *s = '\0';

    return str;
}

apr_table_t *parse_parameters(apr_pool_t * p, char *params)
{
    char *param, *value, *last;
    apr_array_header_t *param_array;
    apr_table_t *param_table;

    /* Parse each line into an array */
    param_array = apr_array_make(p, 3, sizeof(char*));
    for (param = apr_strtok(params, "\r\n", &last) ;
         param != NULL ; param = apr_strtok(NULL, "\r\n", &last)) {
        APR_ARRAY_PUSH(param_array, char*) = param;
    }

    /* Parse each name=value into a table */
    param_table = apr_table_make(p, param_array->nelts);
    while(param_array->nelts > 0) {
        param = *(char**)apr_array_pop(param_array);
        /* Get the parameter name */
        param = trim(apr_strtok(param, "=", &last));
        /* Skip it if it's empty */
        if(*param == '\0') {
            continue;
        }
        /* Get the parameter value */
        value = trim(apr_strtok(NULL, "\0", &last));
        /* If only the name was given, value will be null */
        if(value == NULL) {
            apr_table_setn(param_table, param, "");
        }
        else {
            apr_table_setn(param_table, param, value);
        }
    }

    return param_table;
}

char *sqrl_base64_encode(apr_pool_t * p, const uchar *plain,
                          size_t plain_len)
{
    char *b64, *b;
    size_t i = plain_len / 3U, r = plain_len % 3U;
    static char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" "0123456789-_";        // +/

    b64 = b = apr_palloc(p, 4U * i + 1);

    while (i-- > 0) {
        *b++ = alpha[plain[0] >> 2];
        *b++ = alpha[((plain[0] & 0x03) << 4) | ((plain[1] & 0xf0) >> 4)];
        *b++ = alpha[((plain[1] & 0x0f) << 2) | ((plain[2] & 0xc0) >> 6)];
        *b++ = alpha[plain[2] & 0x3f];
        plain += 3;
    }
    switch (r) {
    case 1:
        *b++ = alpha[*plain >> 2];
        *b++ = alpha[((*plain & 0x03) << 4)];
        ++plain;
        break;
    case 2:
        *b++ = alpha[*plain >> 2];
        *b++ = alpha[((*plain & 0x03) << 4) | ((plain[1] & 0xf0) >> 4)];
        *b++ = alpha[((plain[1] & 0x0f) << 2)];
        ++plain;
    }
    *b = '\0';

    return b64;
}

uchar *sqrl_base64_decode(apr_pool_t * p, const char *b64,
                                   size_t *plain_len)
{
    unsigned char *str, *s, *sb;
    size_t b64_len = strlen(b64), i = b64_len / 4U, r = b64_len % 4U;
    static const char nib[] = { 62, -1, -1, 52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1,
        -1, -1, 63, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };
    static const char niblen = sizeof(nib);

    if(plain_len) {
        *plain_len = 0;
    }

    str = s = apr_palloc(p, b64_len);

    while (b64_len-- > 0) {
        *s++ = (*b64++) - 45;
    }

#define invalid(i) (sb[i] < 0 || sb[i] > niblen)
#define get(i) nib[sb[i]]

    s = sb = str;
    while (i-- > 0) {
        if (invalid(0) || invalid(1) || invalid(2) || invalid(3)) {
            return NULL;
        }
        *s++ = (get(0) << 2) | (get(1) >> 4);
        *s++ = (get(1) << 4) | (get(2) >> 2);
        *s++ = ((get(2) << 6) & 0xc0) | get(3);
        sb += 4;
    }
    switch (r) {
    case 1:
        return NULL;
        break;
    case 2:
        if (invalid(0) || invalid(1)) {
            return NULL;
        }
        *s++ = (get(0) << 2) | (get(1) >> 4);
        *s++ = (get(1) << 4);
        break;
    case 3:
        if (invalid(0) || invalid(1) || invalid(2)) {
            return NULL;
        }
        *s++ = (get(0) << 2) | (get(1) >> 4);
        *s++ = (get(1) << 4) | (get(2) >> 2);
        *s++ = ((get(2) << 6) & 0xc0);
        break;
    }
    *s = '\0';

    if(plain_len) {
        *plain_len = s - str - 1;
    }

    return str;
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

const char *sqrl_client_to_string(apr_pool_t * pool,
                                       const sqrl_client_rec * args)
{
    return apr_psprintf(pool,
                        "sqrl_client_rec{version=%s,key=%s}",
                        ck_null(args->version),
                        hex_or_null(pool, args->idk, SQRL_PUBLIC_KEY_BYTES));
}

const char *sqrl_req_to_string(apr_pool_t * pool, const sqrl_req_rec * req)
{
    const char *client, *sqrl;

    if (req->client) {
        client = sqrl_client_to_string(pool, req->client);
    }
    else {
        client = "null";
    }
    if (req->sqrl) {
        sqrl = sqrl_to_string(pool, req->sqrl);
    }
    else {
        sqrl = "null";
    }

    return apr_psprintf(pool,
                        "sqrl_req_rec{raw_client=%s,client=%s,"
                        "raw_server=%s,server=%s,sqrl=%s,"
                        "raw_ids=%s,ids=%s}",
                        str_or_null(req->raw_client),
                        client,
                        str_or_null(req->raw_server),
                        str_or_null(req->server),
                        sqrl,
                        str_or_null(req->raw_ids),
                        hex_or_null(pool, req->ids, SQRL_SIGN_BYTES));
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
