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
#include "http_log.h"

#include "apr_base64.h"
#include "apr_buckets.h"
#include "apr_hash.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"

#include "util_filter.h"

#include "sodium/utils.h"

#include "utils.h"


apr_hash_t *parse_form_data(apr_pool_t * pool, char *str, int limit)
{
    apr_hash_t *form;
    apr_array_header_t *values;
    int count;
    const char *sep = "&";
    char *last;
    char *key;
    char *value;

    if (str == NULL) {
        return NULL;
    }

    form = apr_hash_make(pool);

    /* Split string on the '&' separator */
    for (key = apr_strtok(str, sep, &last), count = 0;
         key != NULL && count < limit;
         key = apr_strtok(NULL, sep, &last), ++count) {
        for (value = key; *value; ++value) {
            if (*value == '+') {
                *value = ' ';
            }
        }

        /* Split into key / value */
        value = strchr(key, '=');

        /* Unescape */
        if (value) {
            *value = '\0';
            ++value;
            ap_unescape_urlencoded(key);
            ap_unescape_urlencoded(value);
        }
        else {
            value = "";
            ap_unescape_urlencoded(key);
        }

        /* Store in the hash */
        values = apr_hash_get(form, key, APR_HASH_KEY_STRING);
        if (values == NULL) {
            values = apr_array_make(pool, 1, sizeof(char *));
            apr_hash_set(form, key, APR_HASH_KEY_STRING, values);
        }
        APR_ARRAY_PUSH(values, char *) = value;
    }

    return form;
}

apr_size_t read_body(request_rec * r, char **body, apr_size_t limit)
{
    char *body0;
    apr_size_t bytes,           /* Bytes remaining in body buffer
                                 * and bytes read from the brigade */
               count = 0;       /* Bytes read count */
    apr_bucket_brigade *bb;
    apr_status_t status;

    /* Allocate the body buffer */
    body0 = apr_palloc(r->pool, limit + 1);

    /* Create a brigade to pull in data from the input filters */
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    /* Read data from input filters */
    do {
        /* Get the brigade from the input filters */
        status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES,
                                APR_BLOCK_READ, limit);
        if (status == APR_SUCCESS) {
            /* Read data from the brigade */
            bytes = limit - count;
            status = apr_brigade_flatten(bb, body0 + count, &bytes);
            if (status != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, LOG_DEBUG, status, r, "reading bb");
            }
            count += bytes;
        }

        /* Discard the data */
        apr_brigade_cleanup(bb);
    } while ((status == APR_SUCCESS) && (count < limit));

    /* NULL terminate */
    body0[count] = '\0';

    *body = body0;

    return count;
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

int sqrl_base64url_decode(unsigned char *plain, char *encoded)
{
    register char *i;

    /* Convert the URL-safe version back to normal */
    i = encoded;
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
    return apr_base64_decode_binary(plain, encoded);
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
