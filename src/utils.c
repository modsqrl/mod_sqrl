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

#include "sodium/utils.h"

#include "utils.h"


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
