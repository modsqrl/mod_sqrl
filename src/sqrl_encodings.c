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

#include "apr_pools.h"
#include "sodium/utils.h"

char *sqrl_base64_encode(apr_pool_t * p, const unsigned char * plain,
                         size_t plain_len)
{
    char *b64, *b;
    size_t i = plain_len / 3U, r = plain_len % 3U;
    static char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "abcdefghijklmnopqrstuvwxyz"
                          "0123456789-_";        // +/

    b64 = b = (char*)apr_palloc(p, 4U * i + 1U);

    while (i-- > 0) {
        *b++ = alpha[plain[0] >> 2];
        *b++ = alpha[((plain[0] & 0x03) << 4) | ((plain[1] & 0xf0) >> 4)];
        *b++ = alpha[((plain[1] & 0x0f) << 2) | ((plain[2] & 0xc0) >> 6)];
        *b++ = alpha[plain[2] & 0x3f];
        plain += 3;
    }
    switch (r) {
    case 1U:
        *b++ = alpha[*plain >> 2];
        *b++ = alpha[((*plain & 0x03) << 4)];
        ++plain;
        break;
    case 2U:
        *b++ = alpha[*plain >> 2];
        *b++ = alpha[((*plain & 0x03) << 4) | ((plain[1] & 0xf0) >> 4)];
        *b++ = alpha[((plain[1] & 0x0f) << 2)];
        ++plain;
    }
    *b = '\0';

    return b64;
}

unsigned char *sqrl_base64_decode(apr_pool_t * p, const char *b64,
                                  size_t * plain_len)
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

    if (plain_len) {
        *plain_len = 0;
    }

    str = s = (unsigned char*)apr_palloc(p, b64_len);

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

    if (plain_len) {
        *plain_len = s - str - 1;
    }

    return str;
}

char *bin2hex(apr_pool_t * p, const unsigned char *bin,
              const size_t binlen, size_t * hexlen)
{
    size_t hexlen0 = binlen * 2U;
    char *hex = (char*)apr_palloc(p, hexlen0 + 1U);

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

