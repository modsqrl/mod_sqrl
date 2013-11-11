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
#include "apr_strings.h"
#include "apr_time.h"

#include "sodium/crypto_auth.h"
#include "sodium/crypto_hash.h"
#include "sodium/crypto_sign.h"
#include "sodium/crypto_stream_aes256estream.h"
#include "sodium/randombytes.h"
#include "sodium/utils.h"

#include "sqrl.h"
#include "utils.h"


static char *ck_null(char *val)
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
        key =
            bin2hex(pool, sqrl->key, crypto_sign_ed25519_PUBLICKEYBYTES,
                    NULL);
    }
    else {
        key = "null";
    }
    if (sqrl->sig) {
        sig =
            bin2hex(pool, sqrl->sig, crypto_sign_ed25519_SECRETKEYBYTES,
                    NULL);
    }
    else {
        sig = "null";
    }

    return apr_psprintf(pool,
                        "sqrl_rec{url=%s,sqrl_nut_rec{timestamp=%s,counter=%d,nonce=%s,ip_hash=%s},session_id=%s,version=%f,key=%s,sig_len=%lu,sig=%s}",
                        ck_null(sqrl->url), timestamp,
                        (sqrl->nut->counter ? sqrl->nut->counter : 0), nonce,
                        ip_hash, ck_null(sqrl->session_id),
                        (sqrl->version ? sqrl->version : 0.0), key,
                        (sqrl->sig_len ? sqrl->sig_len : 0), sig);
}

int sqrl_create(apr_pool_t * pool, sqrl_rec ** sqrl, const char *scheme,
                const char *domain, const char *additional, const char *path,
                const char *ip_addr, apr_int32_t counter)
{
    sqrl_rec *sq;
    unsigned char *session_id_bytes;
    apr_size_t ip_len;
    unsigned char *ip_buff;
    unsigned char *nut_buff;
    char *nut64;

    sq = apr_palloc(pool, sizeof(sqrl_rec));

    /* Generate a session id */
    session_id_bytes = apr_palloc(pool, SQRL_SESSION_ID_BYTES);
    /* libsodium PRNG */
    randombytes(session_id_bytes, SQRL_SESSION_ID_BYTES);

    /* Convert the session id to base64 */
    sq->session_id =
        sqrl_base64url_encode(pool, session_id_bytes, SQRL_SESSION_ID_BYTES);

    /* Build the nut struct */
    sq->nut = apr_palloc(pool, sizeof(sqrl_nut_rec));
    sq->nut->timestamp = apr_time_sec(apr_time_now());
    sq->nut->counter = counter;
    sq->nut->nonce = apr_palloc(pool, 4);
    randombytes(sq->nut->nonce, 4);

    /* Build a salted IP */
    ip_len = strlen(ip_addr);
    ip_buff = apr_palloc(pool, 12 + ip_len);
    /* Add the current time */
    int32_to_bytes(ip_buff, (apr_int32_t) sq->nut->timestamp);
    /* Add the counter */
    int32_to_bytes((ip_buff + 4), sq->nut->counter);
    /* Add a nonce */
    memcpy((ip_buff + 8), sq->nut->nonce, 4);
    /* Add the IP */
    memcpy((ip_buff + 12), ip_addr, ip_len);

    /* Hash the salted IP and add to the nut struct */
    sq->nut->ip_hash = apr_palloc(pool, crypto_hash_BYTES);
    crypto_hash(sq->nut->ip_hash, ip_buff, (12 + ip_len));

    /* Build the authentication URL's nut */
    nut_buff = apr_palloc(pool, 16);
    memcpy(nut_buff, ip_buff, 12);
    memcpy((nut_buff + 12), sq->nut->ip_hash, 4);

    /* TODO encrypt nut_buff before base64 encoding */

    /* Encode the nut as base64 */
    nut64 = sqrl_base64url_encode(pool, nut_buff, 16);

    /* Generate the url */
    if (additional && strlen(additional) > 1) {
        sq->url =
            apr_pstrcat(pool, scheme, "://", domain, additional, "|", path,
                        "?nut=", nut64, "&sid=", sq->session_id, NULL);
    }
    else {
        sq->url =
            apr_pstrcat(pool, scheme, "://", domain, "/", path, "?nut=",
                        nut64, "&sid=", sq->session_id, NULL);
    }

    /* Initialize the remaining fields */
    sq->version = 0.0;
    sq->options = NULL;
    sq->key = NULL;
    sq->sig_len = 0;
    sq->sig = NULL;

    /* Set sqrl */
    *sqrl = sq;

    return SQRL_OK;
}
