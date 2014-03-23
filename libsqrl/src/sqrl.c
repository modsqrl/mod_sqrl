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
#include "string.h"

#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "apreq2/apreq_module.h"
#include "apreq2/apreq_util.h"

#include "sodium/core.h"
#include "sodium/randombytes.h"
#include "sodium/utils.h"
#include "sodium/version.h"

#include "sqrl.h"
#include "sqrl_encodings.h"


/*
 * Remove whitespace from the beginning and end of a string. The only change
 * to the supplied string is the resetting of the terminating '\0'.
 * @param str String to trim.
 * @return Pointer to the first non-whitespace character in the string.
 */
char *trim(char *str)
{
    register char *s = str;

    if (str == NULL) {
        return NULL;
    }

    /* Scan over the leading whitespace */
    while (isspace(*s)) {
        ++s;
    }
    str = s;

    /* Scan to the end */
    while (*s != '\0') {
        ++s;
    }

    /* Scan over the trailing whitespace */
    while (isspace(*(s - 1))) {
        --s;
    }
    *s = '\0';

    return str;
}

/*
 * Parse name/value pairs into a table. There must be one pair per line and
 * pairs must be formated as name=value.
 * @param p Memory pool to allocate the table.
 * @param params Parameters to parse.
 * @return Table of parameters.
 */
apr_table_t *parse_parameters(apr_pool_t * p, char *params)
{
    char *param, *value, *last;
    apr_array_header_t *param_array;
    apr_table_t *param_table;

    /* Parse each line into an array */
    param_array = apr_array_make(p, 3, sizeof(char *));
    for (param = apr_strtok(params, "\r\n", &last);
         param != NULL; param = apr_strtok(NULL, "\r\n", &last)) {
        APR_ARRAY_PUSH(param_array, char *) = param;
    }

    /* Parse each name=value into a table */
    param_table = apr_table_make(p, param_array->nelts);
    while (param_array->nelts > 0) {
        param = *(char **) apr_array_pop(param_array);
        /* Get the parameter name */
        param = trim(apr_strtok(param, "=", &last));
        /* Skip it if it's empty */
        if (*param == '\0') {
            continue;
        }
        /* Get the parameter value */
        value = trim(apr_strtok(NULL, "\0", &last));
        /* If only the name was given, value will be null */
        if (value == NULL) {
            apr_table_setn(param_table, param, "");
        }
        else {
            apr_table_setn(param_table, param, value);
        }
    }

    return param_table;
}

unsigned char *get_ip_hash(apr_pool_t * p, const char *ip, const char *nonce)
{
    size_t ip_len, nonce_len;
    unsigned char *ip_buff, *ip_hash;

    ip_len = strlen(ip);
    nonce_len = strlen(nonce);

    ip_buff = (unsigned char *) apr_palloc(p, ip_len + nonce_len);
    /* Add the IP */
    memcpy(ip_buff, ip, ip_len);
    /* Add the nonce */
    memcpy((ip_buff + ip_len), nonce, nonce_len);

    /* Hash the salted IP and add to the nut struct */
    ip_hash = (unsigned char *) apr_palloc(p, SQRL_HASH_BYTES);
    sqrl_hash_impl(ip_hash, ip_buff, (ip_len + nonce_len));

    return ip_hash;
}

sqrl_rec *sqrl_create(apr_pool_t * pool, sqrl_svr_cfg * sconf,
                      sqrl_dir_cfg * dconf, char *ip)
{
    sqrl_rec *sqrl;
    const char *scheme, *domain, *realm, *path;
    sqrl_nut_rec *nut;
    unsigned char *nonce_bytes;
    unsigned char *nut_buff;
    unsigned char *nut_crypt;

    scheme = sconf->scheme;
    domain = sconf->domain;
    realm = dconf->realm;
    path = dconf->path;

    /* Log config
       ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
       "scheme = %s, domain = %s, realm = %s, path = %s",
       scheme, domain, (realm == NULL ? "null" : realm), path);
       ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "nut_key = %s",
       bin2hex(r->pool, sconf->nut_key, SQRL_ENCRYPTION_KEY_BYTES,
       NULL)); */

    /* Allocate the sqrl struct */
    sqrl = (sqrl_rec *) apr_palloc(pool, sizeof(sqrl_rec));

    /* Generate a nonce */
    nonce_bytes = (unsigned char *) apr_palloc(pool, SQRL_NONCE_BYTES);
    /* libsodium PRNG */
    randombytes(nonce_bytes, SQRL_NONCE_BYTES);

    /* Convert the nonce to base64 */
    sqrl->nonce = sqrl_base64_encode(pool, nonce_bytes, SQRL_NONCE_BYTES);

    /* Increment the counter */
    ++sconf->counter;           /* TODO increment_and_get() */

    /* Build the nut struct */
    nut = (sqrl_nut_rec *) apr_palloc(pool, sizeof(sqrl_nut_rec));
    nut->timestamp = apr_time_sec(apr_time_now());
    nut->counter = sconf->counter;
    nut->nonce = (unsigned char *) apr_palloc(pool, 4);
    randombytes(nut->nonce, 4);
    nut->ip_hash = get_ip_hash(pool, ip, sqrl->nonce);

    /* Set nut */
    sqrl->nut = nut;

    /* Build the authentication URL's nut */
    nut_buff = (unsigned char *) apr_palloc(pool, 16);
    /* Add the current time */
    int32_to_bytes(nut_buff, nut->timestamp);
    /* Add the counter */
    int32_to_bytes((nut_buff + 4), nut->counter);
    /* Add a nonce */
    memcpy((nut_buff + 8), nut->nonce, 4);
    /* Add the IP */
    memcpy((nut_buff + 12), nut->ip_hash, 4);

    /* Encrypt the nut */
    nut_crypt = (unsigned char *) apr_palloc(pool, 16U);
    sqrl_crypto_stream_impl(nut_crypt, nut_buff, 16U, nonce_bytes,
                            sconf->nut_key);

    /* Encode the nut as base64 */
    sqrl->nut64 = sqrl_base64_encode(pool, nut_crypt, 16U);

    /* Generate the url */
    if (realm && strlen(realm) > 1) {
        sqrl->uri =
            apr_pstrcat(pool, scheme, "://", domain, realm, "|", path,
                        "?nut=", sqrl->nut64, "&n=", sqrl->nonce, NULL);
    }
    else {
        sqrl->uri =
            apr_pstrcat(pool, scheme, "://", domain, "/", path, "?nut=",
                        sqrl->nut64, "&n=", sqrl->nonce, NULL);
    }

//    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, sqrl_to_string(p, sqrl));

    return sqrl;
}

int sqrl_verify(apr_pool_t * pool, const sqrl_req_rec * sqrl_req)
{
    size_t client_len = strlen(sqrl_req->raw_client);
    size_t server_len = strlen(sqrl_req->raw_server);
    unsigned long long sig_len = SQRL_SIGN_BYTES + client_len + server_len;
    unsigned long long msg_len;
    unsigned char *sig = (unsigned char *) apr_palloc(pool, sig_len);
    unsigned char *msg = (unsigned char *) apr_palloc(pool, sig_len);

    /* Build signature */
    memcpy(sig, sqrl_req->ids, SQRL_SIGN_BYTES);
    memcpy((sig + SQRL_SIGN_BYTES), sqrl_req->raw_client, client_len);
    memcpy((sig + SQRL_SIGN_BYTES + client_len), sqrl_req->raw_server,
           server_len);

    /* Verify signature */
    return sqrl_crypto_sign_open_impl(msg, &msg_len, sig, sig_len,
                                      sqrl_req->client->idk);
}

static sqrl_nut_rec *sqrl_nut_parse(apr_pool_t * pool,
                                    const unsigned char *nut_bytes)
{
    sqrl_nut_rec *sqrl_nut =
        (sqrl_nut_rec *) apr_palloc(pool, sizeof(sqrl_nut_rec));

    sqrl_nut->timestamp = bytes_to_int32(nut_bytes);
    sqrl_nut->counter = bytes_to_int32(nut_bytes + 4);
    sqrl_nut->nonce = (unsigned char *) apr_palloc(pool, 4);
    memcpy(sqrl_nut->nonce, (nut_bytes + 8), 4);
    sqrl_nut->ip_hash = (unsigned char *) apr_palloc(pool, 4);
    memcpy(sqrl_nut->ip_hash, (nut_bytes + 12), 4);

    return sqrl_nut;
}

apr_status_t sqrl_parse(apr_pool_t * pool, sqrl_rec ** sqrl,
                        sqrl_svr_cfg * sconf, const char *sqrl_uri)
{
    sqrl_rec *sq = (sqrl_rec *) apr_palloc(pool, sizeof(sqrl_rec));
    apr_table_t *server_params;
    const char *uri;
    unsigned char *nonce, *nut_bytes, *nut_crypt;
    size_t dec_len;
    apr_status_t rv;

    /* Copy the uri into the sqrl struct */
    sq->uri = apr_pstrdup(pool, sqrl_uri);

    /* Find the uri's query string */
    uri = strchr(sqrl_uri, '?');
    if (uri == NULL || *(++uri) == '\0') {
        return SQRL_INVALID_SERVER;
    }

    /* Parse the query string */
    server_params = apr_table_make(pool, 2);
    rv = apreq_parse_query_string(pool, server_params, uri);
    if (apreq_module_status_is_error(rv)) {
        return SQRL_INVALID_SERVER;
    }

    /* Get the nonce */
    sq->nonce = apr_table_get(server_params, "n");
    if (!sq->nonce) {
        return SQRL_MISSING_SID;
    }
    /* Decode the nonce */
    nonce = sqrl_base64_decode(pool, sq->nonce, &dec_len);
    if (dec_len != SQRL_NONCE_BYTES) {
        return SQRL_INVALID_SID;
    }

    /* Get the nut */
    sq->nut64 = apr_table_get(server_params, "nut");
    if (!sq->nut64) {
        return SQRL_MISSING_NUT;
    }
    /* Decode the nut */
    nut_bytes = sqrl_base64_decode(pool, sq->nut64, &dec_len);
    if (dec_len != 16) {
        return SQRL_INVALID_NUT;
    }

    /* Decrypt the nut */
    nut_crypt = (unsigned char *) apr_palloc(pool, 16);
    sqrl_crypto_stream_impl(nut_crypt, nut_bytes, 16U, nonce, sconf->nut_key);

    /* Parse the nut */
    sq->nut = sqrl_nut_parse(pool, nut_crypt);
    if (!sq->nut) {
        return SQRL_INVALID_NUT;
    }

    /* Set sqrl */
    *sqrl = sq;

    return APR_SUCCESS;
}

apr_status_t sqrl_client_parse(apr_pool_t * pool,
                               sqrl_client_rec ** sqrl_client,
                               const char *raw_client)
{
    sqrl_client_rec *args =
        (sqrl_client_rec *) apr_palloc(pool, sizeof(sqrl_client_rec));
    char *client;
    apr_table_t *client_params;
    const char *version, *key64;
    size_t dec_len;

    /* Decode the client args */
    client = (char *) sqrl_base64_decode(pool, raw_client, &dec_len);
    if (client == NULL) {
        return SQRL_INVALID_CLIENT;
    }
    //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "client = %s", client);

    /* Parse client parameters */
    client_params = parse_parameters(pool, client);

    /* Get the version */
    version = apr_table_get(client_params, "ver");
    if (version == NULL) {
        return SQRL_MISSING_VER;
    }
    if (strcmp("1", version) != 0) {
        return SQRL_INVALID_VER;
    }
    args->version = "1";

    /* Get the public key */
    key64 = apr_table_get(client_params, "idk");
    if (!key64) {
        return SQRL_MISSING_KEY;
    }
    /* Decode the public key */
    args->idk = sqrl_base64_decode(pool, key64, &dec_len);
    if (dec_len != SQRL_PUBLIC_KEY_BYTES) {
        return SQRL_INVALID_KEY;
    }

    /* Set sqrl_client */
    *sqrl_client = args;

    return APR_SUCCESS;
}

apr_status_t sqrl_req_parse(apr_pool_t * pool, sqrl_req_rec ** sqrl_req,
                            sqrl_svr_cfg * sconf, const apr_table_t * body)
{
    sqrl_req_rec *req =
        (sqrl_req_rec *) apr_palloc(pool, sizeof(sqrl_req_rec));
    sqrl_rec *sqrl;
    sqrl_client_rec *client;
    char *server;
    size_t dec_len;
    apr_status_t rv;

    /* Get the client args */
    req->raw_client = apr_table_get(body, "client");
    if (req->raw_client == NULL) {
        return SQRL_MISSING_CLIENT;
    }

    /* Parse the client args */
    rv = sqrl_client_parse(pool, &client, req->raw_client);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    req->client = client;

    /* Get the server's uri */
    req->raw_server = apr_table_get(body, "server");
    if (req->raw_server == NULL) {
        return SQRL_MISSING_SERVER;
    }

    /* Decode the server's uri */
    server = (char *) sqrl_base64_decode(pool, req->raw_server, NULL);
    if (server == NULL) {
        return SQRL_INVALID_SERVER;
    }
    req->server = server;

    /* Parse the server's uri */
    rv = sqrl_parse(pool, &sqrl, sconf, req->server);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    req->sqrl = sqrl;
    //ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, sqrl_to_string(r->pool, sqrl));

    /* Get the user's signature */
    req->raw_ids = apr_table_get(body, "ids");
    if (req->raw_ids == NULL) {
        return SQRL_MISSING_SIG;
    }

    /* Decode the user's signature */
    req->ids = sqrl_base64_decode(pool, req->raw_ids, &dec_len);
    if (dec_len < SQRL_SIGN_BYTES) {
        return SQRL_INVALID_SIG;
    }

    /* Get the previous signature */
    req->raw_pids = apr_table_get(body, "pids");
    if (req->raw_pids != NULL) {
        /* Decode the new signature */
        req->pids = sqrl_base64_decode(pool, req->raw_pids, &dec_len);
        if (dec_len < SQRL_SIGN_BYTES) {
            return SQRL_INVALID_SIG;
        }
    }

    /* Get the unlock signature */
    req->raw_urs = apr_table_get(body, "urs");
    if (req->raw_urs != NULL) {
        /* Decode the id unlock signature */
        req->urs = sqrl_base64_decode(pool, req->raw_urs, &dec_len);
        if (dec_len < SQRL_SIGN_BYTES) {
            return SQRL_INVALID_SIG;
        }
    }

    *sqrl_req = req;

    return APR_SUCCESS;
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
        timestamp = (char *) apr_palloc(pool, APR_RFC822_DATE_LEN);
        apr_rfc822_date(timestamp, apr_time_from_sec(nut->timestamp));
    }
    else {
        timestamp = (char *) "null";
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
