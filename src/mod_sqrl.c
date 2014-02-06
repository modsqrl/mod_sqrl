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

#include "string.h"

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"

#include "ap_config.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_strings.h"
#include "apr_time.h"

#include "mod_include.h"
#include "apreq2/apreq_module_apache2.h"
#include "apreq2/apreq_module.h"
#include "apreq2/apreq_util.h"

#include "sodium/core.h"
#include "sodium/randombytes.h"
#include "sodium/utils.h"
#include "sodium/version.h"

#include "sqrl.h"
#include "utils.h"


typedef struct
{
    const char *scheme, *domain;
    const unsigned char *nut_key;
    apr_int32_t counter;
} sqrl_svr_cfg;

typedef struct
{
    const char *realm, *path;
    int timeout;
} sqrl_dir_cfg;

module AP_MODULE_DECLARE_DATA sqrl_module;


/*
 * SQRL functions
 */

sqrl_rec *sqrl_create(request_rec * r)
{
    sqrl_rec *sqrl;
    sqrl_svr_cfg *sconf;
    sqrl_dir_cfg *dconf;
    const char *scheme, *domain, *realm, *path;
    sqrl_nut_rec *nut;
    unsigned char *nonce_bytes;
    unsigned char *nut_buff;
    unsigned char *nut_crypt;

    /* Load the server config to get the counter */
    sconf = ap_get_module_config(r->server->module_config, &sqrl_module);
    scheme = sconf->scheme;
    domain = sconf->domain;

    /* Load the directory config to get the URL properties */
    dconf = ap_get_module_config(r->per_dir_config, &sqrl_module);
    realm = dconf->realm;
    path = dconf->path;

    /* Log config */
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "scheme = %s, domain = %s, realm = %s, path = %s",
                  scheme, domain, (realm == NULL ? "null" : realm), path);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "nut_key = %s",
                  bin2hex(r->pool, sconf->nut_key, SQRL_ENCRYPTION_KEY_BYTES,
                          NULL));

    /* Allocate the sqrl struct */
    sqrl = apr_palloc(r->pool, sizeof(sqrl_rec));

    /* Generate a nonce */
    nonce_bytes = apr_palloc(r->pool, SQRL_NONCE_BYTES);
    /* libsodium PRNG */
    randombytes(nonce_bytes, SQRL_NONCE_BYTES);

    /* Convert the nonce to base64 */
    sqrl->nonce = sqrl_base64_encode(r->pool, nonce_bytes, SQRL_NONCE_BYTES);

    /* Increment the counter */
    ++sconf->counter;           /* TODO increment_and_get() */

    /* Build the nut struct */
    nut = apr_palloc(r->pool, sizeof(sqrl_nut_rec));
    nut->timestamp = apr_time_sec(apr_time_now());
    nut->counter = sconf->counter;
    nut->nonce = apr_palloc(r->pool, 4);
    randombytes(nut->nonce, 4);
    nut->ip_hash = get_ip_hash(r, sqrl->nonce);

    /* Set nut */
    sqrl->nut = nut;

    /* Build the authentication URL's nut */
    nut_buff = apr_palloc(r->pool, 16);
    /* Add the current time */
    int32_to_bytes(nut_buff, nut->timestamp);
    /* Add the counter */
    int32_to_bytes((nut_buff + 4), nut->counter);
    /* Add a nonce */
    memcpy((nut_buff + 8), nut->nonce, 4);
    /* Add the IP */
    memcpy((nut_buff + 12), nut->ip_hash, 4);

    /* Encrypt the nut */
    nut_crypt = apr_palloc(r->pool, 16);
    sqrl_crypto_stream(nut_crypt, nut_buff, 16U, nonce_bytes, sconf->nut_key);

    /* Encode the nut as base64 */
    sqrl->nut64 = sqrl_base64_encode(r->pool, nut_crypt, 16U);

    /* Generate the url */
    if (realm && strlen(realm) > 1) {
        sqrl->uri =
            apr_pstrcat(r->pool, scheme, "://", domain, realm, "|", path,
                        "?nut=", sqrl->nut64, "&n=", sqrl->nonce, NULL);
    }
    else {
        sqrl->uri =
            apr_pstrcat(r->pool, scheme, "://", domain, "/", path, "?nut=",
                        sqrl->nut64, "&n=", sqrl->nonce, NULL);
    }

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, sqrl_to_string(r->pool, sqrl));

    return sqrl;
}

int sqrl_verify(apr_pool_t * p, const sqrl_req_rec * sqrl_req)
{
    size_t client_len = strlen(sqrl_req->raw_client);
    size_t server_len = strlen(sqrl_req->raw_server);
    unsigned long long sig_len = SQRL_SIGN_BYTES + client_len + server_len;
    unsigned long long msg_len;
    unsigned char *sig = apr_palloc(p, sig_len);
    unsigned char *msg = apr_palloc(p, sig_len);

    /* Build signature */
    memcpy(sig, sqrl_req->ids, SQRL_SIGN_BYTES);
    memcpy((sig + SQRL_SIGN_BYTES), sqrl_req->raw_client, client_len);
    memcpy((sig + SQRL_SIGN_BYTES + client_len), sqrl_req->raw_server,
           server_len);

    /* Verify signature */
    return sqrl_crypto_sign_open(msg, &msg_len, sig, sig_len,
                                 sqrl_req->client->idk);
}

static sqrl_nut_rec *sqrl_nut_parse(apr_pool_t * p,
                                    const unsigned char *nut_bytes)
{
    sqrl_nut_rec *sqrl_nut = apr_palloc(p, sizeof(sqrl_nut_rec));

    sqrl_nut->timestamp = bytes_to_int32(nut_bytes);
    sqrl_nut->counter = bytes_to_int32(nut_bytes + 4);
    sqrl_nut->nonce = apr_palloc(p, 4);
    memcpy(sqrl_nut->nonce, (nut_bytes + 8), 4);
    sqrl_nut->ip_hash = apr_palloc(p, 4);
    memcpy(sqrl_nut->ip_hash, (nut_bytes + 12), 4);

    return sqrl_nut;
}

apr_status_t sqrl_parse(request_rec * r, sqrl_rec ** sqrl,
                        const char *sqrl_uri)
{
    sqrl_rec *sq = apr_palloc(r->pool, sizeof(sqrl_rec));
    sqrl_svr_cfg *sconf;
    apr_table_t *server_params;
    char *uri;
    unsigned char *nonce, *nut_bytes, *nut_crypt;
    size_t dec_len;
    apr_status_t rv;

    /* Load the server config for domain properties */
    sconf = ap_get_module_config(r->server->module_config, &sqrl_module);

    /* Copy the uri into the sqrl struct */
    sq->uri = apr_pstrdup(r->pool, sqrl_uri);

    /* Find the uri's query string */
    uri = strchr(sqrl_uri, '?');
    if (uri == NULL || *(++uri) == '\0') {
        return SQRL_INVALID_SERVER;
    }

    /* Parse the query string */
    server_params = apr_table_make(r->pool, 2);
    rv = apreq_parse_query_string(r->pool, server_params, uri);
    if (apreq_module_status_is_error(rv)) {
        return SQRL_INVALID_SERVER;
    }

    /* Get the nonce */
    sq->nonce = apr_table_get(server_params, "n");
    if (!sq->nonce) {
        return SQRL_MISSING_SID;
    }
    /* Decode the nonce */
    nonce = sqrl_base64_decode(r->pool, sq->nonce, &dec_len);
    if (dec_len != SQRL_NONCE_BYTES) {
        return SQRL_INVALID_SID;
    }

    /* Get the nut */
    sq->nut64 = apr_table_get(server_params, "nut");
    if (!sq->nut64) {
        return SQRL_MISSING_NUT;
    }
    /* Decode the nut */
    nut_bytes = sqrl_base64_decode(r->pool, sq->nut64, &dec_len);
    if (dec_len != 16) {
        return SQRL_INVALID_NUT;
    }

    /* Decrypt the nut */
    nut_crypt = apr_palloc(r->pool, 16);
    sqrl_crypto_stream(nut_crypt, nut_bytes, 16U, nonce, sconf->nut_key);

    /* Parse the nut */
    sq->nut = sqrl_nut_parse(r->pool, nut_crypt);
    if (!sq->nut) {
        return SQRL_INVALID_NUT;
    }

    /* Set sqrl */
    *sqrl = sq;

    return APR_SUCCESS;
}

apr_status_t sqrl_client_parse(request_rec * r,
                               sqrl_client_rec ** sqrl_client,
                               const char *raw_client)
{
    sqrl_client_rec *args = apr_palloc(r->pool, sizeof(sqrl_client_rec));
    char *client;
    apr_table_t *client_params;
    const char *version, *key64;
    size_t dec_len;

    /* Decode the client args */
    client = (char *) sqrl_base64_decode(r->pool, raw_client, &dec_len);
    if (client == NULL) {
        return SQRL_INVALID_CLIENT;
    }
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "client = %s", client);

    /* Parse client parameters */
    client_params = parse_parameters(r->pool, client);

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
    args->idk = sqrl_base64_decode(r->pool, key64, &dec_len);
    if (dec_len != SQRL_PUBLIC_KEY_BYTES) {
        return SQRL_INVALID_KEY;
    }

    /* Set sqrl_client */
    *sqrl_client = args;

    return APR_SUCCESS;
}

apr_status_t sqrl_req_parse(request_rec * r, sqrl_req_rec ** sqrl_req)
{
    sqrl_req_rec *req = apr_palloc(r->pool, sizeof(sqrl_req_rec));
    sqrl_rec *sqrl;
    sqrl_client_rec *client;
    apreq_handle_t *apreq;
    const apr_table_t *body;
    char *server;
    size_t dec_len;
    apr_status_t rv;

    /* Initiate libapreq */
    apreq = apreq_handle_apache2(r);

    /* Parse the body parameters */
    rv = apreq_body(apreq, &body);
    if (apreq_module_status_is_error(rv)) {
        return rv;
    }

    /* Get the client args */
    req->raw_client = apr_table_get(body, "client");
    if (req->raw_client == NULL) {
        return SQRL_MISSING_CLIENT;
    }

    /* Parse the client args */
    rv = sqrl_client_parse(r, &client, req->raw_client);
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
    server = (char *) sqrl_base64_decode(r->pool, req->raw_server, NULL);
    if (server == NULL) {
        return SQRL_INVALID_SERVER;
    }
    req->server = server;

    /* Parse the server's uri */
    rv = sqrl_parse(r, &sqrl, req->server);
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
    req->ids = sqrl_base64_decode(r->pool, req->raw_ids, &dec_len);
    if (dec_len < SQRL_SIGN_BYTES) {
        return SQRL_INVALID_SIG;
    }

    /* Get the previous signature */
    req->raw_pids = apr_table_get(body, "pids");
    if (req->raw_pids != NULL) {
        /* Decode the new signature */
        req->pids = sqrl_base64_decode(r->pool, req->raw_pids, &dec_len);
        if (dec_len < SQRL_SIGN_BYTES) {
            return SQRL_INVALID_SIG;
        }
    }

    /* Get the unlock signature */
    req->raw_urs = apr_table_get(body, "urs");
    if (req->raw_urs != NULL) {
        /* Decode the id unlock signature */
        req->urs = sqrl_base64_decode(r->pool, req->raw_urs, &dec_len);
        if (dec_len < SQRL_SIGN_BYTES) {
            return SQRL_INVALID_SIG;
        }
    }

    *sqrl_req = req;

    return APR_SUCCESS;
}


/*
 * SQRL Authentication handler
 */

static int authenticate_sqrl(request_rec * r)
{
    sqrl_dir_cfg *dconf;
    sqrl_req_rec *sqrl_req;
    const sqrl_rec *sqrl;
    apr_status_t rv;
    int verified, ip_matches;
    apr_int32_t time_now;
    unsigned char *ip_hash;

    dconf = ap_get_module_config(r->per_dir_config, &sqrl_module);

    if (!r->handler || (strcmp(r->handler, "sqrl") != 0)) {
        return DECLINED;
    }

    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "Verifying SQRL code ...");

    /* Parse the sqrl request */
    rv = sqrl_req_parse(r, &sqrl_req);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, LOG_WARNING, rv, r,
                      "Error parsing the authentication request");
        return HTTP_BAD_REQUEST;
    }
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r,
                  sqrl_req_to_string(r->pool, sqrl_req));

    /* Verify the signature */
    verified = sqrl_verify(r->pool, sqrl_req);
    if (verified != 0) {
        ap_log_rerror(APLOG_MARK, LOG_WARNING, verified, r,
                      "SQRL failed verification");
        return HTTP_BAD_REQUEST;
    }
    else {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "SQRL sig verified");
    }

    sqrl = sqrl_req->sqrl;

    /* Verify the timeout */
    if(dconf->timeout > 0) {
        time_now = apr_time_sec(apr_time_now());
        if (time_now > (sqrl->nut->timestamp + dconf->timeout)) {
            ap_log_rerror(APLOG_MARK, LOG_WARNING, SQRL_EXPIRED_NUT, r,
                          "Nut has expired");
            return HTTP_BAD_REQUEST;
        }
    }

    /* Verify the IP address */
    ip_hash = get_ip_hash(r, sqrl->nonce);
    ip_matches = memcmp(sqrl->nut->ip_hash, ip_hash, 4) == 0;
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "Request's IP %s the nut's IP",
                  (ip_matches ? "matches" : "does not match"));

    /* Return a status message to the client */
    ap_set_content_type(r, "application/x-www-form-urlencoded");
    rv = write_out(r, "ver=1&result=1&display=success");

    return HTTP_OK;
}

static int sign_sqrl(request_rec * r)
{
    unsigned char *private, *public, *signature;
    char *public_hex, *private_hex, *signature_hex, *public64, *signature64;
    char *url, *end, *pipe;
    apr_size_t url_len;
    unsigned long long signature_len;
    apr_status_t rv;
    char *response;

    if (!r->handler || (strcmp(r->handler, "sign_sqrl") != 0)) {
        return DECLINED;
    }

    if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    /* Get URL to sign */
    url = strstr(r->parsed_uri.query, "url=") + 4;
    for (end = url; *end != '&' && *end != '\0'; ++end) {
    }
    url_len = end - url;
    url = apr_pstrndup(r->pool, url, url_len);
    rv = ap_unescape_urlencoded(url);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Error interpreting the given url: %s", url);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Replace the pipe */
    pipe = strchr(url, '|');
    if (pipe) {
        *pipe = '/';
    }

    /* Generate the public key */
    public = apr_palloc(r->pool, SQRL_PUBLIC_KEY_BYTES);
    private = apr_palloc(r->pool, SQRL_PRIVATE_KEY_BYTES);
    rv = sqrl_crypto_sign_keypair(public, private);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Error generating the public key");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    public_hex = bin2hex(r->pool, public, SQRL_PUBLIC_KEY_BYTES, NULL);
    private_hex = bin2hex(r->pool, private, SQRL_PRIVATE_KEY_BYTES, NULL);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "public key = %s ; private key = %s", public_hex,
                  private_hex);

    /* Encode the public key in base64 */
    public64 = sqrl_base64_encode(r->pool, public, SQRL_PUBLIC_KEY_BYTES);

    /* Complete the URL */
    url =
        apr_pstrcat(r->pool, url, "&sqrlver=1&sqrlopt=enforce&sqrlkey=",
                    public64, NULL);

    /* Sign the URL */
    signature = apr_palloc(r->pool, SQRL_SIGN_BYTES + strlen(url));
    rv = sqrl_crypto_sign(signature, &signature_len, (unsigned char *) url,
                          strlen(url), private);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Error signing the URL");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    signature_hex = bin2hex(r->pool, signature, signature_len, NULL);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "signature = %s ; sig len = %lu", signature_hex,
                  (unsigned long) signature_len);

    /* Encode the signature in base64 */
    signature64 = sqrl_base64_encode(r->pool, signature, SQRL_SIGN_BYTES);

    /* Build the response */
    response =
        apr_pstrcat(r->pool, "sqrlurl=", url, "&sqrlsig=", signature64, NULL);

    /* Write output */
    ap_set_content_type(r, "text/plain");
    rv = write_out(r, response);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Error writing the response");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    return HTTP_OK;
}


/*
 * mod_include extention.
 */

static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *
    sqrl_get_tag_and_value;

/**
 * Generate a SQRL URL and add to the SSI environment.
 * Example:
 * <!--#sqrl_gen url="sqrl_url" id="sqrl_id" -->
 * URL = <!--#echo var="sqrl_url" -->
 * ID = <!--#echo var="sqrl_id" -->
 */
     static apr_status_t handle_sqrl_gen(include_ctx_t * ctx, ap_filter_t * f,
                                         apr_bucket_brigade * bb)
{
    request_rec *r = f->r;
    request_rec *mr = r->main;
    apr_pool_t *p = r->pool;
    char *tag = NULL, *tag_val = NULL;
    char *url = NULL, *id = NULL;
    sqrl_rec *sqrl;

    /* Need the main request's pool */
    while (mr) {
        p = mr->pool;
        mr = mr->main;
    }

    /* Loop over directive arguments */
    while (1) {
        /* Parse the next name/value pair */
        sqrl_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
        if (!tag || !tag_val) {
            break;
        }

        /* Check and set the sqrl authentication url */
        if (!strcmp(tag, "url")) {
            url = tag_val;
        }
        /* Check and set the sqrl session id */
        else if (!strcmp(tag, "id")) {
            id = tag_val;
        }
        /* Unknown argument */
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid tag for 'sqrl_gen' directive in %s",
                          r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            return APR_SUCCESS;
        }
    }

    /* Only generate a sqrl if it's actually going to be used */
    if (url || id) {
        sqrl = sqrl_create(r);
        if (!sqrl) {
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            return APR_SUCCESS;
        }
        if (url) {
            apr_table_set(r->subprocess_env, url, sqrl->uri);
        }
        if (id) {
            apr_table_set(r->subprocess_env, id, sqrl->nut64);
        }
    }

    return APR_SUCCESS;
}

/*
 * Configuration
 */

static const char *UNSET = NULL;

static int sqrl_post_config(apr_pool_t * p, apr_pool_t * plog,
                            apr_pool_t * ptemp, server_rec * s)
{
    sqrl_svr_cfg *sconf;
    unsigned char *nut_key;
    int rv;

    /* Load the server config to validate settings */
    sconf = ap_get_module_config(s->module_config, &sqrl_module);

    /* If a domain isn't configured, set it to this server's domain */
    if (sconf->domain == UNSET) {
        sconf->domain = s->server_hostname;
    }

    /* If a nut_key isn't configured, generate a random one */
    if (sconf->nut_key == (unsigned char *) UNSET) {
        nut_key = apr_palloc(p, SQRL_ENCRYPTION_KEY_BYTES);
        randombytes(nut_key, SQRL_ENCRYPTION_KEY_BYTES);
        sconf->nut_key = nut_key;
    }

    /* Retrieve mod_include's optional functions */
    APR_OPTIONAL_FN_TYPE(ap_register_include_handler) * sqrl_reg_ssi =
        APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
    sqrl_get_tag_and_value =
        APR_RETRIEVE_OPTIONAL_FN(ap_ssi_get_tag_and_value);

    /* If mod_include is loaded, register sqrl directives */
    if ((sqrl_reg_ssi) && (sqrl_get_tag_and_value)) {
        sqrl_reg_ssi("sqrl_gen", handle_sqrl_gen);
    }

    /* Initialize the libsodium library. Makes it go faster. :-) */
    rv = sodium_init();
    if (rv) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
                     "Error initializing the libsodium library");
        return rv;
    }
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "libsodium initialized: %s", sodium_version_string());

    return OK;
}


static void *create_server_config(apr_pool_t * p, server_rec * s)
{
    sqrl_svr_cfg *conf = apr_palloc(p, sizeof(sqrl_svr_cfg));
    unsigned char *counter_bytes = apr_palloc(p, 4);

    conf->scheme = "qrl";
    conf->domain = UNSET;       /* Default is set in post_config() */
    conf->nut_key = (unsigned char *) UNSET;    /* Default is set in post_config() */
    randombytes(counter_bytes, 4);
    conf->counter = bytes_to_int32(counter_bytes);
    return conf;
}

static void *create_dir_config(apr_pool_t * p, char *dir)
{
    sqrl_dir_cfg *conf = apr_palloc(p, sizeof(sqrl_dir_cfg));
    conf->realm = UNSET;
    conf->path = "sqrl";
    conf->timeout = 120;        /* 2 minutes */
    return conf;
}

static const char *cfg_set_tls(cmd_parms * parms, void *mconfig, int on)
{
    server_rec *s = parms->server;
    sqrl_svr_cfg *conf = ap_get_module_config(s->module_config, &sqrl_module);
    conf->scheme = (on ? "sqrl" : "qrl");
    return NULL;
}

static const char *cfg_set_domain(cmd_parms * parms, void *mconfig,
                                  const char *w)
{
    server_rec *s = parms->server;
    sqrl_svr_cfg *conf = ap_get_module_config(s->module_config, &sqrl_module);
    conf->domain = w;
    return NULL;
}

#define AssertHex(c, pool) \
if (c < '0' || (c > '9' && c < 'A') || (c > 'F' && c < 'a') || c > 'f') { \
    return apr_pstrcat(pool, "Invalid hex character: ", \
                       apr_pstrndup(pool, w, 1U), NULL); \
}

static const char *cfg_set_key(cmd_parms * parms, void *mconfig,
                               const char *w)
{
    server_rec *s = parms->server;
    sqrl_svr_cfg *conf = ap_get_module_config(s->module_config, &sqrl_module);
    unsigned char *nut_key =
        apr_palloc(parms->pool, SQRL_ENCRYPTION_KEY_BYTES);
    char hex[70];
    char *c;
    unsigned short i;

    /* Setup hex table */
    for (i = 0, c = &hex['0']; i < 10; ++i, ++c) {
        *c = i;
    }
    for (i = 10, c = &hex['A']; i < 16; ++i, ++c) {
        *c = i;
    }
    for (i = 10, c = &hex['a']; i < 16; ++i, ++c) {
        *c = i;
    }

    /* Convert two hex characters to one byte */
    for (i = 0;
         i < SQRL_ENCRYPTION_KEY_BYTES && *w != '\0' && *(w + 1) != '\0';
         ++i, ++w) {
        AssertHex(*w, parms->pool);
        nut_key[i] = (hex[(int) *w] << 4);
        ++w;
        AssertHex(*w, parms->pool);
        nut_key[i] |= (hex[(int) *w]);
    }

    /* Verify the size is correct */
    if (i != SQRL_ENCRYPTION_KEY_BYTES || *w != '\0') {
        return apr_pstrcat(parms->pool, "Encryption key must be ",
                           apr_itoa(parms->pool, SQRL_ENCRYPTION_KEY_BYTES),
                           " bytes", NULL);
    }

    /* Set the nut_key */
    conf->nut_key = nut_key;

    return NULL;
}

static const char *cfg_set_realm(cmd_parms * parms, void *mconfig,
                                 const char *w)
{
    sqrl_dir_cfg *conf = (sqrl_dir_cfg *) mconfig;
    conf->realm = (*w == '/' ? w : apr_pstrcat(parms->pool, "/", w, NULL));
    return NULL;
}

static const char *cfg_set_path(cmd_parms * parms, void *mconfig,
                                const char *w)
{
    sqrl_dir_cfg *conf = (sqrl_dir_cfg *) mconfig;
    conf->path = (*w == '/' ? (w + 1) : w);
    return NULL;
}

static const command_rec configuration_cmds[] = {
    AP_INIT_FLAG("SqrlTls", cfg_set_tls, NULL, RSRC_CONF,
                 "Create secure Authentication-URLs to authenticate over TLS"),
    AP_INIT_TAKE1("SqrlDomain", cfg_set_domain, NULL, RSRC_CONF,
                  "Authenticate to this domain"),
    AP_INIT_TAKE1("SqrlEncryptionKey", cfg_set_key, NULL, RSRC_CONF,
                  "16-byte encryption key for encrypting the nut"),
    AP_INIT_TAKE1("SqrlRealm", cfg_set_realm, NULL,
                  ACCESS_CONF | RSRC_CONF,
                  "Path to include as part of the domain in the "
                  "Authentication-URL"),
    AP_INIT_TAKE1("SqrlPath", cfg_set_path, NULL, ACCESS_CONF | RSRC_CONF,
                  "Path to authentication service"),
    AP_INIT_TAKE1("SqrlTimeout", ap_set_int_slot,
                  (void *) APR_OFFSETOF(sqrl_dir_cfg, timeout),
                  ACCESS_CONF | RSRC_CONF,
                  "Sqrl code is valid for this many seconds."),
    {NULL}
};

/*
 * Apache Registration
 */

/* Register mod_sqrl with Apache */
static void register_hooks(apr_pool_t * pool)
{
    static const char *const pre[] = { "mod_include.c", NULL };
    ap_hook_handler(authenticate_sqrl, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(sign_sqrl, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(sqrl_post_config, pre, NULL, APR_HOOK_MIDDLE);
}

/* Module Data Structure */
module AP_MODULE_DECLARE_DATA sqrl_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,          /* create per-directory configuration record */
    NULL,                       /* merge per-directory configuration records */
    create_server_config,       /* create per-server configuration record */
    NULL,                       /* merge per-server configuration records */
    configuration_cmds,         /* configuration directives */
    register_hooks              /* register modules functions with the core */
};
