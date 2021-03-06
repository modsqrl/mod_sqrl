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
#include "sqrl_encodings.h"


module AP_MODULE_DECLARE_DATA sqrl_module;


char *get_client_ip(request_rec * r)
{
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
    return r->useragent_ip;
#else
    return r->connection->remote_ip;
#endif
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


/*
 * SQRL Authentication handler
 */

static int authenticate_sqrl(request_rec * r)
{
    sqrl_svr_cfg *sconf;
    sqrl_dir_cfg *dconf;
    apreq_handle_t* (*sqrl_apreq_handle_apache2)(request_rec *r);
    sqrl_req_rec *sqrl_req;
    const sqrl_rec *sqrl;
    apr_status_t rv;
    int verified, ip_matches;
    apr_int32_t time_now;
    unsigned char *ip_hash;
    apreq_handle_t *apreq;
    const apr_table_t *body;

    if (!r->handler || (strcmp(r->handler, "sqrl") != 0)) {
        return DECLINED;
    }

    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "Verifying SQRL code ...");

    sconf =
        (sqrl_svr_cfg *) ap_get_module_config(r->server->module_config,
                                              &sqrl_module);
    dconf =
        (sqrl_dir_cfg *) ap_get_module_config(r->per_dir_config,
                                              &sqrl_module);

    /* Initiate libapreq */
    sqrl_apreq_handle_apache2 = APR_RETRIEVE_OPTIONAL_FN(apreq_handle_apache2);
    if (sqrl_apreq_handle_apache2 == NULL) {
        ap_log_rerror(APLOG_MARK, LOG_EMERG, 0, r,
                      "apreq_module has not been loaded. This module is "
                      "required for sqrl_module to work.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    apreq = sqrl_apreq_handle_apache2(r);

    /* Parse the body parameters */
    rv = apreq_body(apreq, &body);
    if (apreq_module_status_is_error(rv)) {
        return rv;
    }

    /* Parse the sqrl request */
    rv = sqrl_req_parse(r->pool, &sqrl_req, sconf, body);
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
    if (dconf->timeout > 0) {
        time_now = apr_time_sec(apr_time_now());
        if (time_now > (sqrl->nut->timestamp + dconf->timeout)) {
            ap_log_rerror(APLOG_MARK, LOG_WARNING, SQRL_EXPIRED_NUT, r,
                          "Nut has expired");
            return HTTP_BAD_REQUEST;
        }
    }

    /* Verify the IP address */
    ip_hash = get_ip_hash(r->pool, get_client_ip(r), sqrl->nonce);
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
    unsigned char *private_key, *public_key, *signature;
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
    rv = apreq_unescape(url);
    //rv = ap_unescape_urlencoded(url);
    if (rv < 0) {
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
    public_key = (unsigned char *) apr_palloc(r->pool, SQRL_PUBLIC_KEY_BYTES);
    private_key =
        (unsigned char *) apr_palloc(r->pool, SQRL_PRIVATE_KEY_BYTES);
    rv = sqrl_crypto_sign_keypair_impl(public_key, private_key);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Error generating the public key");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    public_hex = bin2hex(r->pool, public_key, SQRL_PUBLIC_KEY_BYTES, NULL);
    private_hex = bin2hex(r->pool, private_key, SQRL_PRIVATE_KEY_BYTES, NULL);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "public key = %s ; private key = %s", public_hex,
                  private_hex);

    /* Encode the public key in base64 */
    public64 = sqrl_base64_encode(r->pool, public_key, SQRL_PUBLIC_KEY_BYTES);

    /* Complete the URL */
    url =
        apr_pstrcat(r->pool, url, "&sqrlver=1&sqrlopt=enforce&sqrlkey=",
                    public64, NULL);

    /* Sign the URL */
    signature =
        (unsigned char *) apr_palloc(r->pool, SQRL_SIGN_BYTES + strlen(url));
    rv = sqrl_crypto_sign_impl(signature, &signature_len,
                               (unsigned char *) url, strlen(url),
                               private_key);
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
    sqrl_svr_cfg *sconf;
    sqrl_dir_cfg *dconf;
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

    sconf =
        (sqrl_svr_cfg *) ap_get_module_config(r->server->module_config,
                                              &sqrl_module);
    dconf =
        (sqrl_dir_cfg *) ap_get_module_config(r->per_dir_config,
                                              &sqrl_module);

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
        sqrl = sqrl_create(r->pool, sconf, dconf, get_client_ip(r));
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
    sconf =
        (sqrl_svr_cfg *) ap_get_module_config(s->module_config, &sqrl_module);

    /* If a domain isn't configured, set it to this server's domain */
    if (sconf->domain == UNSET) {
        sconf->domain = s->server_hostname;
    }

    /* If a nut_key isn't configured, generate a random one */
    if (sconf->nut_key == (unsigned char *) UNSET) {
        nut_key = (unsigned char *) apr_palloc(p, SQRL_ENCRYPTION_KEY_BYTES);
        randombytes(nut_key, SQRL_ENCRYPTION_KEY_BYTES);
        sconf->nut_key = nut_key;
    }

    /* apreq_handle_apache2 */

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
    sqrl_svr_cfg *conf = (sqrl_svr_cfg *) apr_palloc(p, sizeof(sqrl_svr_cfg));
    unsigned char *counter_bytes = (unsigned char *) apr_palloc(p, 4);

    conf->scheme = "qrl";
    conf->domain = UNSET;       /* Default is set in post_config() */
    conf->nut_key = (unsigned char *) UNSET;    /* Default is set in post_config() */
    randombytes(counter_bytes, 4);
    conf->counter = bytes_to_int32(counter_bytes);
    return conf;
}

static void *create_dir_config(apr_pool_t * p, char *dir)
{
    sqrl_dir_cfg *conf = (sqrl_dir_cfg *) apr_palloc(p, sizeof(sqrl_dir_cfg));
    conf->realm = UNSET;
    conf->path = "sqrl";
    conf->timeout = 120;        /* 2 minutes */
    return conf;
}

static const char *cfg_set_tls(cmd_parms * parms, void *mconfig, int on)
{
    server_rec *s = parms->server;
    sqrl_svr_cfg *conf =
        (sqrl_svr_cfg *) ap_get_module_config(s->module_config, &sqrl_module);
    conf->scheme = (on ? "sqrl" : "qrl");
    return NULL;
}

static const char *cfg_set_domain(cmd_parms * parms, void *mconfig,
                                  const char *w)
{
    server_rec *s = parms->server;
    sqrl_svr_cfg *conf =
        (sqrl_svr_cfg *) ap_get_module_config(s->module_config, &sqrl_module);
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
    sqrl_svr_cfg *conf =
        (sqrl_svr_cfg *) ap_get_module_config(s->module_config, &sqrl_module);
    unsigned char *nut_key =
        (unsigned char *) apr_palloc(parms->pool, SQRL_ENCRYPTION_KEY_BYTES);
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
