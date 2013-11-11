/*
Copyright 2013 Chris Steinhoff

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

#include "sodium/core.h"
#include "sodium/crypto_auth.h"
#include "sodium/crypto_hash.h"
#include "sodium/crypto_sign.h"
#include "sodium/randombytes.h"
#include "sodium/utils.h"
#include "sodium/version.h"

#include "sqrl.h"
#include "utils.h"

/* typedef struct
 * {
 *     apr_time_t timestamp;
 *     apr_int32_t counter;
 *     unsigned char *nonce;
 *     unsigned char *ip_hash;
 * } sqrl_nut_rec;
 * 
 * typedef struct
 * {
 *     char *url;
 *     sqrl_nut_rec *nut;
 *     char *session_id;
 *     float version;
 *     apr_array_header_t *options;
 *     unsigned char *key;
 *     apr_size_t sig_len;
 *     unsigned char *sig;
 * } sqrl_rec;
 */

typedef struct
{
    const char *scheme, *domain;
    apr_int32_t counter;
} sqrl_svr_cfg;

typedef struct
{
    const char *additional, *path;
} sqrl_dir_cfg;

module AP_MODULE_DECLARE_DATA sqrl_module;


/*
 * SQRL functions
 */

static sqrl_nut_rec *parse_sqrl_nut(apr_pool_t * p, char *nut)
{
    sqrl_nut_rec *sqrl_nut = apr_palloc(p, sizeof(sqrl_nut_rec));
    unsigned char *nut_bytes = apr_palloc(p, strlen(nut));

    sqrl_base64url_decode(nut_bytes, nut);
    sqrl_nut->timestamp = apr_time_from_sec(bytes_to_int32(nut_bytes));
    sqrl_nut->counter = bytes_to_int32(nut_bytes + 4);
    sqrl_nut->nonce = apr_palloc(p, 4);
    memcpy(sqrl_nut->nonce, (nut_bytes + 8), 4);
    sqrl_nut->ip_hash = apr_palloc(p, 4);
    memcpy(sqrl_nut->ip_hash, (nut_bytes + 12), 4);

    return sqrl_nut;
}

sqrl_rec *parse_sqrl(request_rec * r, const char *url)
{
    apr_pool_t *p = r->pool;
    sqrl_rec *sqrl = apr_palloc(p, sizeof(sqrl_rec));
    apr_hash_t *form_data;
    apr_array_header_t *values;
    char *value, **val;
    char *i, **opt;
    char *nonce_hex, *ip_hash_hex, *sqrlkey_hex;

    sqrl->url = apr_pstrdup(p, url);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "url = %s", sqrl->url);

    /* Find the query string */
    i = strchr(sqrl->url, '?');
    if (i == NULL) {
        return NULL;
    }
    ++i;

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "query = %s", i);

    /* Parse the query string */
    form_data = parse_form_data(p, i, 50);
    /* The form processing modifies the url so it needs to be re-copied */
    sqrl->url = apr_pstrdup(p, url);

    values = apr_hash_get(form_data, "nut", APR_HASH_KEY_STRING);
    value = APR_ARRAY_IDX(values, 0, char *);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "nut = %s", value);
    if (!value) {
        return NULL;
    }
    sqrl->nut = parse_sqrl_nut(p, value);

    values = apr_hash_get(form_data, "sid", APR_HASH_KEY_STRING);
    value = APR_ARRAY_IDX(values, 0, char *);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "session_id = %s", value);
    if (!value) {
        return NULL;
    }
    sqrl->session_id = apr_pstrdup(p, value);

    values = apr_hash_get(form_data, "sqrlkey", APR_HASH_KEY_STRING);
    value = APR_ARRAY_IDX(values, 0, char *);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "sqrlkey = %s", value);
    if (!value) {
        return NULL;
    }
    sqrl->key = apr_palloc(p, strlen(value));
    sqrl_base64url_decode(sqrl->key, value);

    values = apr_hash_get(form_data, "sqrlver", APR_HASH_KEY_STRING);
    value = APR_ARRAY_IDX(values, 0, char *);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "sqrlver = %s", value);
    if (!value) {
        sqrl->version = 1;
    }
    else {
        sqrl->version = strtod(value, &i);
        if (*i != '\0') {
            sqrl->version = 1;
        }
    }

    values = apr_hash_get(form_data, "sqrlopt", APR_HASH_KEY_STRING);
    value = APR_ARRAY_IDX(values, 0, char *);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "sqrlopt = %s", value);
    if (value) {
        sqrl->options = apr_array_make(p, 1, sizeof(char *));
        i = NULL;
        for (opt = (char **) apr_strtok(value, ",", &i);
             (opt); opt = (char **) apr_strtok(NULL, ",", &i)) {
            val = apr_array_push(sqrl->options);
            val = opt;
        }
    }

    /* Stringify date */
    i = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(i, sqrl->nut->timestamp);
    /* Stringify nonce */
    nonce_hex = bin2hex(r->pool, sqrl->nut->nonce, 4U, NULL);
    /* Stringify ip_hash */
    ip_hash_hex = bin2hex(r->pool, sqrl->nut->ip_hash, 4U, NULL);
    /* Stringify sqrlkey */
    sqrlkey_hex = bin2hex(r->pool, sqrl->key, 32U, NULL);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "url = %s", sqrl->url);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "nut->timestamp = %s ; nut->counter = %d ; nut->nonce = %s ; "
                  "nut->ip_hash = %s", i, sqrl->nut->counter, nonce_hex,
                  ip_hash_hex);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "session_id = %s ; sqrlkey = %s ; sqrlver = %f",
                  sqrl->session_id, sqrlkey_hex, sqrl->version);

    return sqrl;
}

static sqrl_rec *generate_sqrl(request_rec * r)
{
    sqrl_rec *sqrl;
    sqrl_svr_cfg *sconf;
    sqrl_dir_cfg *dconf;
    const char *scheme, *domain, *additional, *path;

    /* Load the server config to get the counter */
    sconf = ap_get_module_config(r->server->module_config, &sqrl_module);
    scheme = sconf->scheme;
    domain = sconf->domain;

    /* Load the directory config to get the URL properties */
    dconf = ap_get_module_config(r->per_dir_config, &sqrl_module);
    additional = dconf->additional;
    path = dconf->path;

    /* Log config */
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "scheme = %s, domain = %s, additional = %s, path = %s",
                  scheme, domain, (additional == NULL ? "null" : additional),
                  path);

    ++sconf->counter;           /* TODO increment_and_get() */
    sqrl_create(r->pool, &sqrl, scheme, domain, additional, path,
                r->useragent_ip, sconf->counter);

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, sqrl_to_string(r->pool, sqrl));

    return sqrl;
}


/*
 * SQRL Authentication handler
 */

static int authenticate_sqrl(request_rec * r)
{
    sqrl_dir_cfg *conf;
    const char *hostname;
    char *uri;
    char *body;
    apr_size_t limit = 2048;    /* The body's maximum size, in bytes */
    apr_size_t clen;            /* Content length */
    apr_size_t blen;            /* Body length */
    apr_hash_t *params;         /* Parsed parameters */
    apr_array_header_t *values; /* Parameter value */
    char *value;                /* Parameter value */
    sqrl_rec *sqrl;
    char *url;
    unsigned long long sig_len, url_len;
    int verified;

    conf = ap_get_module_config(r->per_dir_config, &sqrl_module);

    if (!r->handler || (strcmp(r->handler, "sqrl") != 0)) {
        return DECLINED;
    }

    if (r->method_number != M_POST) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "Verifying SQRL code ...");

    hostname = r->hostname;
    uri = r->unparsed_uri;
    params = parse_form_data(r->pool, r->args, 10);

    {
        /* Get the Content-Length header */
        const char *length = apr_table_get(r->headers_in, "Content-Length");

        if (length != NULL) {
            /* Convert to long */
            clen = strtol(length, NULL, 0);
            /* Reject if it's too large */
            if (clen > limit) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "Request is too large (%zu/%zu)", clen, limit);
                return HTTP_REQUEST_ENTITY_TOO_LARGE;

            }
        }
        else {
            /* Unknown size, set length to the max */
            clen = limit;
        }
    }
    blen = read_body(r, &body, clen);

    sqrl = parse_sqrl(r, uri);

    /* Parse the form data in the body */
    apr_hash_t *form_data;
    form_data = parse_form_data(r->pool, body, 10);

    /* Get the signature */
    values = apr_hash_get(form_data, "sqrlsig", APR_HASH_KEY_STRING);
    value = APR_ARRAY_IDX(values, 0, char *);
    sqrl->sig = apr_palloc(r->pool, strlen(value));
    sig_len = sqrl_base64url_decode(sqrl->sig, value);
    value = bin2hex(r->pool, sqrl->sig, sig_len, NULL);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "sqrlsig = %s ; sig_len = %lu",
                  value, (unsigned long) sig_len);

    /* Verify the signature */
    url = apr_palloc(r->pool, sig_len);
    verified =
        crypto_sign_open((unsigned char *) url, &url_len, sqrl->sig, sig_len,
                         sqrl->key);
    if (verified == 0) {
        url[url_len] = '\0';
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r,
                      "I think it's verified: %s", url);
        verified = HTTP_OK;
    }
    else {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r,
                      "I think it's not verified");
        verified = HTTP_BAD_REQUEST;
    }

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "hostname = %s", hostname);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "uri = %s", uri);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "blen = %lu",
                  (unsigned long) blen);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "body = %s", (body + 8));

    return verified;
}

static int sign_sqrl(request_rec * r)
{
    unsigned char *private, *public, *signature;
    char *public_hex, *private_hex, *signature_hex, *public64, *signature64;
    char *url, *end, *pipe;
    apr_size_t url_len;
    unsigned long long signature_len;
    apr_bucket_brigade *bb;
    apr_bucket *b;
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
    public = apr_palloc(r->pool, crypto_sign_PUBLICKEYBYTES);
    private = apr_palloc(r->pool, crypto_sign_SECRETKEYBYTES);
    rv = crypto_sign_keypair(public, private);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "Error generating the public key");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    public_hex = bin2hex(r->pool, public, crypto_sign_PUBLICKEYBYTES, NULL);
    private_hex = bin2hex(r->pool, private, crypto_sign_SECRETKEYBYTES, NULL);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "public key = %s ; private key = %s", public_hex,
                  private_hex);

    /* Encode the public key in base64 */
    public64 =
        sqrl_base64url_encode(r->pool, public, crypto_sign_PUBLICKEYBYTES);

    /* Complete the URL */
    url =
        apr_pstrcat(r->pool, url, "&sqrlver=1&sqrlopt=enforce&sqrlkey=",
                    public64, NULL);

    /* Sign the URL */
    signature = apr_palloc(r->pool, strlen(url) + crypto_sign_BYTES);
    rv = crypto_sign(signature, &signature_len, (unsigned char *) url,
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
    signature64 = sqrl_base64url_encode(r->pool, signature, signature_len);

    /* Build the reponse */
    response =
        apr_pstrcat(r->pool, "sqrlurl=", url, "&sqrlsig=", signature64, NULL);

    /* Write output */
    ap_set_content_type(r, "text/plain");
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    b = apr_bucket_immortal_create(response, strlen(response),
                                   bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_eos_create(bb->bucket_alloc));
    rv = ap_pass_brigade(r->output_filters, bb);
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
 * <!--#sqrl_gen url="sqrl_url" session_id="sqrl_id" -->
 * URL = <!--#echo var="sqrl_url" -->
 * Session ID = <!--#echo var="sqrl_id" -->
 */
     static apr_status_t handle_sqrl_gen(include_ctx_t * ctx, ap_filter_t * f,
                                         apr_bucket_brigade * bb)
{
    request_rec *r = f->r;
    request_rec *mr = r->main;
    apr_pool_t *p = r->pool;
    char *tag = NULL, *tag_val = NULL;
    char *url = NULL, *session_id = NULL;
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
        else if (!strcmp(tag, "session_id")) {
            session_id = tag_val;
        }
        /* Unknown argument */
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01366)
                          "Invalid tag for 'sqrl_gen' directive in %s",
                          r->filename);
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            return APR_SUCCESS;
        }
    }

    /* Only generate a sqrl if it's actually going to be used */
    if (url || session_id) {
        /* TODO Get generate_sqrl parameters from the modules config */
        sqrl = generate_sqrl(r);
        if (!sqrl) {
            SSI_CREATE_ERROR_BUCKET(ctx, f, bb);
            return APR_SUCCESS;
        }
        if (url) {
            apr_table_set(r->subprocess_env, url, sqrl->url);
        }
        if (session_id) {
            apr_table_set(r->subprocess_env, session_id, sqrl->session_id);
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
    int rv;

    /* Load the server config to validate the domain */
    sconf = ap_get_module_config(s->module_config, &sqrl_module);

    /* If a domain isn't configured, set it to this server's domain */
    if (sconf->domain == UNSET) {
        sconf->domain = s->server_hostname;
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
    conf->domain = UNSET,       /* Default is set in post_config() */
        randombytes(counter_bytes, 4);
    conf->counter = bytes_to_int32(counter_bytes);
    return conf;
}

static void *create_dir_config(apr_pool_t * p, char *dir)
{
    sqrl_dir_cfg *conf = apr_palloc(p, sizeof(sqrl_dir_cfg));
    conf->additional = UNSET, conf->path = "sqrl";
    return conf;
}

static const command_rec configuration_cmds[] = {
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
