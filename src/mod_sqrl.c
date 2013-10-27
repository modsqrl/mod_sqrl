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
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_base64.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_strings.h"
#include "apr_time.h"
#include "mod_include.h"
#include "sodium/core.h"
#include "sodium/crypto_hash.h"
#include "sodium/randombytes.h"
#include "sodium/version.h"

static APR_OPTIONAL_FN_TYPE(ap_register_include_handler) * sqrl_reg_ssi;
     static APR_OPTIONAL_FN_TYPE(ap_ssi_get_tag_and_value) *
    sqrl_get_tag_and_value;

/**
 * Parse application/x-www-form-urlencoded form data from a string.
 * @param pool Memory allocation pool.
 * @param str Data to parse.
 * @param limit The maxium number of parameters to parse out of the string.
 * @return Hashtable of parsed parameters. Because a key can have multiple
 *         values, the hashtable value is an array of parameter values.
 */
     static apr_hash_t *parse_form_data(apr_pool_t * pool, char *str,
                                        int limit)
{
    apr_hash_t *form;
    apr_array_header_t *values;
    int count;
    const char *sep = "&";
    char *last;
    char *key;
    char *value;
    char **element;

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
            *value++ = '\0';
            ap_unescape_url(key);
            ap_unescape_url(value);
        }
        else {
            value = "";
            ap_unescape_url(key);
        }

        /* Store in the hash */
        values = apr_hash_get(form, key, APR_HASH_KEY_STRING);
        if (values == NULL) {
            values = apr_array_make(pool, 1, sizeof(const char *));
            apr_hash_set(form, key, APR_HASH_KEY_STRING, values);
        }
        element = apr_array_push(values);
        *element = apr_pstrdup(pool, value);
    }

    return form;
}

/**
 * Read data from the request body.
 * @param r Request to read from.
 * @param body On return, data read from the request
 *             (allocated from the request's pool).
 * @param limit The maxium number of bytes to read from the request body.
 * @return The number of bytes read from the request body.
 */
static apr_size_t read_body(request_rec * r, char **body, apr_size_t limit)
{
    apr_status_t status;
    apr_size_t bytes,           /* Bytes remaining in body buffer
                                 * and bytes read from the brigade */
               count = 0;       /* Bytes read count */
    apr_bucket_brigade *bb;

    /* Allocate the body buffer */
    *body = apr_palloc(r->pool, limit + 1);

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
            status = apr_brigade_flatten(bb, (*body) + count, &bytes);
            if (status != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, LOG_DEBUG, status, r, "reading bb");
            }
            count += bytes;
        }

        /* Discard the data */
        apr_brigade_cleanup(bb);
    } while ((status == APR_SUCCESS) && (count < limit));

    /* NULL terminate */
    body[count] = '\0';

    return count;
}

typedef struct
{
    const char *session_id;
    const char *url;
} sqrl_rec;

typedef struct
{
    apr_int32_t counter;
} sqrl_svr_cfg;

typedef struct
{
} sqrl_dir_cfg;

module AP_MODULE_DECLARE_DATA sqrl_module;


/*
 * SQRL functions
 */

/**
 * Encode binary data to URL-safe base64.
 * http://tools.ietf.org/html/rfc4648
 * @param p Memory pool to allocate the returned encoded string.
 * @param plain Binary data to encode. '\0' does not terminate the data.
 * @param plain_len Number of bytes in plain to encode.
 * @return Base64url encoded string. Terminated by '\0'.
 */
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

#define SESSION_ID_LEN 16
static sqrl_rec *generate_sqrl(request_rec * r, const char *scheme,
                               const char *domain, const char *additional,
                               const char *path)
{
    sqrl_rec *sqrl = apr_palloc(r->pool, sizeof(sqrl_rec));
    apr_time_t time_now = apr_time_sec(apr_time_now());
    unsigned char *nonce = apr_palloc(r->pool, 4);
    apr_size_t ip_len = strlen(r->useragent_ip);
    unsigned char *ip_buff = apr_palloc(r->pool, 12 + ip_len);
    unsigned char *ip_hash = apr_palloc(r->pool, crypto_hash_BYTES);
    unsigned char *nut_buff = apr_palloc(r->pool, 32);
    char *nut;
    unsigned char *session_id_bytes;
    size_t additional_len;
    sqrl_svr_cfg *conf;

    /* Validate inputs */
    if (!scheme || *scheme == '\0') {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "Setting scheme to 'qrl'");
        scheme = "qrl";
    }
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "scheme = %s", scheme);
    if (!domain || *domain == '\0') {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                      "Setting domain to self's domain");
        domain = r->server->server_hostname;
    }
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "domain = %s", domain);
    if (!path || *path == '\0') {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                      "Setting path to 'sqrl_auth'");
        path = "sqrl_auth";
    }
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "path = %s", path);

    /* Generate a session id */
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "Generating session id");
    session_id_bytes = apr_palloc(r->pool, SESSION_ID_LEN);
    randombytes(session_id_bytes, SESSION_ID_LEN);      /* libsodium PRNG */

    /* Convert the session id to base64 */
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "Converting session id to base64");
    sqrl->session_id =
        sqrl_base64url_encode(r->pool, session_id_bytes, SESSION_ID_LEN);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "session_id = %s",
                  sqrl->session_id);

    /* Generate a nonce */
    randombytes(nonce, 4);

    /* Load the config to get the counter */
    conf = ap_get_module_config(r->server->module_config, &sqrl_module);

    /* Build a salted IP */
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "Clients IP = %s",
                  r->useragent_ip);
    ++conf->counter;            /* TODO increment_and_get() */
    ip_buff[0] = time_now >> 24 & 0xff;
    ip_buff[1] = time_now >> 16 & 0xff;
    ip_buff[2] = time_now >> 8 & 0xff;
    ip_buff[3] = time_now & 0xff;
    ip_buff[4] = conf->counter >> 24 & 0xff;
    ip_buff[5] = conf->counter >> 16 & 0xff;
    ip_buff[6] = conf->counter >> 8 & 0xff;
    ip_buff[7] = conf->counter & 0xff;
    memcpy((ip_buff + 8), nonce, 4);
    memcpy((ip_buff + 12), r->useragent_ip, ip_len);

    /* Hash the salted IP */
    crypto_hash(ip_hash, ip_buff, (12 + ip_len));       /* int returned? */

    /* Build the authentication URL's nut */
    memcpy(nut_buff, session_id_bytes, SESSION_ID_LEN);
    memcpy((nut_buff + 16), ip_buff, 12);
    nut_buff[28] = ip_hash[0];
    nut_buff[29] = ip_hash[1];
    nut_buff[30] = ip_hash[2];
    nut_buff[31] = ip_hash[3];
    /* TODO encrypt nut_buff before base64 encoding */
    nut = sqrl_base64url_encode(r->pool, nut_buff, 32);

    /* Generate the url */
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r,
                  "Put it all together to make the URL");
    if (additional && (additional_len = strlen(additional)) > 1) {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "additional = %s",
                      additional);
        sqrl->url =
            apr_pstrcat(r->pool, scheme, "://", domain, additional, "|", path,
                        "?nut=", nut, NULL);
    }
    else {
        ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "No additional domain");
        sqrl->url =
            apr_pstrcat(r->pool, scheme, "://", domain, "/", path, "?nut=",
                        nut, NULL);
    }
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, 0, r, "url = %s", sqrl->url);

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
    apr_hash_index_t *param;    /* Current parameter */
    const char *key;            /* Parameter key */
    apr_array_header_t *values; /* Parameter value */

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

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "hostname = %s", hostname);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "uri = %s", uri);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "blen = %zu", blen);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "body = %s", body);

    ap_set_content_type(r, "text/html;charset=us-ascii");
    ap_rprintf(r,
               "<!DOCTYPE html>\n<html>\n<head><title>SQRL</title></head>\n"
               "<body>\n<pre>hostname = %s</pre>\n<pre>uri = %s</pre><br/>\n"
               "<table>\n<caption>Querystring</caption>\n", hostname, uri);

    for (param = apr_hash_first(r->pool, params); param != NULL;
         param = apr_hash_next(param)) {
        int i;
        apr_hash_this(param, (const void **) &key, NULL, (void *) &values);
        for (i = 0; i < values->nelts; ++i) {
            ap_rprintf(r, "<tr><td>%s</td><td>%s</td></tr>\n", key,
                       APR_ARRAY_IDX(values, i, char *));
        }
    }

    ap_rprintf(r,
               "</table>\n<br/><pre>body = %s</pre><br/>\n"
               "<table>\n<caption>Body</caption>\n", body);

    params = parse_form_data(r->pool, body, 10);
    for (param = apr_hash_first(r->pool, params); param != NULL;
         param = apr_hash_next(param)) {
        int i;
        apr_hash_this(param, (const void **) &key, NULL, (void *) &values);
        for (i = 0; i < values->nelts; ++i) {
            ap_rprintf(r, "<tr><td>%s</td><td>%s</td></tr>\n", key,
                       APR_ARRAY_IDX(values, i, char *));
        }
    }

    ap_rputs("</table>\n</body>\n</html>\n", r);

    return OK;
}

/*
 * mod_include extention.
 */

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
        sqrl = generate_sqrl(r, NULL, NULL, "/test", NULL);
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

static int sqrl_post_config(apr_pool_t * p, apr_pool_t * plog,
                            apr_pool_t * ptemp, server_rec * s)
{
    int rv;

    /* Retrieve mod_include's optional functions */
    sqrl_reg_ssi = APR_RETRIEVE_OPTIONAL_FN(ap_register_include_handler);
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


/*
 * Configuration
 */

static void *create_server_config(apr_pool_t * pool, server_rec * s)
{
    sqrl_svr_cfg *conf = apr_palloc(pool, sizeof(sqrl_svr_cfg));
    unsigned char *counter_bytes = apr_palloc(pool, 4);
    randombytes(counter_bytes, 4);
    conf->counter = ((counter_bytes[0] << 24) |
                     (counter_bytes[1] << 16) |
                     (counter_bytes[2] << 8) | (counter_bytes[3]));
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
    ap_hook_post_config(sqrl_post_config, pre, NULL, APR_HOOK_MIDDLE);
}

/* Module Data Structure */
module AP_MODULE_DECLARE_DATA sqrl_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory configuration record */
    NULL,                       /* merge per-directory configuration records */
    create_server_config,       /* create per-server configuration record */
    NULL,                       /* merge per-server configuration records */
    configuration_cmds,         /* configuration directives */
    register_hooks              /* register modules functions with the core */
};
