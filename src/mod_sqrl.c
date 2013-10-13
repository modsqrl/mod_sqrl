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
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_hash.h"
#include "apr_strings.h"


/**
 * Parse application/x-www-form-urlencoded form data from a string.
 * @param pool Memory allocation pool.
 * @param str Data to parse.
 * @param limit The maxium number of parameters to parse out of the string.
 * @return Hashtable of parsed parameters. Because a key can have multiple
 *         values, the hashtable value is an array of parameter values.
 */
static apr_hash_t *parse_form_data(apr_pool_t * pool, char *str, int limit)
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

typedef struct
{
} sqrl_config_rec;

module AP_MODULE_DECLARE_DATA sqrl_module;

static int authenticate_sqrl(request_rec * r)
{
    sqrl_config_rec *conf;
    const char *hostname;
    char *uri;
    apr_hash_t *params;
    apr_hash_index_t *param;
    const char *key;
    apr_array_header_t *values;

    conf = ap_get_module_config(r->per_dir_config, &sqrl_module);

    if (!r->handler || (strcmp(r->handler, "sqrl") != 0)) {
        return DECLINED;
    }

    if (r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "Verifying SQRL code ...");

    hostname = r->hostname;
    uri = r->unparsed_uri;
    params = parse_form_data(r->pool, r->args, 10);

    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "hostname = %s", hostname);
    ap_log_rerror(APLOG_MARK, LOG_DEBUG, OK, r, "uri = %s", uri);

    ap_set_content_type(r, "text/html;charset=us-ascii");
    ap_rprintf(r,
               "<!DOCTYPE html>\n<html>\n<head><title>SQRL</title></head>\n"
               "<body>\nhostname = %s<br/>\nuri = %s<br/><br/>\n"
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

    ap_rputs("</table>\n</body>\n</html>\n", r);

    return OK;
}


/*
 * Configuration
 */

static const command_rec configuration_cmds[] = {
    {NULL}
};

/*
 * Apache Registration
 */

/* Register mod_sqrl with Apache */
static void register_hooks(apr_pool_t * pool)
{
    ap_hook_handler(authenticate_sqrl, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module Data Structure */
module AP_MODULE_DECLARE_DATA sqrl_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory configuration record */
    NULL,                       /* merge per-directory configuration records */
    NULL,                       /* create per-server configuration record */
    NULL,                       /* merge per-server configuration records */
    configuration_cmds,         /* configuration directives */
    register_hooks              /* register modules functions with the core */
};
