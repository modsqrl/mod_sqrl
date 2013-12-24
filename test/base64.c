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

#include "../src/utils.c"

int puts(const char *str);

apr_status_t ap_pass_brigade(ap_filter_t *filter, apr_bucket_brigade *bucket)
{
    return APR_SUCCESS;
}

char *sqrl_base64_encodesn(apr_pool_t * p, const char *str, size_t len)
{
    return sqrl_base64_encode(p, (const unsigned char *) str, len);
}

char *sqrl_base64_encodes(apr_pool_t * p, const char *str)
{
    return sqrl_base64_encodesn(p, str, strlen(str));
}

int main()
{
    char *str;
    const char *one = "abc", *two = "abcd", *three = "abcde", *four =
        "abcdef", *five = "abcdefghijklmnopqrstuvwxyz", *six = "a", *seven =
        "ab";
    size_t len;
    apr_pool_t *p;

    apr_pool_initialize();
    apr_pool_create_unmanaged(&p);

    str = sqrl_base64_encodes(p, six);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);
    str = sqrl_base64_encodes(p, seven);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);
    str = sqrl_base64_encodes(p, one);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);
    str = sqrl_base64_encodes(p, two);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);
    str = sqrl_base64_encodes(p, three);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);
    str = sqrl_base64_encodes(p, four);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);
    str = sqrl_base64_encodes(p, five);
    puts(str);
    str = (char *) sqrl_base64_decode(p, str, &len);
    puts(str);

    str = sqrl_base64_encodes(p, five);
    str[2] = 0x05;
    str = (char *) sqrl_base64_decode(p, str, &len);
    if (str == NULL) {
        puts("Correctly NULL");
    }
    else {
        puts(str);
    }

    str = sqrl_base64_encodes(p, five);
    str[5] = 0x05;
    str = (char *) sqrl_base64_decode(p, str, &len);
    if (str == NULL) {
        puts("Correctly NULL");
    }
    else {
        puts(str);
    }

    str = sqrl_base64_encodes(p, five);
    str[5] = 0x7f;
    str = (char *) sqrl_base64_decode(p, str, &len);
    if (str == NULL) {
        puts("Correctly NULL");
    }
    else {
        puts(str);
    }

    apr_pool_destroy(p);
    apr_pool_terminate();

    return 0;
}

