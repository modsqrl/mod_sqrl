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

/*#include <string.h>*/
#include <check.h>
#include <sqrl_encodings.h>


#define _ck_assert_uint(X, O, Y) ck_assert_msg((X) O (Y), "Assertion '"#X#O#Y"' failed: "#X"==%u, "#Y"==%u", X, Y)

#define ck_assert_uint_eq(X, Y) _ck_assert_uint(X, ==, Y)

#define encode_str(pool, str) \
    sqrl_base64_encode(pool, (const unsigned char*)str, strlen(str))


typedef struct {
    const char *str, *b64;
} test_data;


apr_pool_t *p;
size_t datalen = 8;
test_data data[] = {
    {"",""},
    {"a","YQ"},
    {"ab","YWI"},
    {"abc","YWJj"},
    {"abcd","YWJjZA"},
    {"abcde","YWJjZGU"},
    {"abcdef","YWJjZGVm"},
    {"abcdefghijklmnopqrstuvwxyz","YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"}
};

void setup()
{
    apr_pool_create_unmanaged(&p);
}

void teardown()
{
    apr_pool_destroy(p);
}


START_TEST(Alphabet) {
    size_t chk_len;
    char *encoded, *hex;
    unsigned char *decoded;

    encoded = encode_str(p, data[_i].str);
    ck_assert(encoded != NULL);
    ck_assert_str_eq(encoded, data[_i].b64);
    decoded = sqrl_base64_decode(p, data[_i].b64, &chk_len);
    ck_assert(decoded != NULL);
    ck_assert_uint_eq(chk_len, strlen(data[_i].str));
    if(memcmp(decoded, data[_i].str, chk_len) != 0) {
        hex = bin2hex(p, decoded, chk_len, NULL);
        ck_abort_msg("decoded = %s", hex);
    }

}
END_TEST

START_TEST(All255)
{
    size_t chk_len;
    char *encoded, *bin_hex, *dec_hex;
    unsigned char c, *decoded, *bin;

    bin = (unsigned char*)apr_palloc(p, 255);
    for(c = 0 ; c < 255 ; ++c) {
        bin[c] = c;
    }

    encoded = sqrl_base64_encode(p, bin, 255);
    ck_assert(encoded != NULL);
    ck_assert_str_eq(encoded, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-");
    decoded = sqrl_base64_decode(p, encoded, &chk_len);
    ck_assert(decoded != NULL);
    ck_assert_uint_eq(chk_len, 255);
    if(memcmp(bin, decoded, chk_len) != 0) {
        bin_hex = bin2hex(p, bin, 255, NULL);
        dec_hex = bin2hex(p, decoded, chk_len, NULL);
        ck_abort_msg("bin = %s\ndecoded = %s", bin_hex, dec_hex);
    }
}
END_TEST


Suite *base64_suite()
{
    Suite *s = suite_create("Base64");

    TCase *tc_core = tcase_create("Base64");
    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_loop_test(tc_core, Alphabet, 0, datalen);
    tcase_add_test(tc_core, All255);
    suite_add_tcase(s, tc_core);

    return s;
}


int main()
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = base64_suite();
    sr = srunner_create(s);
    apr_pool_initialize();

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);
    apr_pool_terminate();

    return number_failed;
}

