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

#define CATCH_CONFIG_MAIN

#include <cstring>
#include <vector>
#include "catch.hpp"

extern "C" {
#include "../src/sqrl_encodings.c"
}

#define encode_str(pool, str) \
    sqrl_base64_encode(pool, (const unsigned char*)str, strlen(str))

#define CHECK_STR(expected, str) CHECK(strcmp(expected, str) == 0)

typedef struct {
    const char *str, *b64;
    size_t str_len, chk_len;
} test;

class TestData {
public:
    const char *str, *b64;
    size_t str_len;
    TestData(const char *str, const char *b64);
};

TestData::TestData(const char *str, const char *b64) : str(str), b64(b64) {
    str_len = strlen(str);
}

TEST_CASE("Base64", "[encoding]") {
    size_t chk_len;
    apr_pool_t *p;
    char *encoded, *hex;
    unsigned char *decoded, *bin;
    std::vector<TestData> v;

    v.push_back(TestData("a", "YQ"));
    v.push_back(TestData("ab", "YWI"));
    v.push_back(TestData("abc", "YWJj"));
    v.push_back(TestData("abcd", "YWJjZA"));
    v.push_back(TestData("abcde", "YWJjZGU"));
    v.push_back(TestData("abcdef", "YWJjZGVm"));
    v.push_back(TestData("abcdefghijklmnopqrstuvwxyz",
                         "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"));

    apr_pool_initialize();
    apr_pool_create_unmanaged(&p);

    for(unsigned i = 0 ; i < v.size() ; ++i) {
        INFO("str = " << v[i].str << " ; b64 = " << v[i].b64);
        encoded = encode_str(p, v[i].str);
        REQUIRE(encoded != NULL);
        CAPTURE(encoded);
        CHECK_STR(v[i].b64, encoded);
        decoded = sqrl_base64_decode(p, v[i].b64, &chk_len);
        REQUIRE(decoded != NULL);
        CAPTURE((char*)decoded);
        CHECK_STR(v[i].str, (char*)decoded);
        CHECK(chk_len == v[i].str_len);
    }

    bin = (unsigned char*)apr_palloc(p, 255);
    for(unsigned char i = 0 ; i < 255 ; ++i) {
        bin[i] = i;
    }
    hex = bin2hex(p, bin, 255, NULL);
    CAPTURE(hex);
    encoded = sqrl_base64_encode(p, bin, 255);
    REQUIRE(encoded != NULL);
    CAPTURE(encoded);
    CHECK_STR("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-", encoded);
    decoded = sqrl_base64_decode(p, encoded, &chk_len);
    REQUIRE(decoded != NULL);
    CHECK(chk_len == 255);
    CAPTURE(bin2hex(p, decoded, chk_len, NULL));
    CHECK(memcmp(bin, decoded, chk_len) == 0);

    apr_pool_destroy(p);
    apr_pool_terminate();
}


