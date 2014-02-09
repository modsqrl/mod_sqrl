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
        CHECK_STR(v[i].b64, encode_str(p, v[i].str));
        CHECK_STR(v[i].str, (char*)sqrl_base64_decode(p, v[i].b64, &chk_len));
        CHECK(chk_len == v[i].str_len);
    }

    apr_pool_destroy(p);
    apr_pool_terminate();
}


