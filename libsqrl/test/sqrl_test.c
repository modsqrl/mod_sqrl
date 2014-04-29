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

#include <check.h>
#include <sqrl.h>

static apr_pool_t *p;

static void setup()
{
    apr_pool_create_unmanaged(&p);
}

static void teardown()
{
    apr_pool_destroy(p);
}

START_TEST(CreateSqrl)
{
    int x = 5;
    int y = '5';
    ck_assert_int_eq(x,y);
}
END_TEST

Suite *sqrl_suite()
{
    Suite *s = suite_create("sqrl");

    TCase *tc_sqrl = tcase_create("sqrl");
    tcase_add_checked_fixture(tc_sqrl, setup, teardown);
    tcase_add_test(tc_sqrl, CreateSqrl);
    suite_add_tcase(s, tc_sqrl);

    return s;
}

