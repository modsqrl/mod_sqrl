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

#include <apr_pools.h>
#include <check.h>

Suite *base64_suite();
Suite *sqrl_suite();

int main()
{
    int number_failed;
    SRunner *sr;

    apr_pool_initialize();

    sr = srunner_create(base64_suite());
    srunner_add_suite(sr, sqrl_suite());

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);

    srunner_free(sr);
    apr_pool_terminate();

    return number_failed;
}

