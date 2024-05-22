/*
Copyright (c) 2024 by Tomaz Mascarenhas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h> // memcmp on MacOS
#include <unistd.h> // STDOUT_FILENO on MacOS
#include <time.h>
#include <arpa/inet.h>

#include "test_utilities.h"
#include "../babeld.h"
#include "../util.h"
#include "../kernel.h"

#define N_RANDOM_TESTS 128
#define SEED 42

void roughly_test(void)
{
    int i, input, output, lower_bound, upper_bound;

    srand(SEED);

    for (i = 0; i < N_RANDOM_TESTS; i++) {
        input = rand() % 1024;
        if (rand() % 2) {
            input = -input;
        }

        output = roughly(input);
        lower_bound = 3 * input / 4;
        upper_bound = 5 * input / 4;

        if (input < 0) {
            swap(&lower_bound, &upper_bound);
        }

        if(!babel_check(output >= lower_bound)) {
            fprintf(stderr, "Output of roughly function was too low. Input: %d / Output: %d.\n", input, output);
            fflush(stderr);
        }

        if(!babel_check(output <= upper_bound)) {
            fprintf(stderr, "Output of roughly function was too high. Input: %d / Output: %d.\n", input, output);
            fflush(stderr);
        }
    }

    if(!babel_check(roughly(1) == 1)) {
        fprintf(stderr, "roughly(1) should be 1.\n");
        fflush(stderr);
    }
    if(!babel_check(roughly(0) == 0)) {
        fprintf(stderr, "roughly(1) should be 0.\n");
        fflush(stderr);
    }
}

void timeval_minus_test(void)
{
    struct timeval *tv1, *tv2, result;
    int i, num_of_cases;

    typedef struct test_case {
        struct timeval tv1_val;
        struct timeval tv2_val;
        struct timeval expected;
    } test_case;

    test_case tcs[] =
    {
        { {42, 10}, {42, 10}, {0, 0} },
        { {45, 10}, {42, 8},  {3, 2} },
        { {45, 10}, {42, 11}, {2, 999999} }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        tv1 = &tcs[i].tv1_val;
        tv2 = &tcs[i].tv2_val;

        timeval_minus(&result, tv1, tv2);

        if(!babel_check(result.tv_usec == tcs[i].expected.tv_usec ||
                        result.tv_sec == tcs[i].expected.tv_sec)) {
            fprintf(stderr,
                "timeval_minus(%ld.%06ld, %ld.%06ld) = %ld.%06ld, expected: %ld.%06ld.\n",
                tv1->tv_sec,
                tv1->tv_usec,
                tv2->tv_sec,
                tv2->tv_usec,
                result.tv_sec,
                result.tv_usec,
                tcs[i].expected.tv_sec,
                tcs[i].expected.tv_usec
            );
            fflush(stderr);
        }
    }
}

void timeval_minus_msec_test(void)
{
    struct timeval *tv1, *tv2;
    int i, num_of_cases;
    unsigned result;

    typedef struct test_case {
        struct timeval tv1_val;
        struct timeval tv2_val;
        unsigned expected;
    } test_case;

    test_case tcs[] =
    {
        { {42, 10}, {42, 10}, 0 },
        { {100, 20000}, {40, 5000}, 60015 },
        { {100, 20000}, {40, 5001}, 60014 },
        { {100, 20000}, {100, 19000}, 1 },
        { {100, 20000}, {101, 19000}, 0 },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        tv1 = &tcs[i].tv1_val;
        tv2 = &tcs[i].tv2_val;

        result = timeval_minus_msec(tv1, tv2);

        if(!babel_check(result == tcs[i].expected)) {
            fprintf(stderr,
                "timeval_minus_msec(%ld.%06ld, %ld.%06ld) = %u, expected: %u.\n",
                tv1->tv_sec,
                tv1->tv_usec,
                tv2->tv_sec,
                tv2->tv_usec,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void timeval_add_msec_test(void)
{
    struct timeval *tv, result;
    int msecs, num_of_cases, i, test_ok;

    typedef struct test_case {
        struct timeval tv1_val;
        int msecs_val;
        struct timeval expected;
    } test_case;

    test_case tcs[] =
    {
        { {42, 10}, 50, { 42, 50010 } },
        { {42, 990000}, 10, { 43, 0 } },
        { {42, 990000}, 20, { 43, 10000 } }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        tv = &tcs[i].tv1_val;
        msecs = tcs[i].msecs_val;

        timeval_add_msec(&result, tv, msecs);

        test_ok = (result.tv_sec == tcs[i].expected.tv_sec);
        test_ok &= (result.tv_usec == tcs[i].expected.tv_usec);
        if(!babel_check(test_ok)) {
            fprintf(stderr,
                "timeval_add_msec(%ld.%06ld, %d) = %ld.%06ld, expected: %ld.%06ld.",
                tv->tv_sec,
                tv->tv_usec,
                msecs,
                result.tv_sec,
                result.tv_usec,
                tcs[i].expected.tv_sec,
                tcs[i].expected.tv_usec
            );
            fflush(stderr);
        }
    }
}

void timeval_compare_test(void)
{
    struct timeval *tv1, *tv2;
    int result, i, num_of_cases;

    typedef struct test_case {
        struct timeval tv1_val;
        struct timeval tv2_val;
        int expected;
    } test_case;

    test_case tcs[] =
    {
        { {42, 10}, {42, 10}, 0 },
        { {42, 10}, {42, 50}, -1 },
        { {42, 50}, {42, 10}, 1 },
        { {42, 10}, {52, 10}, -1 },
        { {52, 10}, {42, 10}, 1 },
        { {52, 10}, {42, 5}, 1 },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        tv1 = &tcs[i].tv1_val;
        tv2 = &tcs[i].tv2_val;

        result = timeval_compare(tv1, tv2);

        if(!babel_check(result == tcs[i].expected)) {
            fprintf(stderr,
                "timeval_compare(%ld.%06ld, %ld.%06ld) = %d, expected: %d.",
                tv1->tv_sec,
                tv1->tv_usec,
                tv2->tv_sec,
                tv2->tv_usec,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void timeval_min_test(void)
{
    struct timeval s1, s2;
    int i, num_of_cases, test_ok;

    typedef struct test_case {
        struct timeval s1_val;
        struct timeval s2_val;
        struct timeval expected;
    } test_case;

    test_case tcs[] =
    {
        { {42, 10}, {42, 10}, {42, 10} },
        { {42, 10}, {0, 0}, {42, 10} },
        { {0, 0}, {42, 10}, {42, 10} },
        { {42, 9}, {42, 10}, {42, 9} },
        { {41, 15}, {42, 10}, {41, 15} },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        s1 = tcs[i].s1_val;
        s2 = tcs[i].s2_val;

        timeval_min(&s1, &s2);


        test_ok = (s1.tv_sec == tcs[i].expected.tv_sec);
        test_ok &= (s1.tv_usec == tcs[i].expected.tv_usec);
        if(!babel_check(test_ok)) {
            fprintf(stderr,
                "timeval_min(%ld.%06ld, %ld.%06ld) = %ld.%06ld, expected: %ld.%06ld.",
                tcs[i].s1_val.tv_sec,
                tcs[i].s1_val.tv_usec,
                tcs[i].s2_val.tv_sec,
                tcs[i].s2_val.tv_usec,
                s1.tv_sec,
                s1.tv_usec,
                tcs[i].expected.tv_sec,
                tcs[i].expected.tv_usec
            );
            fflush(stderr);
        }
    }
}

void timeval_min_sec_test(void)
{
    struct timeval s;
    time_t secs;
    int i, num_of_cases;

    typedef struct test_case {
        struct timeval s_val;
        time_t secs_val;
        time_t s_secs_expected;
    } test_case;

    test_case tcs[] =
    {
        { {42, 10}, 41, 41 },
        { {42, 10}, 43, 42 },
        // NOTE: Is it correct? Infinity shouldn't be just {0, 0}?
        { {0, 10}, 1024, 1024 }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        s = tcs[i].s_val;
        secs = tcs[i].secs_val;

        timeval_min_sec(&s, secs);


        if(!babel_check(s.tv_sec == tcs[i].s_secs_expected)) {
            fprintf(stderr,
                "timeval_min_sec(%ld.%06ld, %ld) = %ld._, expected: %ld._.",
                tcs[i].s_val.tv_sec,
                tcs[i].s_val.tv_usec,
                secs,
                s.tv_sec,
                tcs[i].s_secs_expected
            );
            fflush(stderr);
        }
    }
}

void parse_nat_test(void)
{
    const char *string;
    int result, i, num_of_cases;

    typedef struct test_case {
        const char *string_val;
        int expected;
    } test_case;

    test_case tcs[] =
    {
        { "42", 42 },
        { "212348123481293", -1 },
        { "0", 0 },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        string = tcs[i].string_val;

        result = parse_nat(string);

        if(!babel_check(result == tcs[i].expected)) {
            fprintf(stderr,
                "parse_nat(%s) = %d, expected: %d",
                string,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void parse_thousands_test(void)
{
    const char *string;
    int result, i, num_of_cases;

    typedef struct test_case {
        const char * const string_val;
        int expected;
    } test_case;

    test_case tcs[] =
    {
        { "42.1337", 42133 },
        { "10.123456", 10123 },
        { "0.1", 100 }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        string = tcs[i].string_val;

        result = parse_thousands(string);

        if(!babel_check(result == tcs[i].expected)) {
            fprintf(stderr,
                "parse_thousands(%s) = %d, expected: %d.",
                string,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void h2i_test(void)
{
    int result, i, num_of_cases;
    char c;

    typedef struct test_case {
        char c_val;
        int expected;
    } test_case;

    test_case tcs[] =
    {
        { '1', 1 },
        { '9', 9 },
        { 'A', 10 },
        { 'C', 12 },
        { 'd', 13 }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        c = tcs[i].c_val;

        result = h2i(c);

        if(!babel_check(result == tcs[i].expected)) {
            fprintf(stderr,
                "h2i(%c) = %d, expected: %d",
                c,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void util_test_suite(void) {
    run_test(roughly_test, "roughly_test");
    run_test(timeval_minus_test, "timeval_minus_test");
    run_test(timeval_minus_msec_test, "timeval_minus_test");
    run_test(timeval_add_msec_test,"timeval_add_msec_test");
    run_test(timeval_compare_test,"timeval_compare_test");
    run_test(timeval_min_test,"timeval_min_test");
    run_test(timeval_min_sec_test,"timeval_min_sec_test");
    run_test(parse_nat_test,"parse_nat_test");
    run_test(parse_thousands_test,"parse_thousands_test");
    run_test(h2i_test,"h2i_test");
}
