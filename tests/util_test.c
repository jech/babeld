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

void util_test_suite(void) {
    run_test(roughly_test, "roughly_test");
    run_test(timeval_minus_test, "timeval_minus_test");
    run_test(timeval_minus_msec_test, "timeval_minus_test");
}
