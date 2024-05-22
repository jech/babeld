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

#define N_RANDOM_TESTS 128
#define SEED 42
#define EUI_SIZE 8

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

void fromhex_test(void)
{
    unsigned char *dst;
    const char *src;
    int n, i, num_of_cases, dst_len;

    typedef struct test_case {
        const char *src_val;
        unsigned char expected[ADDRESS_ARRAY_SIZE];
        int n_val;
    } test_case;

    test_case tcs[] =
    {
        { "ff",     {0xff},             2 },
        { "eeab",   {0xee, 0xab},       4 },
        { "0A2aC8", {0x0a, 0x2a, 0xc8}, 6 }
    };

    dst = malloc(ADDRESS_ARRAY_SIZE);

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 1; i < num_of_cases; i++) {
        src = tcs[i].src_val;
        n = tcs[i].n_val;

        dst_len = fromhex(dst, src, n);

        if(!babel_check(memcmp(dst, tcs[i].expected, dst_len) == 0)) {
            fprintf(stderr,
                "fromhex(\"%s\", %d) = %s, expected: %s",
                src,
                n,
                str_of_array(dst, dst_len),
                str_of_array(tcs[i].expected, tcs[i].n_val / 2)
            );
            fflush(stderr);
        }
    }
}

void in_prefix_test(void)
{
    const unsigned char *restrict prefix, *restrict address;
    unsigned char plen;
    int num_of_cases, i, result;

    typedef struct test_case {
        const unsigned char prefix_val[ADDRESS_ARRAY_SIZE];
        int prefix_val_length;
        const unsigned char address_val[ADDRESS_ARRAY_SIZE];
        int address_val_length;
        unsigned char plen_val;
        int expected;
    } test_case;

    test_case tcs[] =
    {
        { {0x2a, 0x2a}, 2, {0x2a, 0x2a, 0x2a}, 3, 16, 1 },
        { {0x2a, 0x15}, 2, {0x2a, 0x2a, 0x2a}, 3, 16, 0 },
        { {0x1, 0x2, 0xfe}, 3, {0x1, 0x2, 0xff}, 3, 23, 1 }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        prefix = tcs[i].prefix_val;
        address = tcs[i].address_val;
        plen = tcs[i].plen_val;

        result = in_prefix(prefix, address, plen);

        if(!babel_check(result == tcs[i].expected)) {
            fprintf(stderr,
                "in_prefix(%s, %s, %u) = %d, expected: %d.",
                str_of_array(address, tcs[i].address_val_length),
                str_of_array(prefix, tcs[i].prefix_val_length),
                plen,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void normalize_prefix_test(void)
{
    const unsigned char *restrict prefix;
    unsigned char *restrict result;
    unsigned char plen, mask;
    int num_of_cases, i, j, test_ok, bit_ok;

    typedef struct test_case {
        unsigned char expected[ADDRESS_ARRAY_SIZE];
        const unsigned char prefix_val[ADDRESS_ARRAY_SIZE];
        int prefix_size;
        unsigned char plen_val;
    } test_case;

    test_case tcs[] =
    {
        { {0x4, 0x6}, {0x4, 0x6}, 2, 16 },
        { {0x1, 0x2, 0xfc}, {0x1, 0x2, 0xff}, 3, 22 },
        { {0x1, 0x1, 0x1, 0x1}, {0x1, 0x1, 0x1, 0x0}, 4, 30 }
    };

    result = malloc(ADDRESS_ARRAY_SIZE);

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        prefix = tcs[i].prefix_val;
        plen = tcs[i].plen_val;

        normalize_prefix(result, prefix, plen);

        test_ok = memcmp(result, tcs[i].expected, plen / 8) == 0;
        for(j = 0; j < plen % 8; j++) {
            mask = 1 << (8 - j - 1);
            bit_ok = (result[plen / 8] & mask) ==
                     (tcs[i].expected[plen / 8] & mask);
            test_ok &= bit_ok;
        }
        if(!babel_check(test_ok)) {
            fprintf(stderr,
                "normalize_prefix(%s, %u) = %s, expected: %s.",
                str_of_array(prefix, tcs[i].prefix_size),
                plen,
                str_of_array(result, tcs[i].prefix_size),
                str_of_array(tcs[i].expected, tcs[i].prefix_size)
            );
            fflush(stderr);
        }
    }
}

void format_address_test(void)
{
    const unsigned char *address;
    const char *result;
    int num_of_cases, i;

    typedef struct test_case {
        unsigned char address_val[ADDRESS_ARRAY_SIZE];
        int address_length;
        const char *expected;
    } test_case;

    test_case tcs[] =
    {
        { {0xff, 0xfe, 0x78, 0x2a, 0x14, 0xf, 0x37, 0xc, 0x5a, 0x63, 0x55, 0x5, 0xc8, 0x96, 0x78, 0xff},
          16,
          "fffe:782a:140f:370c:5a63:5505:c896:78ff",
        },
        { {0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc},
          6,
          "aaaa:bbbb:cccc::",
        },
        { {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x7f, 0x0, 0x0, 0x1},
          16,
          "127.0.0.1",
        },
    };

    result = malloc(ADDRESS_ARRAY_SIZE);

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; i++) {
        address = tcs[i].address_val;

        result = format_address(address);

        if(!babel_check(strcmp(result, tcs[i].expected) == 0)) {
            fprintf(stderr,
                "format_address(%s) = %s, expected %s",
                str_of_array(address, tcs[i].address_length),
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void format_prefix_test(void)
{
    unsigned char plen, *prefix;
    const char *result;
    int num_of_cases, i;

    typedef struct test_case {
        unsigned char prefix_val[ADDRESS_ARRAY_SIZE];
        unsigned char plen_val;
        const char *expected;
    } test_case;

    test_case tcs[] =
    {
        { {255, 254, 120, 42, 20, 15, 55, 12, 90, 99, 85, 5, 200, 150, 120, 255},
          120,
          "fffe:782a:140f:370c:5a63:5505:c896:78ff/120",
        },
        { {170, 170, 187, 187, 204, 204},
           50,
          "aaaa:bbbb:cccc::/50",
        },
        { {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127,0,0,1},
          100,
          "127.0.0.1/4",
        },

    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; ++i) {
        plen = tcs[i].plen_val;
        prefix = tcs[i].prefix_val;

        result = format_prefix(prefix, plen);

        if(!babel_check(strcmp(result, tcs[i].expected) == 0)) {
            fprintf(stderr,
                "format_prefix(%s, %u) = %s, expected: %s.",
                str_of_array(prefix, 3),
                plen,
                result,
                tcs[i].expected
            );
            fflush(stderr);
        }
    }
}

void format_eui64_test(void)
{
    unsigned char *eui;
    const char *result;
    int num_of_cases, i;

    typedef struct test_case {
        unsigned char eui_val[EUI_SIZE];
        size_t eui_val_length;
        const char *expected;
    } test_case;

    test_case tcs[] =
    {
        { {255, 254, 120, 42, 20, 15, 55, 12},
          8,
          "ff:fe:78:2a:14:0f:37:0c",
        },
        { {170, 170, 187, 187, 204, 204, 221, 221},
          8,
          "aa:aa:bb:bb:cc:cc:dd:dd",
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; ++i) {
        eui = tcs[i].eui_val;

        result = format_eui64(eui);

        if(!babel_check(strcmp(result, tcs[i].expected) == 0)) {
            fprintf(stderr,
                "format_eui64(%s) = %s, expected: %s.",
                str_of_array(eui, tcs[i].eui_val_length),
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
    run_test(fromhex_test,"fromhex_test");
    run_test(in_prefix_test,"in_prefix_test");
    run_test(normalize_prefix_test,"normalize_prefix_test");
    run_test(format_address_test,"format_address_test");
    run_test(format_prefix_test,"format_prefix_test");
    run_test(format_eui64_test,"format_eui64_test");
}
