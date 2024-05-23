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
#include <string.h>
#include <netinet/in.h>

#include "test_utilities.h"
#include "../rfc6234/sha.h"
#include "../BLAKE2/ref/blake2.h"

#include "../babeld.h"
#include "../interface.h"
#include "../neighbour.h"
#include "../util.h"
#include "../hmac.h"
#include "../configuration.h"
#include "../kernel.h"

#define PACKET_HEADER_SIZE 4
#define MAX_PACKET_BODYLEN 500
#define HMAC_MAX_SIZE 32
#define KEY_MAX_SIZE 64

void add_key_test(void)
{
    int i, num_of_cases, type, len, test_ok;
    char *id;
    unsigned char *value;
    struct key *key;

    typedef struct test_case {
        char *id_val;
        int type_val;
        int len_val;
        unsigned char *value_val;
    } test_case;

    test_case tcs[] =
    {
        {
            .id_val = "k1",
            .type_val = AUTH_TYPE_SHA256,
            .len_val = 64,
            .value_val =
                (unsigned char[])
                    {54, 16,  17, 18, 192, 255, 238, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
        },
        {
            .id_val = "k2",
            .type_val = AUTH_TYPE_BLAKE2S128,
            .len_val = 32,
            .value_val =
                (unsigned char[])
                    {184, 17, 96, 231, 142, 203, 75, 118,
                     42, 213, 55, 90, 176, 66, 15, 104, 19,
                     214, 60, 175, 10, 203, 125, 180, 142,
                     232, 123, 168, 191, 50, 173, 44},
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    for(i = 0; i < num_of_cases; ++i) {
        id = tcs[i].id_val;
        type = tcs[i].type_val;
        len = tcs[i].len_val;
        value = tcs[i].value_val;

        key = add_key(id, type, len, value);

        test_ok = strcmp(id, key->id) == 0;
        test_ok &= type == key->type;
        test_ok &= len == key->len;
        test_ok &= memcmp(value, tcs[i].value_val, len) == 0;
        if(!babel_check(test_ok)) {
            fprintf(stderr,
                "add_key(%s, %d, %d, %s) =\n{ %s, %d, %d, %s }\nexpected: { %s, %d, %d, %s }.\n",
                id,
                type,
                len,
                str_of_array(value, len),
                key->id,
                key->type,
                key->len,
                str_of_array(key->value, key->len),
                id,
                type,
                len,
                str_of_array(value, len)
            );
            fflush(stderr);
        }
    }
}

void compute_hmac_test(void)
{
    unsigned char *src, *dst, *packet_header, *body, *hmac;
    int i, num_of_cases, bodylen;
    struct key *key;
    int hmac_len;

    typedef struct test_case {
        unsigned char src_val[ADDRESS_ARRAY_SIZE];
        unsigned char dst_val[ADDRESS_ARRAY_SIZE];
        unsigned char packet_header_val[PACKET_HEADER_SIZE];
        unsigned char body_val[MAX_PACKET_BODYLEN];
        int bodylen_val;
        struct key key_val;
        unsigned char hmac_expected[HMAC_MAX_SIZE];
    } test_case;

    test_case tcs[] =
    {
        {
            .src_val = {254, 128, 0, 0, 0, 0, 0, 0, 2, 22, 62, 255, 254, 197,
                225, 239},
            .dst_val = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6},
            .packet_header_val = {42, 2, 0, 34},
            .body_val = {8, 10, 0, 0, 0, 0, 255, 255, 105, 131, 255, 255, 4, 6,
                0, 0, 138, 241, 0, 10, 17, 12, 0, 0, 0, 13, 111, 180,
                121, 202, 112, 51, 238, 237},
            .bodylen_val = 34,
            .key_val = {
                .type = AUTH_TYPE_SHA256,
                .len = 64,
                .value =
                    (unsigned char[])
                        {54, 16,  17, 18, 192, 255, 238, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
            },
            .hmac_expected = {12, 124, 238, 71, 58, 55, 173, 152, 18, 174, 138,
                113, 75, 180, 31, 220, 144, 195, 126, 213, 130,
                199, 97, 20, 69, 93, 210, 180, 41, 147, 141, 49},
        },
        {
            .src_val = {254, 128, 0, 0, 0, 0, 0, 0, 2, 22, 62, 255, 254, 0, 0,
                0},
            .dst_val = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6},
            .packet_header_val = {42, 2, 0, 22},
            .body_val =
                {4, 6, 0, 0, 47, 84, 1, 144, 17, 12, 0, 0, 0, 14, 57,
                 72, 181, 138, 248, 108, 171, 133},
            .bodylen_val = 22,
            .key_val = {
                .type = AUTH_TYPE_BLAKE2S128,
                .len = 32,
                .value =
                    (unsigned char[])
                        {184, 17, 96, 231, 142, 203, 75, 118,
                         42, 213, 55, 90, 176, 66, 15, 104, 19,
                         214, 60, 175, 10, 203, 125, 180, 142,
                         232, 123, 168, 191, 50, 173, 44},
            },
            .hmac_expected =
                {237, 164, 28, 31, 153, 50, 126, 166, 67, 195, 21,
                 19, 123, 77, 57, 46, 112, 39, 177, 23, 146, 86, 0,
                 0, 246, 0, 0, 0, 0, 0, 0, 0}
        }
    };

    hmac = malloc(HMAC_MAX_SIZE);
    num_of_cases = sizeof(tcs) / sizeof(test_case);
    for(i = 0; i < num_of_cases; ++i) {
        src = tcs[i].src_val;
        dst = tcs[i].dst_val;
        packet_header = tcs[i].packet_header_val;
        body = tcs[i].body_val;
        bodylen = tcs[i].bodylen_val;
        key = &tcs[i].key_val;

        compute_hmac(src, dst, packet_header, body, bodylen, key, hmac);

        hmac_len = tcs[i].key_val.type == AUTH_TYPE_SHA256 ? 32 : 16;
        if(!babel_check(memcmp(hmac, tcs[i].hmac_expected, hmac_len) == 0)) {
            fprintf(stderr, "Failed test on compute_hmac:\n");
            fprintf(stderr, "src: %s\n", str_of_array(src, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "dst: %s\n", str_of_array(dst, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "packet_header: %s\n", str_of_array(packet_header, PACKET_HEADER_SIZE));
            fprintf(stderr, "body: %s\n", str_of_array(body, bodylen));
            fprintf(stderr, "bodylen: %d\n", bodylen);
            fprintf(stderr, "key value: %s\n", str_of_array(key->value, key->len));
            fprintf(stderr, "hmac computed: %s\n", str_of_array(hmac, hmac_len));
            fprintf(stderr, "hmac expected: %s\n", str_of_array(tcs[i].hmac_expected, hmac_len));
            fflush(stderr);
        }
    }
}

void setup(void)
{
    protocol_port = 6696;
}

void hmac_test_suite(void)
{
    setup();
    run_test(add_key_test, "add_key_test");
    run_test(compute_hmac_test, "compute_hmac_test");
}
