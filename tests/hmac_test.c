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

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_utilities.h"
#include "../rfc6234/sha.h"
#include "../BLAKE2/ref/blake2.h"

#include "../babeld.h"
#include "../interface.h"
#include "../hmac.h"
#include "../configuration.h"

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
            fprintf(stderr, "-----------------------------------------------\n");
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
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test on compute_hmac:\n");
            fprintf(stderr, "src: %s\n", str_of_array(src, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "dst: %s\n", str_of_array(dst, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "packet_header: %s\n", str_of_array(packet_header, PACKET_HEADER_SIZE));
            fprintf(stderr, "body: %s\n", str_of_array(body, bodylen));
            fprintf(stderr, "bodylen: %d\n", bodylen);
            fprintf(stderr, "key value: %s\n", str_of_array(key->value, key->len));
            fprintf(stderr, "hmac computed: %s\n", str_of_array(hmac, hmac_len));
            fprintf(stderr, "hmac expected: %s\n", str_of_array(tcs[i].hmac_expected, hmac_len));
        }
    }
}

void add_hmac_test(void)
{
    int i, num_of_cases, new_buf_len;
    struct buffered buf;
    struct interface ifp;
    unsigned char *packet_header;

    typedef struct test_case {
        struct in6_addr sin6_addr;
        unsigned char* buf_buf_val;
        int buf_len_val;
        int buf_size_val;
        unsigned char ll0_val[16];
        int numll_val;
        unsigned char *packet_header_val;
        struct key key_val;
        int expected_buf_len;
        unsigned char *expected_buf_val;
    } test_case;

    test_case tcs[] =
    {
        {
            .sin6_addr = { .s6_addr = { 255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6 }},
            .buf_buf_val = (unsigned char [])
                {4, 6, 0, 0, 172, 80, 0, 10, 17, 12, 0, 0, 0, 16, 101, 161, 234, 241, 60, 193, 123, 197},
            .buf_len_val = 22,
            .buf_size_val = 1448,
            .ll0_val = {254, 128, 0, 0, 0, 0, 0, 0, 2, 22, 62, 255, 254, 208, 154, 166},
            .numll_val = 1,
            .packet_header_val = (unsigned char []) {42, 2, 0, 22},
            .key_val = {
                .type = AUTH_TYPE_BLAKE2S128,
                .len = 32,
                .value = (unsigned char [])
                    {184, 17, 96, 231, 142, 203, 75, 118, 42, 213, 55, 90, 176, 66, 15, 104, 19,
                     214, 60, 175, 10, 203, 125, 180, 142, 232, 123, 168, 191, 50, 173, 44}
            },
            .expected_buf_len = 40,
            .expected_buf_val = (unsigned char [])
                {4, 6, 0, 0, 172, 80, 0, 10, 17, 12, 0, 0, 0, 16, 101, 161, 234, 241, 60, 193, 123,
                 197, 16, 16, 114, 37, 115, 35, 6, 165, 73, 235, 15, 109, 39, 142, 171, 237, 105,
                 190}
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    ifp.ll = malloc(16);

    for(i = 0; i < num_of_cases; i++) {
        buf.len = tcs[i].buf_len_val;
        buf.size = tcs[i].buf_size_val;
        buf.buf = tcs[i].buf_buf_val;
        buf.sin6.sin6_addr = tcs[i].sin6_addr;
        ifp.key = &tcs[i].key_val;
        memcpy(*(ifp.ll), tcs[i].ll0_val, 16);
        ifp.numll = tcs[i].numll_val;
        packet_header = tcs[i].packet_header_val;

        new_buf_len = add_hmac(&buf, &ifp, packet_header);

        if(!babel_check(new_buf_len == tcs[i].expected_buf_len)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr,
                    "Failed test on add_hmac:\n"
                    "add_hmac return code was %d, expected %d.\n",
                    new_buf_len,
                    tcs[i].expected_buf_len);
        } else if(!babel_check(memcmp(buf.buf, tcs[i].expected_buf_val, new_buf_len) == 0)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test on add_hmac:\n");
            fprintf(stderr, "ifp.ll[0]: %s\n", str_of_array(ifp.ll[0], 16));
            fprintf(stderr, "ifp.numll: %d\n", ifp.numll);
            fprintf(stderr, "ifp.key.type: AUTH_TYPE_%s\n",
                      ifp.key->type == AUTH_TYPE_SHA256 ? "SHA256" : "BLAKE2S128");
            fprintf(stderr, "ifp.key.len: %d\n", ifp.key->len);
            fprintf(stderr, "ifp.key.value: %s\n", str_of_array(ifp.key->value, ifp.key->len));
            fprintf(stderr, "buf.len: %d\n", buf.len);
            fprintf(stderr, "buf.size: %d\n", buf.size);
            fprintf(stderr, "original buf.buf: %s\n", str_of_array(tcs[i].buf_buf_val, tcs[i].buf_len_val));
            fprintf(stderr, "buf.sin6.sin6_addr: %s\n",
                      str_of_array(buf.sin6.sin6_addr.s6_addr, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "packet_header: %s\n", str_of_array(packet_header, PACKET_HEADER_SIZE));
            fprintf(stderr, "resulting buf: %s\n", str_of_array(buf.buf, new_buf_len));
            fprintf(stderr, "expected buf: %s\n", str_of_array(tcs[i].expected_buf_val, tcs[i].expected_buf_len));
        }
    }

    free(ifp.ll);
}

void check_hmac_test(void)
{
    int i, num_of_cases, packetlen, bodylen, rc;
    unsigned char *packet, *src, *dst;
    struct interface ifp;

    typedef struct test_case {
        unsigned char *packet_val;
        int packetlen_val;
        int bodylen_val;
        unsigned char src_val[ADDRESS_ARRAY_SIZE];
        unsigned char dst_val[ADDRESS_ARRAY_SIZE];
        struct key key_val;
        int expected_rc;
    } test_case;

    test_case tcs[] =
    {
        {
            .packet_val = (unsigned char[])
                {42, 2, 0, 38, 4, 6, 0, 0, 41, 222, 1, 144, 5, 14, 3, 0, 255, 255, 4, 176, 206, 28,
                 12, 0, 201, 49, 72, 251, 17, 12, 0, 0, 0, 11, 120, 212, 188, 48, 134, 68, 203, 254,
                 16, 16, 132, 247, 70, 15, 217, 7, 16, 58, 31, 87, 47, 237, 228, 51, 34, 45},
            .packetlen_val = 60,
            .bodylen_val = 38,
            .src_val = {254, 128, 0, 0, 0, 0, 0, 0, 28, 106, 200, 156, 164, 179, 1, 90},
            .dst_val = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6},
            .key_val = {
                .value = (unsigned char [])
                    {184, 17, 96, 231, 142, 203, 75, 118, 42, 213, 55, 90, 176, 66, 15, 104, 19,
                     214, 60, 175, 10, 203, 125, 180, 142, 232, 123, 168, 191, 50, 173, 44},
                .len = 32,
                .type = AUTH_TYPE_BLAKE2S128
            },
            .expected_rc = 1
        },
        {
            .packet_val = (unsigned char[])
                {42, 2, 0, 22, 4, 6, 0, 0, 204, 139, 1, 144, 17, 12, 0, 0, 0, 4, 80, 128, 214,
                 66, 231, 209, 171, 31, 16, 16, 213, 145, 25, 162, 84, 23, 13, 58, 217, 218,
                 90, 8, 163, 228, 206, 121},
            .packetlen_val = 44,
            .bodylen_val = 22,
            .src_val = {254, 128, 0, 0, 0, 0, 0, 0, 2, 22, 62, 255, 254, 208, 154, 166},
            .dst_val = {255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 6},
            .key_val = {
                .value = (unsigned char[])
                    {184, 17, 96, 231, 142, 203, 75, 118, 42, 213, 55, 90, 176, 66, 15, 104, 19,
                     214, 60, 175, 10, 203, 125, 180, 142, 232, 123, 168, 191, 50, 173, 44},
                .len = 32,
                .type = AUTH_TYPE_BLAKE2S128
            },
            .expected_rc = 0
        }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; ++i) {
        packet = tcs[i].packet_val;
        packetlen = tcs[i].packetlen_val;
        bodylen = tcs[i].bodylen_val;
        src = tcs[i].src_val;
        dst = tcs[i].dst_val;
        ifp.key = &tcs[i].key_val;

        rc = check_hmac(packet, packetlen, bodylen, src, dst, &ifp);

        if(!babel_check(rc == tcs[i].expected_rc)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test on check_hmac:\n");
            fprintf(stderr, "src: %s\n", str_of_array(src, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "dst: %s\n", str_of_array(dst, ADDRESS_ARRAY_SIZE));
            fprintf(stderr, "packetlen: %d\n", packetlen);
            fprintf(stderr, "packet: %s\n", str_of_array(packet, packetlen));
            fprintf(stderr, "bodylen: %d\n", bodylen);
            fprintf(stderr, "key value: %s\n", str_of_array(ifp.key->value, ifp.key->len));
            fprintf(stderr, "rc computed: %d\n", rc);
            fprintf(stderr, "rc expected: %d\n", tcs[i].expected_rc);
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
    run_test(add_hmac_test, "add_hmac_test");
    run_test(check_hmac_test, "check_hmac_test");
}
