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


void setup(void)
{
    protocol_port = 6696;
}

void hmac_test_suite(void)
{
    setup();
    run_test(add_key_test, "add_key_test");
}
