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
#include <time.h>

#include "test_utilities.h"

int tests_failed = 0;

void
swap(int* a, int* b)
{
    int t = *a;
    *a = *b;
    *b = t;
}

char*
str_of_array(const unsigned char* const arr, int len) {
    int j;
    int pt;
    char *str = malloc(sizeof(char) * ARR_MAX_SIZE);

    pt = snprintf(str, 3, "{ ");
    for(j = 0; j < len - 1; ++j) {
        pt += snprintf(str + pt, 7, "0x%02x, ", arr[j]);
    }
    pt += snprintf(str + pt, 7, "0x%02x }", arr[len - 1]);

    return str;
}

int babel_check(int prop) {
    if(!prop)
        tests_failed++;
    return prop;
}

void run_test(void (*test)(void), const char* test_name) {
    struct timespec start, end;
    double diff_secs;
    clock_gettime(CLOCK_MONOTONIC, &start);
    test();
    clock_gettime(CLOCK_MONOTONIC, &end);
    diff_secs = end.tv_sec - start.tv_sec;
    diff_secs += (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%s done. Time taken: %.8f.\n", test_name, diff_secs);
}

void run_suite(void (*suite)(void), const char* suite_name) {
    struct timespec start, end;
    double diff_secs;
    clock_gettime(CLOCK_MONOTONIC, &start);
    suite();
    clock_gettime(CLOCK_MONOTONIC, &end);
    diff_secs = end.tv_sec - start.tv_sec;
    diff_secs += (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%s suite done. Total time taken: %.8f seconds.\n", suite_name, diff_secs);
}

