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

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "test_utilities.h"

#include "../babeld.h"
#include "../configuration.h"
#include "../interface.h"
#include "../kernel.h"
#include "../neighbour.h"
#include "../route.h"
#include "../source.h"
#include "../util.h"

#define N_ROUTES 6

struct neighbour *ns[N_ROUTES];

int sign(int x) {
    if(x > 0)
        return 1;
    if(x < 0)
        return -1;
    return 0;
}

int route_list_length(struct babel_route *r) {
    int length = 0;
    while(r != NULL) {
        length++;
        r = r->next;
    }
    return length;
}

void route_compare_test(void)
{
    int i, num_of_cases, rc_sign;
    unsigned char *prefix, *src_prefix;
    unsigned char plen, src_plen;
    struct babel_route route;

    typedef struct test_case {
        unsigned char *prefix_val;
        unsigned char plen_val;
        unsigned char *src_prefix_val;
        unsigned char src_plen_val;
        unsigned char *route_src_prefix_val;
        unsigned char route_src_plen_val;
        unsigned char *route_prefix_val;
        unsigned char route_plen_val;
        int expected_rc_sign;
    } test_case;

    test_case tcs[] =
    {
        {
            .prefix_val = (unsigned char[])
                { 204, 191, 204, 17, 179, 148, 97, 201, 24, 33, 133, 32, 138, 138, 104, 235 },
            .plen_val = 128,
            .src_prefix_val = (unsigned char[])
                { 167, 145, 127, 130, 201, 185, 216, 226, 87, 1, 78, 203, 236, 64, 33, 184 },
            .src_plen_val = 96,
            .route_src_prefix_val = (unsigned char[])
                { 0, 237, 201, 179, 130, 42, 124, 154, 75, 1, 186, 213, 139, 34, 192, 50 },
            .route_src_plen_val = 96,
            .route_prefix_val = (unsigned char[])
                { 180, 64, 181, 125, 249, 141, 95, 81, 142, 173, 28, 122, 238, 61, 50, 238 },
            .route_plen_val = 128,
            .expected_rc_sign = 24
        },
        {
            .prefix_val = (unsigned char[])
                { 204, 191, 204, 17, 179, 148, 97, 201, 24, 33, 133, 32, 138, 138, 104, 235 },
            .plen_val = 128,
            .src_prefix_val = (unsigned char[])
                { 167, 145, 127, 130, 201, 185, 216, 226, 87, 1, 78, 203, 236, 64, 33, 184 },
            .src_plen_val = 0,
            .route_src_prefix_val = (unsigned char[])
                { 0, 237, 201, 179, 130, 42, 124, 154, 75, 1, 186, 213, 139, 34, 192, 50 },
            .route_src_plen_val = 96,
            .route_prefix_val = (unsigned char[])
                { 180, 64, 181, 125, 249, 141, 95, 81, 142, 173, 28, 122, 238, 61, 50, 238 },
            .route_plen_val = 128,
            .expected_rc_sign = 1
        },
        {
            .prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .plen_val = 128,
            .src_prefix_val = (unsigned char[])
                { 234, 209, 73, 225, 36, 213, 61, 230, 152, 59, 215, 238, 134, 233, 23, 140 },
            .src_plen_val = 96,
            .route_src_prefix_val = (unsigned char[])
                { 5, 224, 238, 168, 213, 155, 140, 95, 208, 200, 219, 162, 95, 201, 94, 65 },
            .route_src_plen_val = 0,
            .route_prefix_val = (unsigned char[])
                { 225, 33, 114, 8, 246, 83, 140, 92, 194, 195, 254, 241, 86, 75, 18, 40 },
            .route_plen_val = 128,
            .expected_rc_sign = -1
        },
        {
            .prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .plen_val = 10,
            .src_prefix_val = (unsigned char[])
                { 234, 209, 73, 225, 36, 213, 61, 230, 152, 59, 215, 238, 134, 233, 23, 140 },
            .src_plen_val = 96,
            .route_src_prefix_val = (unsigned char[])
                { 5, 224, 238, 168, 213, 155, 140, 95, 208, 200, 219, 162, 95, 201, 94, 65 },
            .route_src_plen_val = 96,
            .route_prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .route_plen_val = 128,
            .expected_rc_sign = -1
        },
        {
            .prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .plen_val = 128,
            .src_prefix_val = (unsigned char[])
                { 234, 209, 73, 225, 36, 213, 61, 230, 152, 59, 215, 238, 134, 233, 23, 140 },
            .src_plen_val = 96,
            .route_src_prefix_val = (unsigned char[])
                { 5, 224, 238, 168, 213, 155, 140, 95, 208, 200, 219, 162, 95, 201, 94, 65 },
            .route_src_plen_val = 96,
            .route_prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .route_plen_val = 10,
            .expected_rc_sign = 1
        },
        {
            .prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .plen_val = 128,
            .src_prefix_val = (unsigned char[])
                { 234, 209, 73, 225, 36, 213, 61, 230, 152, 59, 215, 238, 134, 233, 23, 140 },
            .src_plen_val = 96,
            .route_src_prefix_val = (unsigned char[])
                { 5, 224, 238, 168, 213, 155, 140, 95, 208, 200, 219, 162, 95, 201, 94, 65 },
            .route_src_plen_val = 96,
            .route_prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .route_plen_val = 128,
            .expected_rc_sign = 1
        },
        {
            .prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .plen_val = 128,
            .src_prefix_val = (unsigned char[])
                { 234, 209, 73, 225, 36, 213, 61, 230, 152, 59, 215, 238, 134, 233, 23, 140 },
            .src_plen_val = 0,
            .route_src_prefix_val = (unsigned char[])
                { 5, 224, 238, 168, 213, 155, 140, 95, 208, 200, 219, 162, 95, 201, 94, 65 },
            .route_src_plen_val = 0,
            .route_prefix_val = (unsigned char[])
                { 201, 5, 52, 158, 160, 192, 253, 113, 137, 217, 19, 232, 162, 114, 41, 141 },
            .route_plen_val = 128,
            .expected_rc_sign = 0
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    route.src = malloc(sizeof(struct source));
    for(i = 0; i < num_of_cases; ++i) {
        prefix = tcs[i].prefix_val;
        plen = tcs[i].plen_val;
        src_prefix = tcs[i].src_prefix_val;
        src_plen = tcs[i].src_plen_val;
        route.src->plen = tcs[i].route_plen_val;
        memcpy(route.src->prefix, tcs[i].route_prefix_val, 16);
        route.src->src_plen = tcs[i].route_src_plen_val;
        memcpy(route.src->src_prefix, tcs[i].route_src_prefix_val, 16);

        rc_sign = route_compare(prefix, plen, src_prefix, src_plen, &route);

        // The magnitude of the result of memcmp is implementation-dependent, so we can only check
        // if we got the right sign
        if(!babel_check(sign(rc_sign) == sign(tcs[i].expected_rc_sign))) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test (%d) on route_compare\n", i);
            fprintf(stderr, "prefix: %s\n", format_prefix(prefix, plen));
            fprintf(stderr, "src_prefix: %s\n", format_prefix(src_prefix, src_plen));
            fprintf(stderr, "route->src->prefix: %s\n", format_prefix(route.src->prefix, route.src->plen));
            fprintf(stderr, "route->src->src_prefix: %s\n", format_prefix(route.src->src_prefix, route.src->src_plen));
            fprintf(stderr, "expected rc: %d\n", tcs[i].expected_rc_sign);
            fprintf(stderr, "computed rc: %d\n", rc_sign);
        }
    }
    free(route.src);
}

void find_route_slot_test(void)
{
    int i, num_of_cases, rc, new_return, test_ok;
    unsigned char *prefix, *src_prefix;
    unsigned char plen, src_plen;

    typedef struct test_case {
        unsigned char *prefix_val;
        unsigned char plen_val;
        unsigned char *src_prefix_val;
        unsigned char src_plen_val;
        int expected_rc;
        int expected_new_return;
    } test_case;

    test_case tcs[] =
    {
        {
            .prefix_val = (unsigned char[])
                { 145, 103, 214, 219, 183, 36, 182, 66, 11, 175, 199, 131, 227, 198, 7, 136 },
            .plen_val = 54,
            .src_prefix_val = (unsigned char[])
                { 97, 114, 138, 89, 89, 22, 41, 71, 180, 179, 225, 48, 49, 80, 170, 194 },
            .src_plen_val = 99,
            .expected_rc = -1,
            .expected_new_return = 4
        },
        {
            .prefix_val = (unsigned char[])
                { 78, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
            .plen_val = 101,
            .src_prefix_val = (unsigned char[])
                { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
            .src_plen_val = 115,
            .expected_rc = 1,
            .expected_new_return = -1
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    for(i = 0; i < num_of_cases; ++i) {
        prefix = tcs[i].prefix_val;
        plen = tcs[i].plen_val;
        src_prefix = tcs[i].src_prefix_val;
        src_plen = tcs[i].src_plen_val;
        new_return = -1;

        rc = find_route_slot(prefix, plen, src_prefix, src_plen, &new_return);

        test_ok = (tcs[i].expected_rc == -1 && new_return == tcs[i].expected_new_return) ||
                  (tcs[i].expected_rc == rc);
        if (!babel_check(test_ok)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test (%d) on route_compare\n", i);
            fprintf(stderr, "prefix: %s\n", format_prefix(prefix, plen));
            fprintf(stderr, "src_prefix: %s\n", format_prefix(src_prefix, src_plen));
            fprintf(stderr, "expected rc: %d\n", tcs[i].expected_rc);
            fprintf(stderr, "computed rc: %d\n", rc);
            fprintf(stderr, "expected new_return: %d\n", tcs[i].expected_new_return);
            fprintf(stderr, "computed new_return: %d\n", new_return);
        }
    }
}

void find_route_test(void)
{
    int i, num_of_cases;
    unsigned char *prefix, *src_prefix;
    unsigned char plen, src_plen;
    struct babel_route *route, *expected_route;
    struct neighbour *neigh;

    typedef struct test_case {
        unsigned char *prefix_val;
        unsigned char plen_val;
        unsigned char *src_prefix_val;
        unsigned char src_plen_val;
        int neigh_index_val;
        int expected_route_index;
    } test_case;

    test_case tcs[] =
    {
        {
            .prefix_val = (unsigned char[])
                { 78, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
            .plen_val = 101,
            .src_prefix_val = (unsigned char[])
                { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
            .src_plen_val = 115,
            .neigh_index_val = 1,
            .expected_route_index = 1
        },
        {
            .prefix_val = (unsigned char[])
                { 68, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
            .plen_val = 101,
            .src_prefix_val = (unsigned char[])
                { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
            .src_plen_val = 115,
            .neigh_index_val = -1,
            .expected_route_index = -1
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; ++i) {
        prefix = tcs[i].prefix_val;
        plen = tcs[i].plen_val;
        src_prefix = tcs[i].src_prefix_val;
        src_plen = tcs[i].src_plen_val;
        neigh = ns[tcs[i].neigh_index_val];

        route = find_route(prefix, plen, src_prefix, src_plen, neigh);

        expected_route =
            tcs[i].expected_route_index == -1 ? NULL : routes[tcs[i].expected_route_index];
        if(!babel_check(route == expected_route)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test (%d) on find_route\n", i);
            fprintf(stderr, "prefix: %s\n", format_prefix(prefix, plen));
            fprintf(stderr, "src_prefix: %s\n", format_prefix(src_prefix, src_plen));
            fprintf(stderr, "neighbour: ns[%d]\n", tcs[i].neigh_index_val);
            fprintf(stderr, "expected route: routes[%d]\n", tcs[i].expected_route_index);
        }
    }
}

void find_installed_route_test(void)
{

    unsigned char prefix[] =
      { 78, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 };
    unsigned char src_prefix[] =
      { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 };
    unsigned char plen = 101;
    unsigned char src_plen = 115;

    struct babel_route *route = find_installed_route(prefix, plen, src_prefix, src_plen);

    if(!babel_check(route == routes[1])) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on find_installed_route\n");
        fprintf(stderr, "prefix: %s\n", format_prefix(prefix, plen));
        fprintf(stderr, "src_prefix: %s\n", format_prefix(src_prefix, src_plen));
        fprintf(stderr, "expected route: routes[1].\n");
    }

    uninstall_route(route);

    route = find_installed_route(prefix, plen, src_prefix, src_plen);
    if(!babel_check(route == NULL)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on find_installed_route (after uninstall_route)\n");
        fprintf(stderr, "prefix: %s\n", format_prefix(prefix, plen));
        fprintf(stderr, "src_prefix: %s\n", format_prefix(src_prefix, src_plen));
        fprintf(stderr, "expected NULL.\n");
    }
}

void installed_routes_estimate_test(void)
{
    struct route_stream *stream = route_stream(1);
    struct babel_route *r;
    int installed_routes = 0, estimate = installed_routes_estimate();

    while(1) {
        r = route_stream_next(stream);
        if(r == NULL)
            break;
        else
            installed_routes++;
    }

    if(!babel_check(installed_routes <= estimate)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on installed_routes_estimate.\n");
        fprintf(stderr, "Expected that the estimated number would be greater or equal to the number of actually installed routes.\n");
        fprintf(stderr, "Installed routes: %d\nEstimate: %d\n", installed_routes, estimate);
    }
}

void insert_route_test(void)
{
    int i, num_of_cases, test_ok;
    struct babel_route *route, *returned_route, *r;

    typedef struct test_case {
        unsigned char *prefix_val;
        unsigned char plen_val;
        unsigned char *src_prefix_val;
        unsigned char src_plen_val;
        int expected_pos;
    } test_case;

    test_case tcs[] =
    {
        {
            .prefix_val = (unsigned char[])
                { 88, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
            .plen_val = 101,
            .src_prefix_val = (unsigned char[])
                { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
            .src_plen_val = 115,
            .expected_pos = 2
        },
        {
            .prefix_val = (unsigned char[])
                { 68, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
            .plen_val = 101,
            .src_prefix_val = (unsigned char[])
                { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
            .src_plen_val = 115,
            .expected_pos = 0
        },
        {
            .prefix_val = (unsigned char[])
                { 78, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
            .plen_val = 101,
            .src_prefix_val = (unsigned char[])
                { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
            .src_plen_val = 115,
            .expected_pos = 2
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    struct babel_route *added_routes[num_of_cases];

    for(i = 0; i < num_of_cases; ++i) {
        route = malloc(sizeof(struct babel_route));
        route->installed = 0;
        route->src = malloc(sizeof(struct source));
        route->src->plen = tcs[i].plen_val;
        memcpy(route->src->prefix, tcs[i].prefix_val, 16);
        route->src->src_plen = tcs[i].src_plen_val;
        route->src->route_count = 1;
        memcpy(route->src->src_prefix, tcs[i].src_prefix_val, 16);

        returned_route = insert_route(route);

        r = routes[tcs[i].expected_pos];
        while(r->next)
            r = r->next;

        test_ok = returned_route != NULL;
        test_ok &= r == route;
        if(!babel_check(test_ok)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test (%d) on insert_route\n", i);
            fprintf(stderr, "routes[%d] is not equal to the route being inserted.\n", tcs[i].expected_pos);
        }
        added_routes[i] = r;
    }
    for(i = 0; i < num_of_cases; i++)
        flush_route(added_routes[i]);
}

void flush_route_test(void) {
    int i, j, num_of_cases, test_ok, prev_slots, prev_length, curr_length;
    struct babel_route *r, *to_insert;

    // Insert some routes before running the test, so we can test slots with size > 1.
    unsigned char p1[] = { 78, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 };
    unsigned char src_p1[] = { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 };
    to_insert = malloc(sizeof(struct babel_route));
    to_insert->installed = 0;
    to_insert->src = malloc(sizeof(struct source));
    to_insert->src->plen = 101;
    memcpy(to_insert->src->prefix, p1, 16);
    to_insert->src->src_plen = 115;
    memcpy(to_insert->src->src_prefix, src_p1, 16);
    to_insert->src->route_count = 1;
    insert_route(to_insert);

    // Select one of the routes stored in the global variable `routes` to be flushed in the test.
    typedef struct test_case {
        int slot; // slot where the route is located
        int pos; // position inside that slot of the route
        short last_route_in_slot;
    } test_case;

    test_case tcs[] =
    {
        {
            .slot = 1,
            .pos = 1,
            .last_route_in_slot = 0
        },
        {
            .slot = 0,
            .pos = 0,
            .last_route_in_slot = 1
        }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; ++i) {
        r = routes[tcs[i].slot];
        for(j = 0; j < tcs[i].pos; j++)
            r = r->next;

        prev_slots = route_slots;
        prev_length = route_list_length(routes[tcs[i].slot]);

        flush_route(r);

        curr_length = route_list_length(routes[tcs[i].slot]);
        if(tcs[i].last_route_in_slot)
            test_ok = route_slots == prev_slots - 1;
        else
            test_ok = curr_length == prev_length - 1;

        if(!babel_check(test_ok)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test (%d) on flush_route.\n", i);
            fprintf(stderr, "Trying to flush %d-th route from %d-th slot:\n", tcs[i].pos, tcs[i].slot);
            if(!tcs[i].last_route_in_slot && curr_length != prev_length - 1)
                fprintf(stderr, "Route list length was not updated. Previous: %d; Current: %d.\n", prev_length, curr_length);
            if(tcs[i].last_route_in_slot && route_slots != prev_slots - 1)
                fprintf(stderr, "Number of route slots was not updated. Previous: %d; Current: %d.\n", prev_slots, route_slots);
        }
    }
}

void flush_all_routes_test()
{
    flush_all_routes();
    if(!babel_check(route_slots == 0)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on flush_all_routes.\n");
        fprintf(stderr, "Expected route_slots = 0, got %d.\n", route_slots);
    }
}

void flush_neighbour_route_test(void)
{
    int prev_route_slots = route_slots;
    flush_neighbour_routes(ns[1]);
    if(!babel_check(prev_route_slots == route_slots + 1)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on flush_neighbour_route_test.\n");
        fprintf(stderr, "Expected route_slots = %d, got %d.\n", prev_route_slots - 1, route_slots);
    }
}

void route_stream_test(void) {
    struct route_stream *stream;
    int which;
    for(which = 0; which <= 1; which++) {
        stream = route_stream(which);
        if(!babel_check(stream != NULL)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test: route_stream(%d) was NULL.", which);
        }
    }
}

void route_stream_next_test(void) {
    int i, j, num_of_cases;
    struct route_stream *stream;
    struct babel_route *route = NULL;

    typedef struct test_case {
        int installed_val;
        int number_of_calls;
        int expected_route_index;
    } test_case;

    test_case tcs[] = {
        {
            .installed_val = 0,
            .number_of_calls = 2,
            .expected_route_index = 1,
        },
        {
            .installed_val = 1,
            .number_of_calls = 1,
            .expected_route_index = 0,
        }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);

    for(i = 0; i < num_of_cases; ++i) {
        stream = route_stream(tcs[i].installed_val);
        j = tcs[i].number_of_calls;
        while(j) {
            route = route_stream_next(stream);
            j--;
        }

        if(!babel_check(routes[tcs[i].expected_route_index] == route)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test (%d) on route_stream_next.\n", i);
            fprintf(stderr, "Expected routes[%d] after %d iteration(s) (", tcs[i].expected_route_index, tcs[i].number_of_calls);
            if(tcs[i].installed_val)
                fprintf(stderr, "only installed routes).\n");
            else
                fprintf(stderr, "all routes).\n");
        }
    }
}

void metric_to_kernel_test(void) {
    int m;
    m = metric_to_kernel(2 * INFINITY);
    if(!babel_check(m == KERNEL_INFINITY)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test: metric_to_kernel(2 * INFINITY) = %d, expected %d\n", m, KERNEL_INFINITY);
    }
    m = metric_to_kernel(INFINITY - 1);
    if(!babel_check(m == kernel_metric)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test: metric_to_kernel(INFINITY - 1) = %d, expected %d\n", m, kernel_metric);
    }
    reflect_kernel_metric = 1;
    m = metric_to_kernel(KERNEL_INFINITY - 1);
    if(!babel_check(m == KERNEL_INFINITY - 1)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test: metric_to_kernel(KERNEL_INFINITY - 1) = %d, expected %d.\n", m, KERNEL_INFINITY - 1);
    }
    kernel_metric = 2;
    m = metric_to_kernel(KERNEL_INFINITY - 1);
    if(!babel_check(m == KERNEL_INFINITY)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test: metric_to_kernel(KERNEL_INFINITY - 1) = %d, expected %d.\n", m, KERNEL_INFINITY);
    }
}

void update_feasible_test(void)
{
    int i, num_of_cases, rc;
    struct source src;

    gettime(&now);

    rc = update_feasible(NULL, 0, 0);
    if(!babel_check(rc == 1)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on update_feasible.\n");
        fprintf(stderr, "update_feasible(NULL, 0, 0) = %d, expected 1.\n", rc);
    }

    typedef struct test_case {
        time_t src_time_val;
        unsigned short src_seqno_val;
        unsigned short src_metric_val;
        unsigned short seqno_val;
        unsigned short refmetric_val;
        int expected_rc;
    } test_case;

    test_case tcs[] =
    {
        {
            .src_time_val = now.tv_sec - SOURCE_GC_TIME - 10,
            .src_seqno_val = 0,
            .src_metric_val = 0,
            .seqno_val = 0,
            .refmetric_val = 0,
            .expected_rc = 1,
        },
        {
            .src_time_val = now.tv_sec,
            .src_seqno_val = 0,
            .src_metric_val = 0,
            .seqno_val = 0,
            .refmetric_val = INFINITY,
            .expected_rc = 1
        },
        {
            .src_time_val = now.tv_sec,
            .src_seqno_val = 0,
            .src_metric_val = 0,
            .seqno_val = 0x8000,
            .refmetric_val = 0,
            .expected_rc = 1
        },
        {
            .src_time_val = now.tv_sec,
            .src_seqno_val = 0x8000,
            .src_metric_val = 50,
            .seqno_val = 0x8000,
            .refmetric_val = 10,
            .expected_rc = 1
        },
        {
            .src_time_val = now.tv_sec,
            .src_seqno_val = 0x8000,
            .src_metric_val = 10,
            .seqno_val = 0x8000,
            .refmetric_val = 50,
            .expected_rc = 0
        },
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    for(i = 0; i < num_of_cases; ++i) {
        src.time = tcs[i].src_time_val;
        src.seqno = tcs[i].src_seqno_val;
        src.metric = tcs[i].src_metric_val;

        rc = update_feasible(&src, tcs[i].seqno_val, tcs[i].refmetric_val);
        if(!babel_check(rc == tcs[i].expected_rc)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test on update_feasible.\n");
            fprintf(stderr, "src->time = %jd\n", src.time);
            fprintf(stderr, "src->seqno = %d\n", src.seqno);
            fprintf(stderr, "src->metric = %d\n", src.metric);
            fprintf(stderr, "seqno = %d\n", tcs[i].seqno_val);
            fprintf(stderr, "refmetric = %d\n", tcs[i].refmetric_val);
            fprintf(stderr, "expected rc: %d\n", tcs[i].expected_rc);
            fprintf(stderr, "computed rc: %d\n", rc);
        }
    }
}

void change_smoothing_half_life_test(void)
{
    int half_life;
    int expected_values[] = {0, 131072, 92682, 82570, 77935, 74621};

    change_smoothing_half_life(-1);
    if(!babel_check(two_to_the_one_over_hl == 0 && smoothing_half_life == 0)) {
        fprintf(stderr, "-----------------------------------------------\n");
        fprintf(stderr, "Failed test on change_smoothing_half_life.\n");
        fprintf(stderr, "change_smoothing_half_life(-1) resulted in:\n");
        fprintf(stderr, "two_to_the_one_over_hl = %d and smoothing_half_life = %d.\n",
                        two_to_the_one_over_hl, smoothing_half_life);
        fprintf(stderr, "Expected two_to_the_one_over_hl = 0 and smoothing_half_life = 0.\n");
    }
    for(half_life = 0; half_life <= 5; half_life++) {
        change_smoothing_half_life(half_life);
        if(!babel_check(smoothing_half_life == half_life && two_to_the_one_over_hl == expected_values[half_life])) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test on change_smoothing_half_life.\n");
            fprintf(stderr, "change_smoothing_half_life(%d) resulted in:\n", half_life);
            fprintf(stderr, "two_to_the_one_over_hl = %d and smoothing_half_life = %d.\n",
                            two_to_the_one_over_hl, smoothing_half_life);
            fprintf(stderr, "Expected two_to_the_one_over_hl = %d and smoothing_half_life = %d.\n",
                             expected_values[half_life], half_life);
        }
    }
}

void change_route_metric_test(void)
{
    int i, num_of_cases, test_ok;
    struct babel_route *route;

    typedef struct test_case {
        int index_of_route_to_change;
        unsigned refmetric_val;
        unsigned cost_val;
        unsigned add_val;
    } test_case;

    test_case tcs[] =
    {
        {
            .index_of_route_to_change = 1,
            .refmetric_val = 10,
            .cost_val = 20,
            .add_val = 30
        }
    };

    num_of_cases = sizeof(tcs) / sizeof(test_case);
    for(i = 0; i < num_of_cases; ++i) {
        route = routes[tcs[i].index_of_route_to_change];

        change_route_metric(route, tcs[i].refmetric_val, tcs[i].cost_val, tcs[i].add_val);

        test_ok = route->refmetric == tcs[i].refmetric_val;
        test_ok &= route->cost == tcs[i].cost_val;
        test_ok &= route->add_metric == tcs[i].add_val;
        if(!babel_check(test_ok)) {
            fprintf(stderr, "-----------------------------------------------\n");
            fprintf(stderr, "Failed test on change_route_metric\n");
            fprintf(stderr, "Route used: routes[%d]\n", tcs[i].index_of_route_to_change);
            fprintf(stderr, "Call was: change_route_metric(routes[%d], %u, %u, %u)\n",
                            tcs[i].index_of_route_to_change,
                            tcs[i].refmetric_val,
                            tcs[i].cost_val,
                            tcs[i].add_val);
            fprintf(stderr, "Expected route->refmetric = %u, "
                            "route->cost = %u, "
                            "route->add_metric = %u.\n",
                            tcs[i].refmetric_val, tcs[i].cost_val, tcs[i].add_val);
            fprintf(stderr, "Got: route->refmetric = %u, "
                            "route->cost = %u, "
                            "route->add_metric = %u.\n",
                            route->refmetric, route->cost, route->add_metric);
        }
    }
}

void route_setup(void) {
    int i;
    struct interface *ifp = add_interface("test_if", NULL);
    unsigned char next_hops[][16] =
      {
        { 116, 183, 7, 94, 183, 40, 143, 20, 251, 193, 125, 15, 37, 226, 212, 149 },
        { 221, 72, 210, 3, 227, 190, 71, 159, 76, 55, 112, 69, 199, 37, 117, 59 },
        { 220, 124, 153, 147, 164, 40, 167, 160, 234, 37, 175, 15, 7, 131, 164, 228 },
        { 204, 118, 231, 175, 52, 46, 78, 128, 102, 190, 197, 45, 227, 59, 104, 191 },
        { 183, 2, 83, 92, 42, 250, 252, 20, 31, 171, 35, 38, 47, 200, 11, 251 },
        { 62, 242, 170, 115, 33, 249, 243, 135, 183, 185, 180, 155, 244, 28, 90, 171 },
      };
    unsigned char neigh_addresses[][16] =
      {
        { 11, 192, 14, 226, 201, 183, 167, 80, 75, 132, 129, 96, 129, 53, 20, 225 },
        { 166, 108, 155, 153, 212, 135, 74, 110, 123, 32, 24, 125, 212, 248, 2, 223 },
        { 184, 16, 193, 129, 199, 104, 209, 18, 236, 82, 114, 110, 135, 135, 79, 45 },
        { 243, 235, 198, 200, 114, 17, 54, 237, 49, 78, 107, 5, 70, 109, 228, 255 },
        { 125, 165, 128, 69, 13, 82, 87, 250, 164, 202, 104, 44, 81, 183, 89, 68 },
        { 162, 32, 12, 21, 49, 67, 2, 98, 145, 109, 103, 216, 218, 75, 215, 88 },
      };
    unsigned char prefixes[][16] =
      {
        { 69, 198, 228, 78, 253, 128, 30, 115, 115, 189, 34, 209, 203, 126, 38, 62 },
        { 78, 162, 240, 49, 189, 24, 46, 203, 201, 107, 41, 160, 213, 182, 197, 23 },
        { 93, 135, 206, 145, 214, 232, 94, 9, 247, 22, 71, 251, 157, 3, 77, 167 },
        { 118, 204, 77, 156, 52, 93, 35, 51, 137, 29, 164, 158, 179, 101, 255, 252 },
        { 160, 175, 139, 76, 149, 129, 138, 109, 209, 43, 127, 92, 8, 202, 53, 182 },
        { 227, 216, 75, 160, 38, 254, 131, 189, 88, 42, 56, 139, 244, 255, 11, 82 },
      };
    int plens[] = {77, 101, 105, 12, 40, 25};
    unsigned char src_prefixes[][16] =
      {
        { 24, 27, 163, 100, 57, 21, 220, 196, 63, 155, 246, 218, 80, 49, 160, 174 },
        { 26, 137, 255, 238, 199, 6, 224, 128, 87, 142, 8, 197, 49, 142, 106, 113 },
        { 107, 103, 113, 193, 138, 153, 175, 32, 159, 28, 70, 247, 160, 25, 204, 190 },
        { 153, 214, 219, 41, 222, 82, 207, 131, 155, 79, 202, 239, 25, 208, 233, 179 },
        { 157, 105, 76, 111, 96, 98, 35, 253, 235, 49, 69, 120, 108, 140, 34, 198 },
        { 173, 76, 71, 184, 21, 200, 70, 185, 15, 19, 223, 62, 165, 179, 210, 92 },
      };
    int src_plens[] = {100, 115, 96, 50, 37, 81};

    // Install artificial filter
    struct filter *filter = calloc(1, sizeof(struct filter));
    filter->plen_le = 128;
    filter->src_plen_le = 128;
    add_filter(filter, FILTER_TYPE_INSTALL);

    for(i = 0; i < N_ROUTES; i++) {
        const unsigned char id[] = {i};
        struct neighbour *n = find_neighbour(neigh_addresses[i], ifp);
        update_route(id, prefixes[i], plens[i], src_prefixes[i], src_plens[i], 0, 10, 0, n, next_hops[i]);
        ns[i] = n;
    }
}

void route_tear_down(void) {
    flush_all_routes();
}

void run_route_test(void (*test)(void), char *test_name) {
    route_setup();
    run_test(test, test_name);
    route_tear_down();
}

void route_test_suite(void)
{
    run_test(route_compare_test, "route_compare_test");
    run_route_test(find_route_slot_test, "find_route_slot_test");
    run_route_test(find_route_test, "find_route_test");
    run_route_test(find_installed_route_test, "find_installed_route_test");
    run_route_test(installed_routes_estimate_test, "installed_routes_estimate_test");
    run_route_test(insert_route_test, "insert_route_test");
    run_route_test(flush_route_test, "flush_route_test");
    run_route_test(flush_all_routes_test, "flush_all_routes_test");
    run_route_test(flush_neighbour_route_test, "flush_neighbour_route_test");
    run_test(route_stream_test, "route_stream_test");
    run_route_test(route_stream_next_test, "route_stream_next_test");
    run_test(metric_to_kernel_test, "metric_to_kernel_test");
    run_test(update_feasible_test, "update_feasible_test");
    run_test(change_smoothing_half_life_test, "change_smoothing_half_life_test");
    run_route_test(change_route_metric_test, "change_route_metric_test");
}
