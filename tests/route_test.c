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
#include <stdlib.h>
#include <time.h>

#include "test_utilities.h"

#include "../babeld.h"
#include "../configuration.h"
#include "../interface.h"
#include "../neighbour.h"
#include "../route.h"

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
        struct babel_route *r = update_route(id, prefixes[i], plens[i], src_prefixes[i], src_plens[i], 0, 10, 0, n, next_hops[i]);
        ns[i] = n;
        install_route(r);
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
}
