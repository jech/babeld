/*
Copyright (c) 2007 by Juliusz Chroboczek

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "babel.h"
#include "kernel.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "xroute.h"
#include "util.h"
#include "filter.h"

struct xroute xroutes[MAXXROUTES];
int numxroutes = 0;

struct xroute *
find_xroute(const unsigned char *prefix, unsigned char plen)
{
    int i;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].plen == plen &&
           memcmp(xroutes[i].prefix, prefix, 16) == 0)
            return &xroutes[i];
    }
    return NULL;
}

void
flush_xroute(struct xroute *xroute)
{
    int n;

    n = xroute - xroutes;
    assert(n >= 0 && n < numxroutes);

    if(n != numxroutes - 1)
        memcpy(xroutes + n, xroutes + numxroutes - 1, sizeof(struct xroute));
    numxroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(xroutes + numxroutes, sizeof(struct xroute));
}

int
add_xroute(unsigned char prefix[16], unsigned char plen,
           unsigned short metric, unsigned int ifindex, int proto)
{
    struct xroute *xroute = find_xroute(prefix, plen);
    if(xroute) {
        if(xroute->metric <= metric)
            return 0;
        if(xroute->forced)
            return 0;
        xroute->metric = metric;
        return 1;
    }

    if(numxroutes >= MAXXROUTES)
        return -1;

    memcpy(xroutes[numxroutes].prefix, prefix, 16);
    xroutes[numxroutes].plen = plen;
    xroutes[numxroutes].forced = 0;
    xroutes[numxroutes].metric = metric;
    xroutes[numxroutes].ifindex = ifindex;
    xroutes[numxroutes].proto = proto;
    numxroutes++;
    return 1;
}

int
check_xroutes()
{
    int i, j, n, metric, export, change = 0, rc;
    struct kernel_route routes[240];

    debugf("\nChecking kernel routes.\n");

    n = kernel_routes(routes, 240);
    if(n < 0)
        return -1;

    i = 0;
    while(i < numxroutes) {
        if(xroutes[i].forced) {
            i++;
            continue;
        }
        export = 0;
        metric = redistribute_filter(xroutes[i].prefix, xroutes[i].plen,
                                     xroutes[i].ifindex, xroutes[i].proto);
        if((metric < INFINITY && metric == xroutes[i].metric) ||
           metric == METRIC_INHERIT) {
            for(j = 0; j < n; j++) {
                if(xroutes[i].plen == routes[j].plen &&
                   memcmp(xroutes[i].prefix, routes[j].prefix, 16) == 0 &&
                   xroutes[i].ifindex == routes[j].ifindex &&
                   xroutes[i].proto == routes[j].proto) {
                    if(metric < INFINITY ||
                       (metric == METRIC_INHERIT &&
                        xroutes[i].metric == routes[j].metric)) {
                        export = 1;
                        break;
                    }
                }
            }
        }
        if(!export) {
            flush_xroute(&xroutes[i]);
            change = 1;
        } else {
            i++;
        }
    }

    for(i = 0; i < n; i++) {
        metric = redistribute_filter(routes[i].prefix, routes[i].plen,
                                     routes[i].ifindex, routes[i].proto);
        if(metric == METRIC_INHERIT)
            metric = routes[i].metric;
        if(metric < INFINITY) {
            rc = add_xroute(routes[i].prefix, routes[i].plen,
                            metric, routes[i].ifindex, routes[i].proto);
            if(rc)
                change = 1;
        }
    }
    return change;
}
