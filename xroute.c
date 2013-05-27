/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

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
#include <sys/time.h>
#include <netinet/in.h>

#include "babeld.h"
#include "kernel.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "xroute.h"
#include "util.h"
#include "configuration.h"
#include "interface.h"
#include "local.h"

static struct xroute *xroutes;
static int numxroutes = 0, maxxroutes = 0;

struct xroute *
find_xroute(const unsigned char *prefix, unsigned char plen,
            const unsigned char *src_prefix, unsigned char src_plen)
{
    int i;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].plen == plen &&
           memcmp(xroutes[i].prefix, prefix, 16) == 0 &&
           xroutes[i].src_plen == src_plen &&
           memcmp(xroutes[i].src_prefix, src_prefix, 16) == 0)
            return &xroutes[i];
    }
    return NULL;
}

struct xroute *
find_next_xroute(const unsigned char *prefix, unsigned char plen, int *next)
{
    int i = 0;
    if(*next >= 0)
        i = *next;
    for(; i < numxroutes; i++) {
        if(xroutes[i].plen == plen &&
           memcmp(xroutes[i].prefix, prefix, 16) == 0) {
            *next = i + 1;
            return &xroutes[i];
        }
    }
    return NULL;
}

void
flush_xroute(struct xroute *xroute)
{
    int i;

    i = xroute - xroutes;
    assert(i >= 0 && i < numxroutes);

    local_notify_xroute(xroute, LOCAL_FLUSH);

    if(i != numxroutes - 1)
        memcpy(xroutes + i, xroutes + numxroutes - 1, sizeof(struct xroute));
    numxroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(xroutes + numxroutes, sizeof(struct xroute));

    if(numxroutes == 0) {
        free(xroutes);
        xroutes = NULL;
        maxxroutes = 0;
    } else if(maxxroutes > 8 && numxroutes < maxxroutes / 4) {
        struct xroute *new_xroutes;
        int n = maxxroutes / 2;
        new_xroutes = realloc(xroutes, n * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return;
        xroutes = new_xroutes;
        maxxroutes = n;
    }
}

int
add_xroute(unsigned char prefix[16], unsigned char plen,
           unsigned char src_prefix[16], unsigned char src_plen,
           unsigned short metric, unsigned int ifindex, int proto)
{
    struct xroute *xroute = find_xroute(prefix, plen, src_prefix, src_plen);
    if(xroute) {
        if(xroute->metric <= metric)
            return 0;
        xroute->metric = metric;
        local_notify_xroute(xroute, LOCAL_CHANGE);
        return 1;
    }

    if(numxroutes >= maxxroutes) {
        struct xroute *new_xroutes;
        int n = maxxroutes < 1 ? 8 : 2 * maxxroutes;
        new_xroutes = xroutes == NULL ?
            malloc(n * sizeof(struct xroute)) :
            realloc(xroutes, n * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return -1;
        maxxroutes = n;
        xroutes = new_xroutes;
    }

    memcpy(xroutes[numxroutes].prefix, prefix, 16);
    xroutes[numxroutes].plen = plen;
    memcpy(xroutes[numxroutes].src_prefix, src_prefix, 16);
    xroutes[numxroutes].src_plen = src_plen;
    xroutes[numxroutes].metric = metric;
    xroutes[numxroutes].ifindex = ifindex;
    xroutes[numxroutes].proto = proto;
    numxroutes++;
    local_notify_xroute(&xroutes[numxroutes - 1], LOCAL_ADD);
    return 1;
}

/* Returns an overestimate of the number of xroutes. */
int
xroutes_estimate()
{
    return numxroutes;
}

void
for_all_xroutes(void (*f)(struct xroute*, void*), void *closure)
{
    int i, n = numxroutes;

    for(i = 0; i < n; i++)
        (*f)(&xroutes[i], closure);
}

int
check_xroutes(int send_updates)
{
    int i, j, metric, export, change = 0, rc;
    struct kernel_route *routes;
    int numroutes;
    static int maxroutes = 8;
    const int maxmaxroutes = 16 * 1024;

    debugf("\nChecking kernel routes.\n");

 again:
    routes = malloc(maxroutes * sizeof(struct kernel_route));
    if(routes == NULL)
        return -1;
    memset(routes, 0, maxroutes * sizeof(struct kernel_route)); /* calloc ? */

    rc = kernel_addresses(NULL, 0, 0, routes, maxroutes);
    if(rc < 0) {
        perror("kernel_addresses");
        numroutes = 0;
    } else {
        numroutes = rc;
    }

    if(numroutes >= maxroutes)
        goto resize;

    rc = kernel_routes(routes + numroutes, maxroutes - numroutes);
    if(rc < 0)
        fprintf(stderr, "Couldn't get kernel routes.\n");
    else
        numroutes += rc;

    if(numroutes >= maxroutes)
        goto resize;

    /* Cast kernel routes to our prefix. */

    for (i = 0; i < numroutes;) {
        const unsigned char *ss_prefix;
        unsigned char ss_plen;
        if (v4mapped(routes[i].prefix)) {
            ss_prefix = source_specific_addr;
            ss_plen   = source_specific_plen;
        } else {
            ss_prefix = source_specific_addr6;
            ss_plen   = source_specific_plen6;
        }
        switch (prefixes_cmp(routes[i].src_prefix, routes[i].src_plen,
                             ss_prefix, ss_plen)) {
            case PST_DISJOINT:
                if (i < numroutes - 1)
                    memcpy(&routes[i], &routes[numroutes-1],
                           sizeof(struct kernel_route));
                numroutes--; /* no i ++ */
                break;
            case PST_LESS_SPECIFIC:
                memcpy(routes[i].src_prefix, ss_prefix, 16);
                routes[i].src_plen = ss_plen;
                /* fall through */;
            case PST_EQUALS:
            case PST_MORE_SPECIFIC:
                i ++;
                break;
        }
    }

    /* Check for any routes that need to be flushed */

    i = 0;
    while(i < numxroutes) {
        export = 0;
        metric = redistribute_filter(xroutes[i].prefix, xroutes[i].plen,
                                     xroutes[i].src_prefix, xroutes[i].src_plen,
                                     xroutes[i].ifindex, xroutes[i].proto);
        if(metric < INFINITY && metric == xroutes[i].metric) {
            for(j = 0; j < numroutes; j++) {
                if(xroutes[i].plen == routes[j].plen &&
                   memcmp(xroutes[i].prefix, routes[j].prefix, 16) == 0 &&
                   xroutes[i].ifindex == routes[j].ifindex &&
                   xroutes[i].proto == routes[j].proto) {
                    export = 1;
                    break;
                }
            }
        }

        if(!export) {
            unsigned char prefix[16], plen;
            unsigned char src_prefix[16], src_plen;
            struct babel_route *route;
            memcpy(prefix, xroutes[i].prefix, 16);
            plen = xroutes[i].plen;
            memcpy(src_prefix, xroutes[i].src_prefix, 16);
            src_plen = xroutes[i].src_plen;
/* XXX : source-routing ? */
            flush_xroute(&xroutes[i]);
            route = find_best_route(prefix, plen, src_prefix, src_plen, 1,NULL);
            if(route)
                install_route(route);
            /* send_update_resend only records the prefix, so the update
               will only be sent after we perform all of the changes. */
            if(send_updates)
                send_update_resend(NULL, prefix, plen, src_prefix, src_plen);
            change = 1;
        } else {
            i++;
        }
    }

    /* Add any new routes */

    for(i = 0; i < numroutes; i++) {
        if(martian_prefix(routes[i].prefix, routes[i].plen))
            continue;
        metric = redistribute_filter(routes[i].prefix, routes[i].plen,
                                     routes[i].src_prefix, routes[i].src_plen,
                                     routes[i].ifindex, routes[i].proto);
        if(metric < INFINITY) {
            rc = add_xroute(routes[i].prefix, routes[i].plen,
                            routes[i].src_prefix, routes[i].src_plen,
                            metric, routes[i].ifindex, routes[i].proto);
            if(rc > 0) {
                struct babel_route *route;
                route = find_installed_route(routes[i].prefix, routes[i].plen,
                                             routes[i].src_prefix,
                                             routes[i].src_plen);
                if(route) {
                    if(allow_duplicates < 0 ||
                       routes[i].metric < allow_duplicates)
                        uninstall_route(route);
                }
                change = 1;
                if(send_updates)
                    send_update(NULL, 0, routes[i].prefix, routes[i].plen,
                                routes[i].src_prefix, routes[i].src_plen);
            }
        }
    }

    free(routes);
    /* Set up maxroutes for the next call. */
    maxroutes = MIN(numroutes + 8, maxmaxroutes);
    return change;

 resize:
    free(routes);
    if(maxroutes >= maxmaxroutes)
        return -1;
    maxroutes = MIN(maxmaxroutes, 2 * maxroutes);
    goto again;
}
