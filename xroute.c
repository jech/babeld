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
#include "interface.h"
#include "neighbour.h"
#include "message.h"
#include "source.h"
#include "route.h"
#include "xroute.h"
#include "util.h"
#include "configuration.h"
#include "local.h"

static struct xroute *xroutes;
static int numxroutes = 0, maxxroutes = 0;

static int
xroute_compare(const unsigned char *prefix, unsigned char plen,
               const unsigned char *src_prefix, unsigned char src_plen,
               const struct xroute *xroute)
{
    int rc;

    if(plen < xroute->plen)
        return -1;
    if(plen > xroute->plen)
        return 1;

    rc = memcmp(prefix, xroute->prefix, 16);
    if(rc != 0)
        return rc;

    if(src_plen < xroute->src_plen)
        return -1;
    if(src_plen > xroute->src_plen)
        return 1;

    rc = memcmp(src_prefix, xroute->src_prefix, 16);
    if(rc != 0)
        return rc;

    return 0;
}

static int
find_xroute_slot(const unsigned char *prefix, unsigned char plen,
                 const unsigned char *src_prefix, unsigned char src_plen,
                 int *new_return)
{
    int p, m, g, c;

    if(numxroutes < 1) {
        if(new_return)
            *new_return = 0;
        return -1;
    }

    p = 0; g = numxroutes - 1;

    do {
        m = (p + g) / 2;
        c = xroute_compare(prefix, plen, src_prefix, src_plen, &xroutes[m]);
        if(c == 0)
            return m;
        else if(c < 0)
            g = m - 1;
        else
            p = m + 1;
    } while(p <= g);

    if(new_return)
        *new_return = p;

    return -1;
}


struct xroute *
find_xroute(const unsigned char *prefix, unsigned char plen,
            const unsigned char *src_prefix, unsigned char src_plen)
{
    int i = find_xroute_slot(prefix, plen, src_prefix, src_plen, NULL);
    if(i >= 0)
        return &xroutes[i];

    return NULL;
}

int
add_xroute(unsigned char prefix[16], unsigned char plen,
           unsigned char src_prefix[16], unsigned char src_plen,
           unsigned short metric, unsigned int ifindex, int proto)
{
    int n = -1;
    int i = find_xroute_slot(prefix, plen, src_prefix, src_plen, &n);

    if(i >= 0)
        return -1;

    if(numxroutes >= maxxroutes) {
        struct xroute *new_xroutes;
        int num = maxxroutes < 1 ? 8 : 2 * maxxroutes;
        new_xroutes = realloc(xroutes, num * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return -1;
        maxxroutes = num;
        xroutes = new_xroutes;
    }

    if(n < numxroutes)
        memmove(xroutes + n + 1, xroutes + n,
                (numxroutes - n) * sizeof(struct xroute));
    numxroutes++;

    memcpy(xroutes[n].prefix, prefix, 16);
    xroutes[n].plen = plen;
    memcpy(xroutes[n].src_prefix, src_prefix, 16);
    xroutes[n].src_plen = src_plen;
    xroutes[n].metric = metric;
    xroutes[n].ifindex = ifindex;
    xroutes[n].proto = proto;
    local_notify_xroute(&xroutes[n], LOCAL_ADD);
    return 1;
}

void
flush_xroute(struct xroute *xroute, int send_updates)
{
    int i;
    unsigned char prefix[16], plen;
    unsigned char src_prefix[16], src_plen;
    struct babel_route *route;

    /* We'll use these after we free the xroute */
    memcpy(prefix, xroute->prefix, 16);
    plen = xroutes->plen;
    memcpy(src_prefix, xroutes->src_prefix, 16);
    src_plen = xroute->src_plen;

    i = xroute - xroutes;
    assert(i >= 0 && i < numxroutes);

    local_notify_xroute(xroute, LOCAL_FLUSH);

    if(i != numxroutes - 1)
        memmove(xroutes + i, xroutes + i + 1,
                (numxroutes - i - 1) * sizeof(struct xroute));
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

    route = find_best_route(prefix, plen, src_prefix, src_plen, 1, NULL);
    if(route != NULL && route_metric(route) < INFINITY &&
       route_feasible(route)) {
        install_route(route);
        if(send_updates)
            send_update(NULL, 0, prefix, plen, src_prefix, src_plen);
    } else {
        if(send_updates)
            send_update_resend(NULL, prefix, plen, src_prefix, src_plen);
    }
}

/* Returns an overestimate of the number of xroutes. */
int
xroutes_estimate()
{
    return numxroutes;
}

struct xroute_stream {
    int index;
};

struct
xroute_stream *
xroute_stream()
{
    struct xroute_stream *stream = calloc(1, sizeof(struct xroute_stream));
    if(stream == NULL)
        return NULL;

    return stream;
}


struct xroute *
xroute_stream_next(struct xroute_stream *stream)
{
    if(stream->index < numxroutes)
        return &xroutes[stream->index++];
    else
        return NULL;
}

void
xroute_stream_done(struct xroute_stream *stream)
{
    free(stream);
}

static void
filter_route(int add, struct kernel_route *route, void *data) {
    void **args = (void**)data;
    int maxroutes = *(int*)args[0];
    struct kernel_route *routes = (struct kernel_route *)args[1];
    int *found = (int*)args[2];

    if(*found >= maxroutes)
        return;

    if(martian_prefix(route->prefix, route->plen) ||
       martian_prefix(route->src_prefix, route->src_plen))
        return;

    routes[*found] = *route;
    ++ *found;
}

static int
kernel_routes(struct kernel_route *routes, int maxroutes)
{
    int found = 0;
    void *data[3] = { &maxroutes, routes, &found };
    struct kernel_filter filter = {0};
    filter.route = filter_route;
    filter.route_closure = data;

    kernel_dump(CHANGE_ROUTE, &filter);

    return found;
}

static void
filter_address(int add, struct kernel_addr *addr, void *data)
{
    void **args = (void **)data;
    int maxroutes = *(int *)args[0];
    struct kernel_route *routes = (struct kernel_route*)args[1];
    int *found = (int *)args[2];
    int ifindex = *(int*)args[3];
    int ll = args[4] ? !!*(int*)args[4] : 0;
    struct kernel_route *route = NULL;

    if(*found >= maxroutes)
        return;

    if(ll == !IN6_IS_ADDR_LINKLOCAL(&addr->addr))
        return;

    /* ifindex may be 0 -- see kernel_addresses */
    if(ifindex && addr->ifindex != ifindex)
        return;

    route = &routes[*found];
    memset(route, 0, sizeof(struct kernel_route));
    memcpy(route->prefix, addr->addr.s6_addr, 16);
    route->plen = 128;
    if(v4mapped(route->prefix)) {
        memcpy(route->src_prefix, v4prefix, 16);
        route->src_plen = 96;
    }
    route->metric = 0;
    route->ifindex = addr->ifindex;
    route->proto = RTPROT_BABEL_LOCAL;
    memset(route->gw, 0, 16);
    ++ *found;
}

/* ifindex is 0 for all interfaces.  ll indicates whether we are
   interested in link-local or global addresses. */
int
kernel_addresses(int ifindex, int ll, struct kernel_route *routes,
                 int maxroutes)
{
    int found = 0;
    void *data[5] = { &maxroutes, routes, &found, &ifindex, &ll };
    struct kernel_filter filter = {0};
    filter.addr = filter_address;
    filter.addr_closure = data;

    kernel_dump(CHANGE_ADDR, &filter);

    return found;
}

/* This must coincide with the ordering defined by xroute_compare above. */
static int
kernel_route_compare(const void *v1, const void *v2)
{
    const struct kernel_route *route1 = (struct kernel_route*)v1;
    const struct kernel_route *route2 = (struct kernel_route*)v2;
    int rc;

    if(route1->plen < route2->plen)
        return -1;
    if(route1->plen > route2->plen)
        return 1;

    rc = memcmp(route1->prefix, route2->prefix, 16);
    if(rc != 0)
        return rc;

    if(route1->src_plen < route2->src_plen)
        return -1;
    if(route1->src_plen > route2->src_plen)
        return 1;

    rc = memcmp(route1->src_prefix, route2->src_prefix, 16);
    if(rc != 0)
        return rc;

    return 0;
}

static void
modify_xroute(int i, struct kernel_route *kroute, int update) {
    if(xroutes[i].metric != kroute->metric ||
       xroutes[i].proto != kroute->proto) {
        xroutes[i].metric = kroute->metric;
        xroutes[i].proto = kroute->proto;
        local_notify_xroute(&xroutes[i], LOCAL_CHANGE);
        if(update)
            send_update(NULL, 0, xroutes[i].prefix, xroutes[i].plen,
                        xroutes[i].src_prefix, xroutes[i].src_plen);
    }
}

static void
flush_duplicate_route(struct kernel_route *kroute) {
    struct babel_route *route;
    route = find_installed_route(kroute->prefix, kroute->plen,
                                 kroute->src_prefix, kroute->src_plen);
    if(route) {
        if(allow_duplicates < 0 || kroute->metric < allow_duplicates)
            uninstall_route(route);
    }
}


void
kernel_route_notify(int add, struct kernel_route *kroute, void *closure)
{
    struct filter_result filter_result;
    int i, rc;

    debugf("Kernel route: %s %s",
           add ? "add" : "del", format_prefix(kroute->prefix, kroute->plen));

    kroute->metric = redistribute_filter(kroute->prefix, kroute->plen,
                                         kroute->src_prefix, kroute->src_plen,
                                         kroute->ifindex, kroute->proto,
                                         &filter_result);

    if(filter_result.src_prefix != NULL) {
        memcpy(kroute->src_prefix, filter_result.src_prefix, 16);
        kroute->src_plen = filter_result.src_plen;
    }

    if(kroute->metric >= INFINITY)
        return;

    i = find_xroute_slot(kroute->prefix, kroute->plen,
                         kroute->src_prefix, kroute->src_plen, NULL);
    if(!add) {
        if(i >= 0)
            flush_xroute(&xroutes[i], 1);
        else
            debugf("Flushing unknown route.\n");
        return;
    }

    if(i >= 0) {
        modify_xroute(i, kroute, 1);
        return;
    }

    if(martian_prefix(kroute->prefix, kroute->plen))
        return;

    rc = add_xroute(kroute->prefix, kroute->plen,
                    kroute->src_prefix, kroute->src_plen,
                    kroute->metric, kroute->ifindex,
                    kroute->proto);
    if(rc > 0) {
        flush_duplicate_route(kroute);
        send_update(NULL, 0, kroute->prefix, kroute->plen,
                    kroute->src_prefix, kroute->src_plen);
    }

}


int
check_xroutes(int send_updates, int warn, int check_infinity)
{
    int i, j, change = 0, rc;
    struct kernel_route *routes;
    struct filter_result filter_result;
    int numroutes;
    static int maxroutes = 8;
    const int maxmaxroutes = 256 * 1024;

    debugf("\nChecking kernel routes.\n");

 again:
    routes = calloc(maxroutes, sizeof(struct kernel_route));
    if(routes == NULL)
        return -1;

    rc = kernel_addresses(0, 0, routes, maxroutes);
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

    for(i = 0; i < numroutes; i++) {
        routes[i].metric = redistribute_filter(routes[i].prefix, routes[i].plen,
                                               routes[i].src_prefix,
                                               routes[i].src_plen,
                                               routes[i].ifindex,
                                               routes[i].proto,
                                               &filter_result);
        if(filter_result.src_prefix != NULL) {
            memcpy(routes[i].src_prefix, filter_result.src_prefix, 16);
            routes[i].src_plen = filter_result.src_plen;
        }
        debugf("Route %s metric %d\n",
                format_prefix(routes[i].prefix, routes[i].plen), routes[i].metric);
    }

    qsort(routes, numroutes, sizeof(struct kernel_route), kernel_route_compare);
    i = 0;
    j = 0;
    while(i < numroutes || j < numxroutes) {
        /* Ignore routes filtered out. */
        if(!check_infinity && i < numroutes && routes[i].metric >= INFINITY) {
            i++;
            continue;
        }

        if(i >= numroutes)
            rc = +1;
        else if(j >= numxroutes)
            rc = -1;
        else
            rc = xroute_compare(routes[i].prefix, routes[i].plen,
                                routes[i].src_prefix, routes[i].src_plen,
                                &xroutes[j]);
        if(rc < 0) {
            /* Add route i. */
            if(!martian_prefix(routes[i].prefix, routes[i].plen) &&
               routes[i].metric < INFINITY) {
                if(warn)
                    fprintf(stderr,
                            "Adding missing route to %s "
                            "(this shouldn't happen)\n",
                            format_prefix(routes[i].prefix, routes[i].plen));
                rc = add_xroute(routes[i].prefix, routes[i].plen,
                                routes[i].src_prefix, routes[i].src_plen,
                                routes[i].metric, routes[i].ifindex,
                                routes[i].proto);
                if(rc > 0) {
                    flush_duplicate_route(&routes[i]);
                    if(send_updates)
                        send_update(NULL, 0, routes[i].prefix, routes[i].plen,
                                    routes[i].src_prefix, routes[i].src_plen);
                    j++;
                }
            }
            i++;
        } else if(rc > 0) {
            /* Flush xroute j. */
            if(warn)
                fprintf(stderr,
                        "Flushing spurious route to %s "
                        "(this shouldn't happen)\n",
                        format_prefix(xroutes[j].prefix, xroutes[j].plen));
            flush_xroute(&xroutes[j], send_updates);
        } else {
            modify_xroute(j, &routes[i], send_updates);
            i++;
            j++;
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
