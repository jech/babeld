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
#include "route.h"
#include "xroute.h"

struct xroute xroutes[MAXXROUTES];
int numxroutes = 0;

struct xroute myxroutes[MAXMYXROUTES];
int nummyxroutes = 0;

static struct xroute *
find_installed_xroute(unsigned char *prefix, unsigned short plen)
{
    int i;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].installed &&
           xroutes[i].plen == plen &&
           memcmp(xroutes[i].prefix, prefix, 16) == 0) {
            return &xroutes[i];
        }
    }
    return NULL;
}

static struct xroute *
find_installed_myxroute(unsigned char *prefix, unsigned short plen)
{
    int i;
    for(i = 0; i < nummyxroutes; i++) {
        if(myxroutes[i].installed &&
           myxroutes[i].plen == plen &&
           memcmp(myxroutes[i].prefix, prefix, 16) == 0) {
            return &xroutes[i];
        }
    }
    return NULL;
}

static struct xroute *
find_best_xroute(unsigned char *prefix, unsigned short plen)
{
    struct xroute *xroute = NULL;
    int i;

    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].metric >= INFINITY && xroutes[i].cost < INFINITY)
            continue;
        if(xroutes[i].plen != plen ||
           memcmp(xroutes[i].prefix, prefix, 16) != 0)
            continue;
        if((!xroute || xroutes[i].metric < xroute->metric) &&
           find_installed_route(xroutes[i].gateway) != NULL)
            xroute = &xroutes[i];
    }
    return xroute;
}

void
install_xroute(struct xroute *xroute)
{
    struct route *gwroute;
    struct xroute *installed;
    int rc;

    if(xroute->installed)
        return;

    if(xroute->metric >= INFINITY && xroute->cost < INFINITY)
        return;

    if(xroute->plen >= 8 &&
       (xroute->prefix[0] == 0 || xroute->prefix[0] == 0xFF)) {
        fprintf(stderr, "Attempted to install martian xroute.\n");
        return;
    }

    gwroute = find_installed_route(xroute->gateway);
    if(!gwroute) {
        fprintf(stderr,
                "Attempted to install a blackhole xroute "
                "(this shouldn't happen).\n");
        return;
    }

    installed = find_installed_xroute(xroute->prefix, xroute->plen);
    if(installed)
        uninstall_xroute(installed);

    rc = kernel_route(1, xroute->prefix, xroute->plen,
                      gwroute->nexthop->address,
                      gwroute->nexthop->network->ifindex,
                      metric_to_kernel(xroute->metric));
    if(rc < 0) {
        perror("kernel_route(1)");
        if(errno != EEXIST)
            return;
    }
    xroute->installed = 1;
}

void
uninstall_xroute(struct xroute *xroute)
{
    struct route *gwroute;
    int rc;

    if(!xroute->installed)
        return;

    gwroute = find_installed_route(xroute->gateway);
    if(!gwroute) {
        fprintf(stderr,
                "Attempted to uninstall a blackhole xroute "
                "(this shouldn't happen).\n");
        return;
    }

    rc = kernel_route(0, xroute->prefix, xroute->plen,
                      gwroute->nexthop->address,
                      gwroute->nexthop->network->ifindex,
                      metric_to_kernel(xroute->metric));
    if(rc < 0)
        perror("kernel_route(0)");
    xroute->installed = 0;
}

void
consider_xroute(struct xroute *xroute)
{
    struct xroute *installed;

    if(xroute->installed)
        return;

    if(find_installed_route(xroute->gateway) == NULL)
        return;

    installed = find_installed_myxroute(xroute->prefix, xroute->plen);
    if(!installed) {
        installed = find_installed_xroute(xroute->prefix, xroute->plen);
        if(!installed || installed->metric > xroute->metric + 64)
            install_xroute(xroute);
    }
}

void
flush_xroute(struct xroute *xroute)
{
    int n;
    int install = 0;
    unsigned char prefix[16];
    unsigned short plen = 0;

    n = xroute - xroutes;
    assert(n >= 0 && n < numxroutes);

    if(xroute->installed) {
        uninstall_xroute(xroute);
        memcpy(prefix, xroute->prefix, 16);
        plen = xroute->plen;
        install = 1;
    }

    if(n != numxroutes - 1)
        memcpy(xroutes + n, xroutes + numxroutes - 1,
               sizeof(struct xroute));
    numxroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(xroutes + numxroutes, sizeof(struct xroute));

    if(install) {
        struct xroute *xroute;
        xroute = find_best_xroute(prefix, plen);
        if(xroute)
            install_xroute(xroute);
    }
}

void
flush_xroutes(struct destination *gateway,
              const struct xroute *except, int numexcept)
{
    int i, j;

    i = 0;
    while(i < numxroutes) {
        if(xroutes[i].gateway == gateway) {
            for(j = 0; j < numexcept; j++) {
                if(memcmp(xroutes[i].prefix, except[j].prefix, 16) == 0 &&
                   xroutes[i].plen == except[j].plen)
                    goto skip;
            }
            flush_xroute(&xroutes[i]);
            continue;
        }
    skip:
        i++;
    }
}

struct xroute *
update_xroute(const unsigned char *prefix, unsigned short plen,
              struct destination *gateway, int cost)
{
    int i;
    struct xroute *xroute = NULL;
    struct route *gwroute;

    if(prefix[0] == 0xFF || (plen >= 8 && prefix[0] == 0)) {
        fprintf(stderr, "Ignoring martian xroute.\n");
        return NULL;
    }

    if(gateway == NULL) {
        fprintf(stderr, "Ignoring xroute through unknown destination.\n");
        return NULL;
    }

    for(i = 0; i < numxroutes; i++) {
        xroute = &xroutes[i];
        if(xroute->gateway == gateway &&
           memcmp(xroute->prefix, prefix, 16) == 0 && xroute->plen == plen) {
            update_xroute_metric(xroute, cost);
            xroute->time = now.tv_sec;
            return xroute;
        }
    }

    if(numxroutes >= MAXXROUTES) {
        fprintf(stderr, "Too many xroutes.\n");
        return NULL;
    }

    gwroute = find_installed_route(gateway);

    xroute = &xroutes[numxroutes];
    memcpy(&xroute->prefix, prefix, 16);
    xroute->plen = plen;
    xroute->gateway = gateway;
    xroute->cost = cost;
    xroute->metric =
        gwroute ? MIN(gwroute->metric + cost, INFINITY) : INFINITY;
    xroute->time = now.tv_sec;
    xroute->installed = 0;
    numxroutes++;

    if(gwroute)
        consider_xroute(xroute);
    return xroute;
}

void
update_xroute_metric(struct xroute *xroute, int cost)
{
    struct route *gwroute;

    gwroute = find_installed_route(xroute->gateway);
    if(!gwroute)
        return;

    if(xroute->cost != cost || xroute->metric != gwroute->metric + cost) {
        int install = 0;
        if(xroute->installed) {
            uninstall_xroute(xroute);
            install = 1;
        }
        xroute->cost = cost;
        xroute->metric = gwroute->metric + cost;
        if(install) {
            struct xroute *best;
            best = find_best_xroute(xroute->prefix, xroute->plen);
            if(best)
                install_xroute(best);
        }
    }
}
int
check_myxroutes()
{
    int i, j, n, change;
    struct kernel_route routes[120];

    n = -1;
    for(i = 0; i < nummyxroutes; i++)
        if(myxroutes[i].installed < 2)
            n = MAX(n, myxroutes[i].plen);

    if(n < 0)
        return 0;

    n = kernel_routes(n, routes, 120);
    if(n < 0)
        return -1;

    change = 0;
    for(i = 0; i < nummyxroutes; i++) {
        int installed;
        if(myxroutes[i].installed == 2)
            continue;
        installed = 0;
        for(j = 0; j < n; j++) {
            if(routes[j].plen == myxroutes[i].plen &&
               memcmp(routes[j].prefix, myxroutes[i].prefix, 16) == 0) {
                installed = 1;
                break;
            }
        }
        if(myxroutes[i].installed != installed) {
            myxroutes[i].installed = installed;
            change = 1;
        }
    }
    return change;
}
