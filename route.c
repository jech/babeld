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
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "babel.h"
#include "util.h"
#include "kernel.h"
#include "destination.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"

struct route routes[MAXROUTES];
int numroutes = 0;
int kernel_metric = 0;
int route_timeout_delay = 50;
int route_gc_delay = 95;

struct route *
find_route(const unsigned char *dest, struct neighbour *nexthop)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].nexthop == nexthop &&
           memcmp(routes[i].dest->address, dest, 16) == 0)
            return &routes[i];
    }
    return NULL;
}

struct route *
find_installed_route(struct destination *dest)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].installed && routes[i].dest == dest)
            return &routes[i];
    }
    return NULL;
}

void
flush_route(struct route *route)
{
    int n;
    struct destination *dest;
    int install = 0, oldmetric;

    n = route - routes;
    assert(n >= 0 && n < numroutes);

    oldmetric = route->metric;

    if(route->installed) {
        uninstall_route(route);
        install = 1;
    }

    dest = route->dest;

    if(n != numroutes - 1)
        memcpy(routes + n, routes + numroutes - 1, sizeof(struct route));
    numroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(routes + numroutes, sizeof(struct route));

    if(install) {
        struct route *new_route;
        new_route = find_best_route(dest);
        if(new_route) {
            install_route(new_route);
            send_triggered_update(new_route, oldmetric);
        } else {
            if(dest->metric < INFINITY) {
                dest->metric = INFINITY;
                dest->seqno = (dest->seqno + 1) & 0xFF;
            }
            send_update(route->dest, NULL);
        }
        if(!new_route || new_route->metric >= INFINITY)
            send_request(NULL, route->dest, max_hopcount, -1);
    }
}

void
flush_neighbour_routes(struct neighbour *neigh)
{
    int i;

    i = 0;
    while(i < numroutes) {
        if(routes[i].nexthop == neigh) {
            flush_route(routes + i);
            continue;
        }
        i++;
    }
}

unsigned int
metric_to_kernel(int metric)
{
    assert(metric >= 0);

    if(metric >= INFINITY)
        return KERNEL_INFINITY;
    else
        return MIN((metric + 255) / 256 + kernel_metric, KERNEL_INFINITY);
}

void
install_route(struct route *route)
{
    struct route *installed;
    int i, rc;

    if(route->installed)
        return;

    installed = find_installed_route(route->dest);
    if(installed)
        uninstall_route(installed);

    rc = kernel_route(ROUTE_ADD, route->dest->address, 128,
                      route->nexthop->address,
                      route->nexthop->network->ifindex,
                      metric_to_kernel(route->metric), 0);
    if(rc < 0) {
        perror("kernel_route(ADD)");
        if(errno != EEXIST)
            return;
    }
    route->installed = 1;

    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].gateway == route->dest &&
           xroutes[i].time >= now.tv_sec - 240) {
            update_xroute_metric(&xroutes[i], xroutes[i].cost);
            consider_xroute(&xroutes[i]);
        }
    }
}

void
uninstall_route(struct route *route)
{
    int i, rc;
    if(!route->installed)
        return;

    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].installed && xroutes[i].gateway == route->dest)
            uninstall_xroute(&xroutes[i]);
    }

    rc = kernel_route(ROUTE_FLUSH, route->dest->address, 128,
                      route->nexthop->address,
                      route->nexthop->network->ifindex,
                      metric_to_kernel(route->metric), 0);
    if(rc < 0)
        perror("kernel_route(FLUSH)");
    route->installed = 0;
}

int
route_feasible(struct route *route)
{
    if(route->dest->time < now.tv_sec - 200) {
        /* Never mind what is probably stale data */
        return 1;
    }

    return update_feasible(route->seqno, route->refmetric, route->dest);
}

int
update_feasible(unsigned char seqno, unsigned short refmetric,
                struct destination *dest)
{
    return (seqno_compare(dest->seqno, seqno) < 0 ||
            (dest->seqno == seqno && refmetric < dest->metric));
}

struct route *
find_best_route(struct destination *dest)
{
    struct route *route = NULL;
    int i;

    for(i = 0; i < numroutes; i++) {
        if(routes[i].dest != dest)
            continue;
        if(routes[i].time < now.tv_sec - route_timeout_delay)
            continue;
        if(!route_feasible(&routes[i]))
            continue;
        if(route && route->metric < INFINITY &&
           route->metric + 512 >= routes[i].metric) {
            if(route->origtime <= now.tv_sec - 30 &&
               routes[i].origtime >= now.tv_sec - 30)
                continue;
            if(route->metric < routes[i].metric)
                continue;
            if(route->origtime > routes[i].origtime)
                continue;
        }
        route = &routes[i];
    }
    return route;
}

void
update_neighbour_metric(struct neighbour *neigh)
{
    int i;

    i = 0;
    while(i < numroutes) {
        if(routes[i].nexthop == neigh)
            update_route_metric(&routes[i]);
        i++;
    }
}

void
update_route_metric(struct route *route)
{
    int oldmetric;
    int newmetric;

    oldmetric = route->metric;
    if(route->time < now.tv_sec - route_timeout_delay) {
        newmetric = INFINITY;
        route->refmetric = INFINITY;
        if(oldmetric < INFINITY)
            route->seqno = (route->dest->seqno + 1) & 0xFF;
    } else {
        newmetric = MIN(route->refmetric + neighbour_cost(route->nexthop),
                        INFINITY);
    }

    change_route_metric(route, newmetric);

    if(route->installed) {
        if(newmetric > oldmetric) {
            struct route *better_route;
            better_route = find_best_route(route->dest);
            if(better_route && better_route->metric <= route->metric - 96)
                consider_route(better_route);
            else
                send_triggered_update(route, oldmetric);
        } else {
            send_triggered_update(route, oldmetric);
        }
    } else if(newmetric < oldmetric) {
        consider_route(route);
    }
}

struct route *
update_route(const unsigned char *d, int seqno, int refmetric,
             struct neighbour *nexthop,
             struct xroute *pxroutes, int numpxroutes)
{
    struct route *route;
    struct destination *dest;
    int i, metric;

    if(d[0] == 0xFF || d[0] == 0) {
        fprintf(stderr, "Ignoring martian route.\n");
        return NULL;
    }

    dest = find_destination(d, 1, seqno);
    if(dest == NULL)
        return NULL;

    metric = MIN(refmetric + neighbour_cost(nexthop), INFINITY);

    route = find_route(d, nexthop);

    if(!update_feasible(seqno, refmetric, dest)) {
        debugf("Rejecting unfeasible update from %s.\n",
               format_address(nexthop->address));
        return NULL;
    }

    if(route) {
        int oldseqno;
        int oldmetric;

        oldseqno = route->seqno;
        oldmetric = route->metric;
        route->time = now.tv_sec;
        if(route->refmetric >= INFINITY)
            route->origtime = now.tv_sec;
        route->seqno = seqno;
        route->refmetric = refmetric;
        change_route_metric(route, metric);
        if(seqno_compare(oldseqno, seqno) <= 0) {
            if(seqno_compare(oldseqno, seqno) < 0)
                retract_xroutes(dest, pxroutes, numpxroutes);
            for(i = 0; i < numpxroutes; i++)
                update_xroute(pxroutes[i].prefix,
                              pxroutes[i].plen,
                              dest,
                              pxroutes[i].cost);
        }
        if(route->installed)
            send_triggered_update(route, oldmetric);
        else
            consider_route(route);
    } else {
        if(refmetric >= INFINITY)
            /* Somebody's retracting a route we never saw. */
            return NULL;
        if(numroutes >= MAXROUTES) {
            fprintf(stderr, "Too many routes -- ignoring update.\n");
            return NULL;
        }
        route = &routes[numroutes];
        route->dest = dest;
        route->refmetric = refmetric;
        route->seqno = seqno;
        route->metric = metric;
        route->nexthop = nexthop;
        route->time = now.tv_sec;
        route->origtime = now.tv_sec;
        route->installed = 0;
        numroutes++;
        for(i = 0; i < numpxroutes; i++)
            update_xroute(pxroutes[i].prefix,
                          pxroutes[i].plen,
                          dest,
                          pxroutes[i].cost);
        consider_route(route);
    }
    return route;
}

void
consider_route(struct route *route)
{
    struct route *installed;

    if(route->installed)
        return;

    if(!route_feasible(route))
        return;

    installed = find_installed_route(route->dest);

    if(installed == NULL)
        goto install;

    if(installed->metric >= route->metric + 384)
        goto install;

    if(route->origtime >= now.tv_sec - 30)
        return;

    if(installed->metric >= route->metric + 96)
        goto install;

    return;

 install:
    install_route(route);
    if(installed)
        send_triggered_update(route, installed->metric);
    else
        send_update(route->dest, NULL);
    return;
}

void
change_route_metric(struct route *route, int newmetric)
{
    int rc;
    if(route->installed) {
        rc = kernel_route(ROUTE_MODIFY,
                          route->dest->address, 128,
                          route->nexthop->address,
                          route->nexthop->network->ifindex,
                          metric_to_kernel(route->metric),
                          metric_to_kernel(newmetric));
        if(rc < 0) {
            perror("kernel_route(MODIFY)");
            return;
        }
    }
    route->metric = newmetric;
}

void
send_triggered_update(struct route *route, int oldmetric)
{
    if(!route->installed)
        return;

    if((route->metric >= INFINITY && oldmetric < INFINITY) ||
       (route->metric - oldmetric >= 256 || oldmetric - route->metric >= 256))
        send_update(route->dest, NULL);

    if(route->metric - oldmetric >= 384) {
        /* This route's metric has increased a lot -- let's hope we find
           something better */
        send_request(NULL, route->dest, 1, -1);
    }
}
