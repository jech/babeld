/*
Copyright (c) 2014 by Matthieu Boutier and Juliusz Chroboczek.

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
#include <sys/time.h>

#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "kernel.h"
#include "route.h"
#include "source.h"
#include "neighbour.h"

struct zone {
    const unsigned char *dst_prefix;
    unsigned char dst_plen;
    const unsigned char *src_prefix;
    unsigned char src_plen;
    int rc;
};

/* Given (d,s), search min { (d1,s1) | s == s1 && d < d1 }. */
static struct babel_route *
get_lowest_dst(const struct zone *zone)
{
    return find_min_iroute(zone->dst_prefix, zone->dst_plen,
                           zone->src_prefix, zone->src_plen,
                           0, 1);
}

/* return true if the zone (d,s) is a conflict, i.e. if there exists (d1,s1) and
   (d2,s2) such that d1 == d, s < s1, d < d2 and s == s2.
   ATTENTION : it doen't return 0 if(d,s) exists ! */
static int
has_conflict(const struct zone *conflict_zone)
{
    struct babel_route *rt;

    /* find (d1, s1) such that d == d1 and s < s1. */
    rt = find_min_iroute(conflict_zone->dst_prefix, conflict_zone->dst_plen,
                         conflict_zone->src_prefix, conflict_zone->src_plen,
                         1, 1);
    if(rt == NULL)
        return 0;

    assert(prefix_cmp(conflict_zone->dst_prefix, conflict_zone->dst_plen,
                      rt->src->prefix, rt->src->plen)
           == PST_EQUALS);
    assert(prefix_cmp(conflict_zone->src_prefix, conflict_zone->src_plen,
                      rt->src->src_prefix, rt->src->src_plen)
           == PST_MORE_SPECIFIC);

    /* find (d1, s1) such that d < d1 and s == s1. */
    rt = find_min_iroute(conflict_zone->dst_prefix, conflict_zone->dst_plen,
                         conflict_zone->src_prefix, conflict_zone->src_plen,
                         0, 1);
    if(rt == NULL)
        return 0;

    assert(prefix_cmp(conflict_zone->dst_prefix, conflict_zone->dst_plen,
                      rt->src->prefix, rt->src->plen)
           == PST_MORE_SPECIFIC);
    assert(prefix_cmp(conflict_zone->src_prefix, conflict_zone->src_plen,
                      rt->src->src_prefix, rt->src->src_plen)
           == PST_EQUALS);

    return 1; /* both exists: conflict */
}

/* Given (d,s), return min { (d1,s1) | d == d1 && s <= s1 }, i.e. the route
   which should be use for packets in (d,s). */
static struct babel_route *
search_conflict_solution(const struct zone *conflict_zone)
{
    return find_min_iroute(conflict_zone->dst_prefix, conflict_zone->dst_plen,
                           conflict_zone->src_prefix, conflict_zone->src_plen,
                           1, 0);
}

static int
add_non_conflicting_route(const struct babel_route *route,
                          const struct zone *zone, int v4)
{
    int rc;
    if((has_ipv6_subtrees && !v4) || !has_conflict(zone)) {
        rc = kernel_route(ROUTE_ADD, zone->dst_prefix, zone->dst_plen,
                          zone->src_prefix, zone->src_plen,
                          route->nexthop,
                          route->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(route)), NULL, 0, 0);
    } else {
        struct babel_route *old = search_conflict_solution(zone);
        assert(old != NULL);
        rc = kernel_route(ROUTE_MODIFY, zone->dst_prefix, zone->dst_plen,
                          zone->src_prefix, zone->src_plen,
                          old->nexthop, old->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(old)),
                          route->nexthop, route->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(route)));
    }
    return rc;
}

static int
install_conflicting_routes(const struct babel_route *route_to_add,
                           const struct babel_route *installed_route)
{
    struct zone cz;
    struct source *rt = route_to_add->src, *rt1 = installed_route->src;
    const struct babel_route *solution = NULL;
    enum prefix_status dst_st, src_st;

    if(v4mapped(rt->prefix) != v4mapped(rt1->prefix))
        return 0;
    dst_st = prefix_cmp(rt->prefix, rt->plen, rt1->prefix, rt1->plen);
    if(dst_st & (PST_DISJOINT | PST_EQUALS))
        return 0;
    src_st = prefix_cmp(rt->src_prefix, rt->src_plen,
                        rt1->src_prefix, rt1->src_plen);
    if(!((dst_st == PST_LESS_SPECIFIC && src_st == PST_MORE_SPECIFIC) ||
         (dst_st == PST_MORE_SPECIFIC && src_st == PST_LESS_SPECIFIC)))
        return 0;

    /* routes are in conflict */
    debugf("    conflicts with %s from %s\n",
           format_prefix(rt1->prefix, rt1->plen),
           format_prefix(rt1->src_prefix, rt1->src_plen));

    if(src_st == PST_MORE_SPECIFIC) {
        cz.dst_prefix = rt1->prefix;
        cz.dst_plen = rt1->plen;
        cz.src_prefix = rt->src_prefix;
        cz.src_plen = rt->src_plen;
        if(has_conflict(&cz))
            return 0; /* conflict should be already solved */
        debugf("    the conflit is not already solved\n");
        solution = search_conflict_solution(&cz);
        assert(solution != NULL);
        if(solution != installed_route)
            return 0;
        debugf("    solution come from %s from %s\n",
               format_prefix(solution->src->prefix, solution->src->plen),
               format_prefix(solution->src->src_prefix,
                             solution->src->src_plen));
    } else {
        assert(src_st == PST_LESS_SPECIFIC);
        cz.dst_prefix = rt->prefix;
        cz.dst_plen = rt->plen;
        cz.src_prefix = rt1->src_prefix;
        cz.src_plen = rt1->src_plen;
        /* avoid adding this entry multiple times : */
        struct babel_route *lowest_dst = get_lowest_dst(&cz);
        assert(lowest_dst != NULL);
        if(installed_route != lowest_dst)
            return 0;
        solution = search_conflict_solution(&cz);
        if(solution != NULL) {
            debugf("    an existing solution is %s from %s\n",
                   format_prefix(solution->src->prefix, solution->src->plen),
                   format_prefix(solution->src->src_prefix,
                                 solution->src->src_plen));
            src_st = prefix_cmp(rt->src_prefix, rt->src_plen,
                                solution->src->src_prefix,
                                solution->src->src_plen);
            if(src_st != PST_MORE_SPECIFIC)
                return 0;
        }
        solution = route_to_add;
        debugf("    solution is our route\n");
    }
    return add_non_conflicting_route(solution, &cz, v4mapped(rt->prefix));
}

int
kinstall_route(const struct babel_route *route)
{
    int rc;
    struct zone zone;
    struct babel_route *rt1 = NULL;
    struct route_stream *stream = NULL;
    int v4 = v4mapped(route->nexthop);

    debugf("install_route(%s from %s)\n",
           format_prefix(route->src->prefix, route->src->plen),
           format_prefix(route->src->src_prefix, route->src->src_plen));
    /* Install source-specific conflicting routes */
    if(!has_ipv6_subtrees || v4) {
        stream = route_stream(1);
        if(!stream) {
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return -1;
        }
        /* Install source-specific conflicting routes */
        while(1) {
            rt1 = route_stream_next(stream);
            if(rt1 == NULL) break;
            rc = install_conflicting_routes(route, rt1);
            if(rc < 0) {
                int save = errno;
                perror("kernel_route(ADD sub)");
                if(save != EEXIST) {
                    route_stream_done(stream);
                    return -1;
                }
            }
        }
        route_stream_done(stream);
    }

    /* Non conflicting case */
    zone.dst_prefix = route->src->prefix;
    zone.dst_plen   = route->src->plen;
    zone.src_prefix = route->src->src_prefix;
    zone.src_plen   = route->src->src_plen;
    rc = add_non_conflicting_route(route, &zone, v4);
    if(rc < 0) {
        int save = errno;
        perror("kernel_route(ADD)");
        if(save != EEXIST)
            return -1;
    }
    return 0;
}

static int
del_non_conflicting_route(const struct babel_route *route,
                          const struct zone *zone, int v4)
{
    int rc;
    if((has_ipv6_subtrees && !v4) || !has_conflict(zone)) {
        rc = kernel_route(ROUTE_FLUSH, zone->dst_prefix, zone->dst_plen,
                          zone->src_prefix, zone->src_plen,
                          route->nexthop,
                          route->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(route)), NULL, 0, 0);
    } else {
        struct babel_route *new = search_conflict_solution(zone);
        assert(new != NULL);
        rc = kernel_route(ROUTE_MODIFY, zone->dst_prefix, zone->dst_plen,
                          zone->src_prefix, zone->src_plen,
                          route->nexthop, route->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(route)),
                          new->nexthop, new->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(new)));
    }
    return rc;
}

static int
uninstall_conflicting_routes(const struct babel_route *route_to_del,
                             const struct babel_route *installed_route)
{
    struct source *rt = route_to_del->src, *rt1 = installed_route->src;
    struct babel_route *solution = NULL;
    struct zone cz;
    enum prefix_status dst_st, src_st;
    int rc = 0;

    if(v4mapped(rt->prefix) != v4mapped(rt1->prefix))
        return 0;
    dst_st = prefix_cmp(rt->prefix, rt->plen, rt1->prefix, rt1->plen);
    if(dst_st & (PST_DISJOINT | PST_EQUALS))
        return 0;
    src_st = prefix_cmp(rt->src_prefix, rt->src_plen,
                        rt1->src_prefix, rt1->src_plen);
    if(dst_st == PST_LESS_SPECIFIC && src_st == PST_MORE_SPECIFIC) {
        cz.dst_prefix = rt1->prefix;
        cz.dst_plen = rt1->plen;
        cz.src_prefix = rt->src_prefix;
        cz.src_plen = rt->src_plen;
        cz.rc = 0;
    } else if(dst_st == PST_MORE_SPECIFIC && src_st == PST_LESS_SPECIFIC) {
        cz.dst_prefix = rt->prefix;
        cz.dst_plen = rt->plen;
        cz.src_prefix = rt1->src_prefix;
        cz.src_plen = rt1->src_plen;
        cz.rc = 0;
    } else {
        return 0;
    }

    /* routes are in conflict */
    debugf("    conflicts with %s from %s\n",
           format_prefix(rt1->prefix, rt1->plen),
           format_prefix(rt1->src_prefix, rt1->src_plen));

    if(src_st == PST_MORE_SPECIFIC) {
        if(has_conflict(&cz))
            return 0;
        /* remove the old solution */
        solution = search_conflict_solution(&cz);
        assert(solution != NULL);
        src_st = prefix_cmp(cz.src_prefix, cz.src_plen,
                            solution->src->src_prefix,
                            solution->src->src_plen);
        if(src_st == PST_EQUALS)
            return 0; /* don't flush an installed RIB route */
        src_st = prefix_cmp(rt1->src_prefix, rt1->src_plen,
                            solution->src->src_prefix,
                            solution->src->src_plen);
        if(src_st != PST_EQUALS)
            return 0; /* avoid flushing this entry multiple times */
        debugf("    flush the now useless solution coming from %s from %s\n",
               format_prefix(solution->src->prefix, solution->src->plen),
               format_prefix(solution->src->src_prefix,
                             solution->src->src_plen));
        rc = kernel_route(ROUTE_FLUSH, cz.dst_prefix, cz.dst_plen,
                          cz.src_prefix, cz.src_plen,
                          solution->nexthop,
                          solution->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(solution)),
                          NULL, 0, 0);
        if(rc < 0)
            debugf("    the flush has failed.\n");
    } else {
        /* avoid flushing this entry multiple times : */
        struct babel_route *lowest_dst = get_lowest_dst(&cz);
        assert(lowest_dst != NULL);
        if(installed_route != lowest_dst)
            return 0;
        solution = search_conflict_solution(&cz);
        if(!solution) { /* => no more conflict */
            debugf("    no more conflict: solution come from the flushed route"
                   " (flush the entry)\n");
            rc = kernel_route(ROUTE_FLUSH, cz.dst_prefix, cz.dst_plen,
                              cz.src_prefix, cz.src_plen,
                              route_to_del->nexthop,
                              route_to_del->neigh->ifp->ifindex,
                              metric_to_kernel(route_metric(route_to_del)),
                              NULL, 0, 0);
            if(rc < 0)
                debugf("    the flush has failed.\n");
        } else {
            src_st = prefix_cmp(rt->src_prefix, rt->src_plen,
                                solution->src->src_prefix,
                                solution->src->src_plen);
            if(src_st != PST_MORE_SPECIFIC)
                return 0; /* solution is already installed */
            debugf("    switch to solution coming from %s from %s\n",
                   format_prefix(rt1->prefix, rt1->plen),
                   format_prefix(rt1->src_prefix, rt1->src_plen));
            rc = kernel_route(ROUTE_MODIFY, cz.dst_prefix, cz.dst_plen,
                              cz.src_prefix, cz.src_plen,
                              installed_route->nexthop,
                              installed_route->neigh->ifp->ifindex,
                              metric_to_kernel(route_metric(installed_route)),
                              solution->nexthop, solution->neigh->ifp->ifindex,
                              metric_to_kernel(route_metric(solution)));
            if(rc < 0)
                debugf("    the switch has failed.\n");
        }
    }
    return rc;
}

int
kuninstall_route(const struct babel_route *route)
{
    int rc;
    struct zone zone;
    struct babel_route *rt1;
    struct route_stream *stream = NULL;
    int v4 = v4mapped(route->nexthop);

    debugf("uninstall_route(%s from %s)\n",
           format_prefix(route->src->prefix, route->src->plen),
           format_prefix(route->src->src_prefix, route->src->src_plen));
    /* Remove the route, or change if the route was solving a conflict. */
    zone.dst_prefix = route->src->prefix;
    zone.dst_plen   = route->src->plen;
    zone.src_prefix = route->src->src_prefix;
    zone.src_plen   = route->src->src_plen;
    rc = del_non_conflicting_route(route, &zone, v4);
    if(rc < 0)
        perror("kernel_route(FLUSH)");

    /* Remove source-specific conflicting routes */
    if(!has_ipv6_subtrees || v4) {
        stream = route_stream(1);
        if(!stream) {
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return -1;
        }
        while(1) {
            rt1 = route_stream_next(stream);
            if(rt1 == NULL) break;
            rc = uninstall_conflicting_routes(route, rt1);
            if(rc < 0)
                perror("kernel_route(FLUSH sub)");
        }
        route_stream_done(stream);
    }

    return rc;
}

static int
switch_conflicting_routes(const struct babel_route *old,
                          const struct babel_route *new,
                          int new_metric,
                          const struct babel_route *installed_route)
{
    struct source *rt = old->src, *rt1 = installed_route->src;
    enum prefix_status dst_st, src_st;
    int rc = 0;

    if(v4mapped(rt->prefix) != v4mapped(rt1->prefix))
        return 0;
    dst_st = prefix_cmp(rt->prefix, rt->plen, rt1->prefix, rt1->plen);
    if(dst_st & (PST_DISJOINT | PST_EQUALS))
        return 0;
    src_st = prefix_cmp(rt->src_prefix, rt->src_plen,
                        rt1->src_prefix, rt1->src_plen);
    if(!((dst_st == PST_LESS_SPECIFIC && src_st == PST_MORE_SPECIFIC) ||
         (dst_st == PST_MORE_SPECIFIC && src_st == PST_LESS_SPECIFIC)))
        return 0;

    /* routes are in conflict */
    debugf("    conflicts with %s from %s\n",
           format_prefix(rt1->prefix, rt1->plen),
           format_prefix(rt1->src_prefix, rt1->src_plen));

    if(src_st == PST_LESS_SPECIFIC) {
        struct zone cz = {
            .dst_prefix = rt->prefix,
            .dst_plen = rt->plen,
            .src_prefix = rt1->src_prefix,
            .src_plen = rt1->src_plen,
            .rc = 0
        };
        struct babel_route *solution = search_conflict_solution(&cz);
        assert(solution);
        if(solution != old)
            return 0;
        debugf("    switch.\n");
        rc = kernel_route(ROUTE_MODIFY, rt->prefix, rt->plen,
                          rt1->src_prefix, rt1->src_plen,
                          old->nexthop, old->neigh->ifp->ifindex,
                          metric_to_kernel(route_metric(old)),
                          new->nexthop, new->neigh->ifp->ifindex,
                          new_metric);
    }
    return rc;
}

/* This is equivalent to uninstall_route followed with install_route,
   but without the race condition.  The destination of both routes
   must be the same. */

int
kswitch_routes(const struct babel_route *old, const struct babel_route *new)
{
    int rc, new_metric = metric_to_kernel(route_metric(new));
    struct babel_route *rt1 = NULL;
    struct route_stream *stream = NULL;

    debugf("switch_routes(%s from %s)\n",
           format_prefix(old->src->prefix, old->src->plen),
           format_prefix(old->src->src_prefix, old->src->src_plen));
    rc = kernel_route(ROUTE_MODIFY, old->src->prefix, old->src->plen,
                      old->src->src_prefix, old->src->src_plen,
                      old->nexthop, old->neigh->ifp->ifindex,
                      metric_to_kernel(route_metric(old)),
                      new->nexthop, new->neigh->ifp->ifindex,
                      new_metric);
    if(rc < 0) {
        perror("kernel_route(MODIFY)");
        return -1;
    }

    new_metric = metric_to_kernel(route_metric(new));

    /* Remove source-specific conflicting routes */
    if(!has_ipv6_subtrees || v4mapped(old->nexthop)) {
        stream = route_stream(1);
        if(!stream) {
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return -1;
        }
        while(1) {
            rt1 = route_stream_next(stream);
            if(rt1 == NULL) break;
            rc = switch_conflicting_routes(old, new, new_metric, rt1);
            if(rc < 0)
                perror("kernel_route(MODIFY sub)");
        }
        route_stream_done(stream);
    }

    return rc;
}

int
kchange_route_metric(const struct babel_route *route,
                     unsigned refmetric, unsigned cost, unsigned add)
{
    int old_metric = metric_to_kernel(route_metric(route));
    int new_metric = metric_to_kernel(MIN(refmetric + cost + add, INFINITY));
    int rc;
    struct babel_route *rt1 = NULL;
    struct route_stream *stream = NULL;

    debugf("change_route_metric(%s from %s, %d -> %d)\n",
           format_prefix(route->src->prefix, route->src->plen),
           format_prefix(route->src->src_prefix, route->src->src_plen),
           old_metric, new_metric);
    rc = kernel_route(ROUTE_MODIFY, route->src->prefix, route->src->plen,
                      route->src->src_prefix, route->src->src_plen,
                      route->nexthop, route->neigh->ifp->ifindex,
                      old_metric,
                      route->nexthop, route->neigh->ifp->ifindex,
                      new_metric);
    if(rc < 0) {
        perror("kernel_route(MODIFY metric)");
        return -1;
    }

    if(!has_ipv6_subtrees || v4mapped(route->nexthop)) {
        stream = route_stream(1);
        if(!stream) {
            fprintf(stderr, "Couldn't allocate route stream.\n");
            return -1;
        }

        while(1) {
            rt1 = route_stream_next(stream);
            if(rt1 == NULL) break;
            rc = switch_conflicting_routes(route, route, new_metric, rt1);
            if(rc < 0)
                perror("kernel_route(MODIFY metric sub)");
        }
        route_stream_done(stream);
    }

    return rc;
}
