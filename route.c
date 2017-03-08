/*
Copyright (c) 2007-2011 by Juliusz Chroboczek

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
#include "kernel.h"
#include "interface.h"
#include "source.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"
#include "resend.h"
#include "configuration.h"
#include "local.h"
#include "disambiguation.h"

struct babel_route **routes = NULL;
static int route_slots = 0, max_route_slots = 0;
int kernel_metric = 0, reflect_kernel_metric = 0;
int allow_duplicates = -1;
int diversity_kind = DIVERSITY_NONE;
int diversity_factor = 256;     /* in units of 1/256 */
int keep_unfeasible = 0;

static int smoothing_half_life = 0;
static int two_to_the_one_over_hl = 0; /* 2^(1/hl) * 0x10000 */

static int
check_specific_first(void)
{
    /* All source-specific routes are in front of the list */
    int specific = 1;
    int i;
    for(i = 0; i < route_slots; i++) {
        if(routes[i]->src->src_plen == 0) {
            specific = 0;
        } else if(!specific) {
            return 0;
        }
    }
    return 1;
}

/* We maintain a list of "slots", ordered by prefix.  Every slot
   contains a linked list of the routes to this prefix, with the
   installed route, if any, at the head of the list. */

static int
route_compare(const unsigned char *prefix, unsigned char plen,
              const unsigned char *src_prefix, unsigned char src_plen,
              struct babel_route *route)
{
    int i;

    /* Put all source-specific routes in the front of the list. */
    if(src_plen == 0 && route->src->src_plen > 0) {
        return 1;
    } else if(src_plen > 0 && route->src->src_plen == 0) {
        return -1;
    }

    i = memcmp(prefix, route->src->prefix, 16);
    if(i != 0)
        return i;

    if(plen < route->src->plen)
        return -1;
    if(plen > route->src->plen)
        return 1;

    if(src_plen == 0) {
        if(route->src->src_plen > 0)
            return -1;
    } else {
        i = memcmp(src_prefix, route->src->src_prefix, 16);
        if(i != 0)
            return i;
        if(src_plen < route->src->src_plen)
            return -1;
        if(src_plen > route->src->src_plen)
            return 1;
    }

    return 0;
}

/* Performs binary search, returns -1 in case of failure.  In the latter
   case, new_return is the place where to insert the new element. */

static int
find_route_slot(const unsigned char *prefix, unsigned char plen,
                const unsigned char *src_prefix, unsigned char src_plen,
                int *new_return)
{
    int p, m, g, c;

    if(route_slots < 1) {
        if(new_return)
            *new_return = 0;
        return -1;
    }

    p = 0; g = route_slots - 1;

    do {
        m = (p + g) / 2;
        c = route_compare(prefix, plen, src_prefix, src_plen, routes[m]);
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

struct babel_route *
find_route(const unsigned char *prefix, unsigned char plen,
           const unsigned char *src_prefix, unsigned char src_plen,
           struct neighbour *neigh, const unsigned char *nexthop)
{
    struct babel_route *route;
    int i = find_route_slot(prefix, plen, src_prefix, src_plen, NULL);

    if(i < 0)
        return NULL;

    route = routes[i];

    while(route) {
        if(route->neigh == neigh && memcmp(route->nexthop, nexthop, 16) == 0)
            return route;
        route = route->next;
    }

    return NULL;
}

struct babel_route *
find_installed_route(const unsigned char *prefix, unsigned char plen,
                     const unsigned char *src_prefix, unsigned char src_plen)
{
    int i = find_route_slot(prefix, plen, src_prefix, src_plen, NULL);

    if(i >= 0 && routes[i]->installed)
        return routes[i];

    return NULL;
}

/* Returns an overestimate of the number of installed routes. */
int
installed_routes_estimate(void)
{
    return route_slots;
}

static int
resize_route_table(int new_slots)
{
    struct babel_route **new_routes;
    assert(new_slots >= route_slots);

    if(new_slots == 0) {
        new_routes = NULL;
        free(routes);
    } else {
        new_routes = realloc(routes, new_slots * sizeof(struct babel_route*));
        if(new_routes == NULL)
            return -1;
    }

    max_route_slots = new_slots;
    routes = new_routes;
    return 1;
}

/* Insert a route into the table.  If successful, retains the route.
   On failure, caller must free the route. */
static struct babel_route *
insert_route(struct babel_route *route)
{
    int i, n;

    assert(!route->installed);

    i = find_route_slot(route->src->prefix, route->src->plen,
                        route->src->src_prefix, route->src->src_plen, &n);

    if(i < 0) {
        if(route_slots >= max_route_slots)
            resize_route_table(max_route_slots < 1 ? 8 : 2 * max_route_slots);
        if(route_slots >= max_route_slots)
            return NULL;
        route->next = NULL;
        if(n < route_slots)
            memmove(routes + n + 1, routes + n,
                    (route_slots - n) * sizeof(struct babel_route*));
        route_slots++;
        routes[n] = route;
    } else {
        struct babel_route *r;
        r = routes[i];
        while(r->next)
            r = r->next;
        r->next = route;
        route->next = NULL;
    }

    return route;
}

static void
destroy_route(struct babel_route *route)
{
    free(route->channels);
    free(route);
}

void
flush_route(struct babel_route *route)
{
    int i;
    struct source *src;
    unsigned oldmetric;
    int lost = 0;

    oldmetric = route_metric(route);
    src = route->src;

    if(route->installed) {
        uninstall_route(route);
        lost = 1;
    }

    i = find_route_slot(route->src->prefix, route->src->plen,
                        route->src->src_prefix, route->src->src_plen, NULL);
    assert(i >= 0 && i < route_slots);

    local_notify_route(route, LOCAL_FLUSH);

    if(route == routes[i]) {
        routes[i] = route->next;
        route->next = NULL;
        destroy_route(route);

        if(routes[i] == NULL) {
            if(i < route_slots - 1)
                memmove(routes + i, routes + i + 1,
                        (route_slots - i - 1) * sizeof(struct babel_route*));
            routes[route_slots - 1] = NULL;
            route_slots--;
            VALGRIND_MAKE_MEM_UNDEFINED(routes + route_slots, sizeof(struct route *));
        }

        if(route_slots == 0)
            resize_route_table(0);
        else if(max_route_slots > 8 && route_slots < max_route_slots / 4)
            resize_route_table(max_route_slots / 2);
    } else {
        struct babel_route *r = routes[i];
        while(r->next != route)
            r = r->next;
        r->next = route->next;
        route->next = NULL;
        destroy_route(route);
    }

    if(lost)
        route_lost(src, oldmetric);

    release_source(src);
}

void
flush_all_routes()
{
    int i;

    /* Start from the end, to avoid shifting the table. */
    i = route_slots - 1;
    while(i >= 0) {
        while(i < route_slots) {
            /* Uninstall first, to avoid calling route_lost. */
            if(routes[i]->installed)
                uninstall_route(routes[i]);
            flush_route(routes[i]);
        }
        i--;
    }

    check_sources_released();
}

void
flush_neighbour_routes(struct neighbour *neigh)
{
    int i;

    i = 0;
    while(i < route_slots) {
        struct babel_route *r;
        r = routes[i];
        while(r) {
            if(r->neigh == neigh) {
                flush_route(r);
                goto again;
            }
            r = r->next;
        }
        i++;
    again:
        ;
    }
}

void
flush_interface_routes(struct interface *ifp, int v4only)
{
    int i;

    i = 0;
    while(i < route_slots) {
        struct babel_route *r;
        r = routes[i];
        while(r) {
            if(r->neigh->ifp == ifp &&
               (!v4only || v4mapped(r->nexthop))) {
                flush_route(r);
                goto again;
            }
            r = r->next;
        }
        i++;
    again:
        ;
    }
}

struct route_stream {
    int installed;
    int index;
    struct babel_route *next;
};


struct route_stream *
route_stream(int which)
{
    struct route_stream *stream;

    if(!check_specific_first())
        fprintf(stderr, "Invariant failed: specific routes first in RIB.\n");

    stream = calloc(1, sizeof(struct route_stream));
    if(stream == NULL)
        return NULL;

    stream->installed = which;
    stream->index = which == ROUTE_ALL ? -1 : 0;
    stream->next = NULL;

    return stream;
}

struct babel_route *
route_stream_next(struct route_stream *stream)
{
    if(stream->installed) {
        while(stream->index < route_slots)
            if(stream->installed == ROUTE_SS_INSTALLED &&
               routes[stream->index]->src->src_plen == 0)
                return NULL;
            else if(routes[stream->index]->installed)
                break;
            else
                stream->index++;

        if(stream->index < route_slots)
            return routes[stream->index++];
        else
            return NULL;
    } else {
        struct babel_route *next;
        if(!stream->next) {
            stream->index++;
            if(stream->index >= route_slots)
                return NULL;
            stream->next = routes[stream->index];
        }
        next = stream->next;
        stream->next = next->next;
        return next;
    }
}

void
route_stream_done(struct route_stream *stream)
{
    free(stream);
}

int
metric_to_kernel(int metric)
{
        if(metric >= INFINITY) {
                return KERNEL_INFINITY;
        } else if(reflect_kernel_metric) {
                int r = kernel_metric + metric;
                return r >= KERNEL_INFINITY ? KERNEL_INFINITY : r;
        } else {
                return kernel_metric;
        }
}

/* This is used to maintain the invariant that the installed route is at
   the head of the list. */
static void
move_installed_route(struct babel_route *route, int i)
{
    assert(i >= 0 && i < route_slots);
    assert(route->installed);

    if(route != routes[i]) {
        struct babel_route *r = routes[i];
        while(r->next != route)
            r = r->next;
        r->next = route->next;
        route->next = routes[i];
        routes[i] = route;
    }
}

void
install_route(struct babel_route *route)
{
    int i, rc;

    if(route->installed)
        return;

    if(!route_feasible(route))
        fprintf(stderr, "WARNING: installing unfeasible route "
                "(this shouldn't happen).");

    i = find_route_slot(route->src->prefix, route->src->plen,
                        route->src->src_prefix, route->src->src_plen, NULL);
    assert(i >= 0 && i < route_slots);

    if(routes[i] != route && routes[i]->installed) {
        fprintf(stderr, "WARNING: attempting to install duplicate route "
                "(this shouldn't happen).");
        return;
    }

    rc = kinstall_route(route);
    if(rc < 0 && errno != EEXIST)
        return;

    route->installed = 1;
    move_installed_route(route, i);

    local_notify_route(route, LOCAL_CHANGE);
}

void
uninstall_route(struct babel_route *route)
{
    if(!route->installed)
        return;

    route->installed = 0;

    kuninstall_route(route);

    local_notify_route(route, LOCAL_CHANGE);
}

/* This is equivalent to uninstall_route followed with install_route,
   but without the race condition.  The destination of both routes
   must be the same. */

static void
switch_routes(struct babel_route *old, struct babel_route *new)
{
    int rc;

    if(!old) {
        install_route(new);
        return;
    }

    if(!old->installed)
        return;

    if(!route_feasible(new))
        fprintf(stderr, "WARNING: switching to unfeasible route "
                "(this shouldn't happen).");

    rc = kswitch_routes(old, new);
    if(rc < 0)
        return;

    old->installed = 0;
    new->installed = 1;
    move_installed_route(new, find_route_slot(new->src->prefix, new->src->plen,
                                              new->src->src_prefix,
                                              new->src->src_plen,
                                              NULL));
    local_notify_route(old, LOCAL_CHANGE);
    local_notify_route(new, LOCAL_CHANGE);
}

static void
change_route_metric(struct babel_route *route,
                    unsigned refmetric, unsigned cost, unsigned add)
{
    int old, new;
    int newmetric = MIN(refmetric + cost + add, INFINITY);

    old = metric_to_kernel(route_metric(route));
    new = metric_to_kernel(newmetric);

    if(route->installed && old != new) {
        int rc;
        rc = kchange_route_metric(route, refmetric, cost, add);
        if(rc < 0)
            return;
    }

    /* Update route->smoothed_metric using the old metric. */
    route_smoothed_metric(route);

    route->refmetric = refmetric;
    route->cost = cost;
    route->add_metric = add;

    if(smoothing_half_life == 0) {
        route->smoothed_metric = route_metric(route);
        route->smoothed_metric_time = now.tv_sec;
    }

    local_notify_route(route, LOCAL_CHANGE);
}

static void
retract_route(struct babel_route *route)
{
    /* We cannot simply remove the route from the kernel, as that might
       cause a routing loop -- see RFC 6126 Sections 2.8 and 3.5.5. */
    change_route_metric(route, INFINITY, INFINITY, 0);
}

int
route_feasible(struct babel_route *route)
{
    return update_feasible(route->src, route->seqno, route->refmetric);
}

int
route_old(struct babel_route *route)
{
    return route->time < now.tv_sec - route->hold_time * 7 / 8;
}

int
route_expired(struct babel_route *route)
{
    return route->time < now.tv_sec - route->hold_time;
}

static int
channels_interfere(int ch1, int ch2)
{
    if(ch1 == IF_CHANNEL_NONINTERFERING || ch2 == IF_CHANNEL_NONINTERFERING)
        return 0;
    if(ch1 == IF_CHANNEL_INTERFERING || ch2 == IF_CHANNEL_INTERFERING)
        return 1;
    return ch1 == ch2;
}

int
route_interferes(struct babel_route *route, struct interface *ifp)
{
    switch(diversity_kind) {
    case DIVERSITY_NONE:
        return 1;
    case DIVERSITY_INTERFACE_1:
        return route->neigh->ifp == ifp;
    case DIVERSITY_CHANNEL_1:
    case DIVERSITY_CHANNEL:
        if(route->neigh->ifp == ifp)
            return 1;
        if(channels_interfere(ifp->channel, route->neigh->ifp->channel))
            return 1;
        if(diversity_kind == DIVERSITY_CHANNEL) {
            int i;
            for(i = 0; i < route->channels_len; i++) {
                if(route->channels[i] != 0 &&
                   channels_interfere(ifp->channel, route->channels[i]))
                    return 1;
            }
        }
        return 0;
    default:
        fprintf(stderr, "Unknown kind of diversity.\n");
        return 1;
    }
}

int
update_feasible(struct source *src,
                unsigned short seqno, unsigned short refmetric)
{
    if(src == NULL)
        return 1;

    if(src->time < now.tv_sec - SOURCE_GC_TIME)
        /* Never mind what is probably stale data */
        return 1;

    if(refmetric >= INFINITY)
        /* Retractions are always feasible */
        return 1;

    return (seqno_compare(seqno, src->seqno) > 0 ||
            (src->seqno == seqno && refmetric < src->metric));
}

void
change_smoothing_half_life(int half_life)
{
    if(half_life <= 0) {
        smoothing_half_life = 0;
        two_to_the_one_over_hl = 0;
        return;
    }

    smoothing_half_life = half_life;
    switch(smoothing_half_life) {
    case 1: two_to_the_one_over_hl = 131072; break;
    case 2: two_to_the_one_over_hl = 92682; break;
    case 3: two_to_the_one_over_hl = 82570; break;
    case 4: two_to_the_one_over_hl = 77935; break;
    default:
        /* 2^(1/x) is 1 + log(2)/x + O(1/x^2) at infinity. */
        two_to_the_one_over_hl = 0x10000 + 45426 / half_life;
    }
}

/* Update the smoothed metric, return the new value. */
int
route_smoothed_metric(struct babel_route *route)
{
    int metric = route_metric(route);

    if(smoothing_half_life <= 0 ||                 /* no smoothing */
       metric >= INFINITY ||                       /* route retracted */
       route->smoothed_metric_time > now.tv_sec || /* clock stepped */
       route->smoothed_metric == metric) {         /* already converged */
        route->smoothed_metric = metric;
        route->smoothed_metric_time = now.tv_sec;
    } else {
        int diff;
        /* We randomise the computation, to minimise global synchronisation
           and hence oscillations. */
        while(route->smoothed_metric_time <= now.tv_sec - smoothing_half_life) {
            diff = metric - route->smoothed_metric;
            route->smoothed_metric += roughly(diff) / 2;
            route->smoothed_metric_time += smoothing_half_life;
        }
        while(route->smoothed_metric_time < now.tv_sec) {
            diff = metric - route->smoothed_metric;
            route->smoothed_metric +=
                roughly(diff) * (two_to_the_one_over_hl - 0x10000) / 0x10000;
            route->smoothed_metric_time++;
        }

        diff = metric - route->smoothed_metric;
        if(diff > -4 && diff < 4)
            route->smoothed_metric = metric;
    }

    /* change_route_metric relies on this */
    assert(route->smoothed_metric_time == now.tv_sec);
    return route->smoothed_metric;
}

static int
route_acceptable(struct babel_route *route, int feasible,
                 struct neighbour *exclude)
{
    if(route_expired(route))
        return 0;
    if(feasible && !route_feasible(route))
        return 0;
    if(exclude && route->neigh == exclude)
        return 0;
    return 1;
}

/* Find the best route according to the weak ordering.  Any
   linearisation of the strong ordering (see consider_route) will do,
   we use sm <= sm'.  We could probably use a lexical ordering, but
   that's probably overkill. */

struct babel_route *
find_best_route(const unsigned char *prefix, unsigned char plen,
                const unsigned char *src_prefix, unsigned char src_plen,
                int feasible, struct neighbour *exclude)
{
    struct babel_route *route, *r;
    int i = find_route_slot(prefix, plen, src_prefix, src_plen, NULL);

    if(i < 0)
        return NULL;

    route = routes[i];
    while(route && !route_acceptable(route, feasible, exclude))
        route = route->next;

    if(!route)
        return NULL;

    r = route->next;
    while(r) {
        if(route_acceptable(r, feasible, exclude) &&
           (route_smoothed_metric(r) < route_smoothed_metric(route)))
            route = r;
        r = r->next;
    }

    return route;
}

void
update_route_metric(struct babel_route *route)
{
    int oldmetric = route_metric(route);
    int old_smoothed_metric = route_smoothed_metric(route);

    if(route_expired(route)) {
        if(route->refmetric < INFINITY) {
            route->seqno = seqno_plus(route->src->seqno, 1);
            retract_route(route);
            if(oldmetric < INFINITY)
                route_changed(route, route->src, oldmetric);
        }
    } else {
        struct neighbour *neigh = route->neigh;
        int add_metric = input_filter(route->src->id,
                                      route->src->prefix, route->src->plen,
                                      route->src->src_prefix,
                                      route->src->src_plen,
                                      neigh->address,
                                      neigh->ifp->ifindex);
        change_route_metric(route, route->refmetric,
                            neighbour_cost(route->neigh), add_metric);
        if(route_metric(route) != oldmetric ||
           route_smoothed_metric(route) != old_smoothed_metric)
            route_changed(route, route->src, oldmetric);
    }
}

/* Called whenever a neighbour's cost changes, to update the metric of
   all routes through that neighbour.  Calls local_notify_neighbour. */
void
update_neighbour_metric(struct neighbour *neigh, int changed)
{

    if(changed) {
        int i;

        for(i = 0; i < route_slots; i++) {
            struct babel_route *r = routes[i];
            while(r) {
                if(r->neigh == neigh)
                    update_route_metric(r);
                r = r->next;
            }
        }
    }

    local_notify_neighbour(neigh, LOCAL_CHANGE);
}

void
update_interface_metric(struct interface *ifp)
{
    int i;

    for(i = 0; i < route_slots; i++) {
        struct babel_route *r = routes[i];
        while(r) {
            if(r->neigh->ifp == ifp)
                update_route_metric(r);
            r = r->next;
        }
    }
}

/* This is called whenever we receive an update. */
struct babel_route *
update_route(const unsigned char *id,
             const unsigned char *prefix, unsigned char plen,
             const unsigned char *src_prefix, unsigned char src_plen,
             unsigned short seqno, unsigned short refmetric,
             unsigned short interval,
             struct neighbour *neigh, const unsigned char *nexthop,
             const unsigned char *channels, int channels_len)
{
    struct babel_route *route;
    struct source *src;
    int metric, feasible;
    int add_metric;
    int hold_time = MAX((4 * interval) / 100 + interval / 50, 15);
    int is_v4;
    if(memcmp(id, myid, 8) == 0)
        return NULL;

    if(martian_prefix(prefix, plen)) {
        fprintf(stderr, "Rejecting martian route to %s through %s.\n",
                format_prefix(prefix, plen), format_address(nexthop));
        return NULL;
    }
    if(src_plen != 0 && martian_prefix(src_prefix, src_plen)) {
        fprintf(stderr, "Rejecting martian route to %s from %s through %s.\n",
                format_prefix(prefix, plen),
                format_prefix(src_prefix, src_plen), format_eui64(id));
        return NULL;
    }

    is_v4 = v4mapped(prefix);
    if(src_plen != 0 && is_v4 != v4mapped(src_prefix))
        return NULL;


    add_metric = input_filter(id, prefix, plen, src_prefix, src_plen,
                              neigh->address, neigh->ifp->ifindex);
    if(add_metric >= INFINITY)
        return NULL;

    route = find_route(prefix, plen, src_prefix, src_plen, neigh, nexthop);

    if(route && memcmp(route->src->id, id, 8) == 0)
        /* Avoid scanning the source table. */
        src = route->src;
    else
        src = find_source(id, prefix, plen, src_prefix, src_plen, 1, seqno);

    if(src == NULL)
        return NULL;

    feasible = update_feasible(src, seqno, refmetric);
    metric = MIN((int)refmetric + neighbour_cost(neigh) + add_metric, INFINITY);

    if(route) {
        struct source *oldsrc;
        unsigned short oldmetric;
        int lost = 0;

        oldsrc = route->src;
        oldmetric = route_metric(route);

        /* If a successor switches sources, we must accept his update even
           if it makes a route unfeasible in order to break any routing loops
           in a timely manner.  If the source remains the same, we ignore
           the update. */
        if(!feasible && route->installed) {
            debugf("Unfeasible update for installed route to %s "
                   "(%s %d %d -> %s %d %d).\n",
                   format_prefix(src->prefix, src->plen),
                   format_eui64(route->src->id),
                   route->seqno, route->refmetric,
                   format_eui64(src->id), seqno, refmetric);
            if(src != route->src) {
                uninstall_route(route);
                lost = 1;
            }
        }

        route->src = retain_source(src);
        if((feasible || keep_unfeasible) && refmetric < INFINITY)
            route->time = now.tv_sec;
        route->seqno = seqno;

        if(channels_len == 0) {
            free(route->channels);
            route->channels = NULL;
            route->channels_len = 0;
        } else {
            if(channels_len != route->channels_len) {
                unsigned char *new_channels =
                    realloc(route->channels, channels_len);
                if(new_channels == NULL) {
                    perror("malloc(channels)");
                    /* Truncate the data. */
                    channels_len = MIN(channels_len, route->channels_len);
                } else {
                    route->channels = new_channels;
                }
            }
            memcpy(route->channels, channels, channels_len);
            route->channels_len = channels_len;
        }

        change_route_metric(route,
                            refmetric, neighbour_cost(neigh), add_metric);
        route->hold_time = hold_time;

        route_changed(route, oldsrc, oldmetric);
        if(lost)
            route_lost(oldsrc, oldmetric);

        if(!feasible)
            send_unfeasible_request(neigh, route->installed && route_old(route),
                                    seqno, metric, src);
        release_source(oldsrc);
    } else {
        struct babel_route *new_route;

        if(refmetric >= INFINITY)
            /* Somebody's retracting a route we never saw. */
            return NULL;
        if(!feasible) {
            send_unfeasible_request(neigh, 0, seqno, metric, src);
            if(!keep_unfeasible)
                return NULL;
        }

        route = calloc(1, sizeof(struct babel_route));
        if(route == NULL) {
            perror("malloc(route)");
            return NULL;
        }

        route->src = retain_source(src);
        route->refmetric = refmetric;
        route->cost = neighbour_cost(neigh);
        route->add_metric = add_metric;
        route->seqno = seqno;
        route->neigh = neigh;
        memcpy(route->nexthop, nexthop, 16);
        route->time = now.tv_sec;
        route->hold_time = hold_time;
        route->smoothed_metric = MAX(route_metric(route), INFINITY / 2);
        route->smoothed_metric_time = now.tv_sec;
        if(channels_len > 0) {
            route->channels = malloc(channels_len);
            if(route->channels == NULL) {
                perror("malloc(channels)");
            } else {
                memcpy(route->channels, channels, channels_len);
            }
        }
        route->next = NULL;
        new_route = insert_route(route);
        if(new_route == NULL) {
            fprintf(stderr, "Couldn't insert route.\n");
            destroy_route(route);
            return NULL;
        }
        local_notify_route(route, LOCAL_ADD);
        consider_route(route);
    }
    return route;
}

/* We just received an unfeasible update.  If it's any good, send
   a request for a new seqno. */
void
send_unfeasible_request(struct neighbour *neigh, int force,
                        unsigned short seqno, unsigned short metric,
                        struct source *src)
{
    struct babel_route *route = find_installed_route(src->prefix, src->plen,
                                                     src->src_prefix,
                                                     src->src_plen);

    if(seqno_minus(src->seqno, seqno) > 100) {
        /* Probably a source that lost its seqno.  Let it time-out. */
        return;
    }

    if(force || !route || route_metric(route) >= metric + 512) {
        send_unicast_multihop_request(neigh, src->prefix, src->plen,
                                      src->src_prefix, src->src_plen,
                                      src->metric >= INFINITY ?
                                      src->seqno :
                                      seqno_plus(src->seqno, 1),
                                      src->id, 127);
    }
}

/* This takes a feasible route and decides whether to install it.
   This uses the strong ordering, which is defined by sm <= sm' AND
   m <= m'.  This ordering is not total, which is what causes
   hysteresis. */

void
consider_route(struct babel_route *route)
{
    struct babel_route *installed;
    struct xroute *xroute;

    if(route->installed)
        return;

    if(!route_feasible(route))
        return;

    xroute = find_xroute(route->src->prefix, route->src->plen,
                         route->src->src_prefix, route->src->src_plen);
    if(xroute && (allow_duplicates < 0 || xroute->metric >= allow_duplicates))
        return;

    installed = find_installed_route(route->src->prefix, route->src->plen,
                                     route->src->src_prefix,
                                     route->src->src_plen);

    if(installed == NULL)
        goto install;

    if(route_metric(route) >= INFINITY)
        return;

    if(route_metric(installed) >= INFINITY)
        goto install;

    if(route_metric(installed) >= route_metric(route) &&
       route_smoothed_metric(installed) > route_smoothed_metric(route))
        goto install;

    return;

 install:
    switch_routes(installed, route);
    if(installed && route->installed)
        send_triggered_update(route, installed->src, route_metric(installed));
    else
        send_update(NULL, 1, route->src->prefix, route->src->plen,
                    route->src->src_prefix, route->src->src_plen);
    return;
}

void
retract_neighbour_routes(struct neighbour *neigh)
{
    int i;

    for(i = 0; i < route_slots; i++) {
        struct babel_route *r = routes[i];
        while(r) {
            if(r->neigh == neigh) {
                if(r->refmetric != INFINITY) {
                    unsigned short oldmetric = route_metric(r);
                    retract_route(r);
                    if(oldmetric != INFINITY)
                        route_changed(r, r->src, oldmetric);
                }
            }
            r = r->next;
        }
    }
}

void
send_triggered_update(struct babel_route *route, struct source *oldsrc,
                      unsigned oldmetric)
{
    unsigned newmetric, diff;
    /* 1 means send speedily, 2 means resend */
    int urgent;

    if(!route->installed)
        return;

    newmetric = route_metric(route);
    diff =
        newmetric >= oldmetric ? newmetric - oldmetric : oldmetric - newmetric;

    if(route->src != oldsrc || (oldmetric < INFINITY && newmetric >= INFINITY))
        /* Switching sources can cause transient routing loops.
           Retractions can cause blackholes. */
        urgent = 2;
    else if(newmetric > oldmetric && oldmetric < 6 * 256 && diff >= 512)
        /* Route getting significantly worse */
        urgent = 1;
    else if(unsatisfied_request(route->src->prefix, route->src->plen,
                                route->src->src_prefix, route->src->src_plen,
                                route->seqno, route->src->id))
        /* Make sure that requests are satisfied speedily */
        urgent = 1;
    else if(oldmetric >= INFINITY && newmetric < INFINITY)
        /* New route */
        urgent = 0;
    else if(newmetric < oldmetric && diff < 1024)
        /* Route getting better.  This may be a transient fluctuation, so
           don't advertise it to avoid making routes unfeasible later on. */
        return;
    else if(diff < 384)
        /* Don't fret about trivialities */
        return;
    else
        urgent = 0;

    if(urgent >= 2)
        send_update_resend(NULL, route->src->prefix, route->src->plen,
                           route->src->src_prefix, route->src->src_plen);
    else
        send_update(NULL, urgent, route->src->prefix, route->src->plen,
                    route->src->src_prefix, route->src->src_plen);

    if(oldmetric < INFINITY) {
        if(newmetric >= oldmetric + 288) {
            send_request(NULL, route->src->prefix, route->src->plen,
                         route->src->src_prefix, route->src->src_plen);
        }
    }
}

/* A route has just changed.  Decide whether to switch to a different route or
   send an update. */
void
route_changed(struct babel_route *route,
              struct source *oldsrc, unsigned short oldmetric)
{
    if(route->installed) {
        struct babel_route *better_route;
        /* Do this unconditionally -- microoptimisation is not worth it. */
        better_route =
            find_best_route(route->src->prefix, route->src->plen,
                            route->src->src_prefix, route->src->src_plen,
                            1, NULL);
        if(better_route && route_metric(better_route) < route_metric(route))
            consider_route(better_route);
    }

    if(route->installed) {
        /* We didn't change routes after all. */
        send_triggered_update(route, oldsrc, oldmetric);
    } else {
        /* Reconsider routes even when their metric didn't decrease,
           they may not have been feasible before. */
        consider_route(route);
    }
}

/* We just lost the installed route to a given destination. */
void
route_lost(struct source *src, unsigned oldmetric)
{
    struct babel_route *new_route;
    new_route = find_best_route(src->prefix, src->plen,
                                src->src_prefix, src->src_plen, 1, NULL);
    if(new_route) {
        consider_route(new_route);
    } else if(oldmetric < INFINITY) {
        /* Avoid creating a blackhole. */
        send_update_resend(NULL, src->prefix, src->plen,
                           src->src_prefix, src->src_plen);
        /* If the route was usable enough, try to get an alternate one.
           If it was not, we could be dealing with oscillations around
           the value of INFINITY. */
        if(oldmetric <= INFINITY / 2)
            send_request_resend(NULL, src->prefix, src->plen,
                                src->src_prefix, src->src_plen,
                                src->metric >= INFINITY ?
                                src->seqno : seqno_plus(src->seqno, 1),
                                src->id);
    }
}

/* This is called periodically to flush old routes.  It will also send
   requests for routes that are about to expire. */
void
expire_routes(void)
{
    struct babel_route *r;
    int i;

    debugf("Expiring old routes.\n");

    i = 0;
    while(i < route_slots) {
        r = routes[i];
        while(r) {
            /* Protect against clock being stepped. */
            if(r->time > now.tv_sec || route_old(r)) {
                flush_route(r);
                goto again;
            }

            update_route_metric(r);

            if(r->installed && r->refmetric < INFINITY) {
                if(route_old(r))
                    /* Route about to expire, send a request. */
                    send_unicast_request(r->neigh,
                                         r->src->prefix, r->src->plen,
                                         r->src->src_prefix, r->src->src_plen);
            }
            r = r->next;
        }
        i++;
    again:
        ;
    }
}
