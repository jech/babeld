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
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "babel.h"
#include "util.h"
#include "network.h"
#include "neighbour.h"
#include "source.h"
#include "route.h"
#include "message.h"
#include "local.h"

struct neighbour *neighs = NULL;

struct neighbour *
find_neighbour(const unsigned char *address, struct network *net)
{
    struct neighbour *neigh;
    FOR_ALL_NEIGHBOURS(neigh) {
        if(memcmp(address, neigh->address, 16) == 0 &&
           neigh->network == net)
            return neigh;
    }
    return NULL;
}

struct neighbour *
find_neighbour_by_id(const unsigned char *id, struct network *net)
{
    struct neighbour *neigh;
    FOR_ALL_NEIGHBOURS(neigh) {
        if(memcmp(id, neigh->id, 16) == 0 && neigh->network == net)
            return neigh;
    }
    return NULL;
}

void
flush_neighbour(struct neighbour *neigh)
{
    flush_neighbour_routes(neigh);
    if(unicast_neighbour == neigh)
        flush_unicast(1);

    if(neighs == neigh) {
        neighs = neigh->next;
    } else {
        struct neighbour *previous = neighs;
        while(previous->next != neigh)
            previous = previous->next;
        previous->next = neigh->next;
    }
    local_notify_neighbour(neigh, LOCAL_FLUSH);
    free(neigh);
}

struct neighbour *
add_neighbour(const unsigned char *id, const unsigned char *address,
              struct network *net)
{
    struct neighbour *neigh;
    const struct timeval zero = {0, 0};

    neigh = find_neighbour(address, net);
    if(neigh) {
        if(memcmp(neigh->id, id, 16) == 0) {
            return neigh;
        } else {
            fprintf(stderr, "Neighbour changed id (%s -> %s)!\n",
                    format_address(neigh->id), format_address(id));
            flush_neighbour(neigh);
            neigh = NULL;
        }
    }

    neigh = find_neighbour_by_id(id, net);
    if(neigh) {
        if((neigh->reach & 0xE000) == 0) {
            /* The other neighbour is probably obsolete. */
            flush_neighbour(neigh);
            neigh = NULL;
        } else {
            fprintf(stderr, "Duplicate neighbour %s (%s and %s)!\n",
                    format_address(id),
                    format_address(neigh->address),
                    format_address(address));
            return NULL;
        }
    }

    debugf("Creating neighbour %s (%s).\n",
           format_address(id), format_address(address));

    neigh = malloc(sizeof(struct neighbour));
    if(neigh == NULL) {
        perror("malloc(neighbour)");
        return NULL;
    }

    neigh->hello_seqno = -1;
    memcpy(neigh->id, id, 16);
    memcpy(neigh->address, address, 16);
    neigh->reach = 0;
    neigh->txcost = INFINITY;
    neigh->ihu_time = now;
    neigh->hello_time = zero;
    neigh->hello_interval = 0;
    neigh->ihu_interval = 0;
    neigh->network = net;
    neigh->next = neighs;
    neighs = neigh;
    local_notify_neighbour(neigh, LOCAL_ADD);
    send_hello(net);
    return neigh;
}

/* Recompute a neighbour's rxcost.  Return true if anything changed. */
int
update_neighbour(struct neighbour *neigh, int hello, int hello_interval)
{
    int missed_hellos;
    int rc = 0;

    if(hello < 0) {
        if(neigh->hello_interval <= 0)
            return rc;
        missed_hellos =
            (timeval_minus_msec(&now, &neigh->hello_time) -
             neigh->hello_interval * 7) /
            (neigh->hello_interval * 10);
        if(missed_hellos <= 0)
            return rc;
        timeval_plus_msec(&neigh->hello_time, &neigh->hello_time,
                          missed_hellos * neigh->hello_interval * 10);
    } else {
        if(neigh->hello_seqno >= 0 && neigh->reach > 0) {
            missed_hellos = seqno_minus(hello, neigh->hello_seqno) - 1;
            if(missed_hellos < -8) {
                /* Probably a neighbour that rebooted and lost its seqno.
                   Reboot the universe. */
                neigh->reach = 0;
                missed_hellos = 0;
                rc = 1;
            } else if(missed_hellos < 0) {
                if(hello_interval > neigh->hello_interval) {
                    /* This neighbour has increased its hello interval,
                       and we didn't notice. */
                    neigh->reach <<= -missed_hellos;
                    missed_hellos = 0;
                } else {
                    /* Late hello.  Probably due to the link layer buffering
                       packets during a link outage.  Ignore it, but reset
                       the expected seqno. */
                    neigh->hello_seqno = hello;
                    hello = -1;
                    missed_hellos = 0;
                }
                rc = 1;
            }
        } else {
            missed_hellos = 0;
        }
        neigh->hello_time = now;
        neigh->hello_interval = hello_interval;
    }

    if(missed_hellos > 0) {
        neigh->reach >>= missed_hellos;
        neigh->hello_seqno = seqno_plus(neigh->hello_seqno, missed_hellos);
        missed_hellos = 0;
        rc = 1;
    }

    if(hello >= 0) {
        neigh->hello_seqno = hello;
        neigh->reach >>= 1;
        neigh->reach |= 0x8000;
        if((neigh->reach & 0xFC00) != 0xFC00)
            rc = 1;
    }

    /* Make sure to give neighbours some feedback early after association */
    if((neigh->reach & 0xBF00) == 0x8000) {
        /* A new neighbour */
        send_hello(neigh->network);
    } else {
        /* Don't send hellos, in order to avoid a positive feedback loop. */
        int a = (neigh->reach & 0xC000);
        int b = (neigh->reach & 0x3000);
        if((a == 0xC000 && b == 0) || (a == 0 && b == 0x3000)) {
            /* Reachability is either 1100 or 0011 */
            send_self_update(neigh->network, 0);
        }
    }

    if((neigh->reach & 0xFC00) == 0xC000) {
        /* This is a newish neighbour.  If we don't have another route to it,
           request a full route dump.  This assumes that the neighbour's id
           is also its IP address and that it is exporting a route to itself. */
        struct route *route = NULL;
        send_ihu(neigh, NULL);
        if(!martian_prefix(neigh->id, 128))
           route = find_installed_route(neigh->id, 128);
        if(!route || route->metric >= INFINITY || route->neigh == neigh)
            send_unicast_request(neigh, NULL, 0, 0, 0, 0);
    }
    if(rc)
        local_notify_neighbour(neigh, LOCAL_CHANGE);
    return rc;
}

static int
reset_txcost(struct neighbour *neigh)
{
    int delay;

    delay = timeval_minus_msec(&now, &neigh->ihu_time);

    if(neigh->ihu_interval > 0 && delay < neigh->ihu_interval * 10 * 3)
        return 0;

    /* If we're losing a lot of packets, we probably lost an IHU too */
    if(delay >= 180000 || (neigh->reach & 0xFFF0) == 0 ||
       (neigh->ihu_interval > 0 &&
        delay >= neigh->ihu_interval * 10 * 10)) {
        neigh->txcost = INFINITY;
        neigh->ihu_time = now;
        return 1;
    }

    return 0;
}

int
neighbour_txcost(struct neighbour *neigh)
{
    reset_txcost(neigh);
    return neigh->txcost;
}

int
check_neighbours()
{
    struct neighbour *neigh;
    int changed, delay;
    int msecs = 50000;

    debugf("Checking neighbours.\n");

    neigh = neighs;
    while(neigh) {
        changed = update_neighbour(neigh, -1, 0);

        if(neigh->reach == 0 ||
           neigh->hello_time.tv_sec > now.tv_sec || /* clock stepped */
           timeval_minus_msec(&now, &neigh->hello_time) > 300000) {
            struct neighbour *old = neigh;
            neigh = neigh->next;
            flush_neighbour(old);
            continue;
        }

        delay = timeval_minus_msec(&now, &neigh->ihu_time);

        changed = changed || reset_txcost(neigh);

        if(changed) {
            update_neighbour_metric(neigh);
            local_notify_neighbour(neigh, LOCAL_CHANGE);
        }

        if(neigh->hello_interval > 0)
            msecs = MIN(msecs, neigh->hello_interval * 10);
        if(neigh->ihu_interval > 0)
            msecs = MIN(msecs, neigh->ihu_interval * 10);
        neigh = neigh->next;
    }

    return msecs;
}

int
neighbour_rxcost(struct neighbour *neigh)
{
    int delay;
    unsigned short reach = neigh->reach;

    delay = timeval_minus_msec(&now, &neigh->hello_time);

    if((reach & 0xFFF0) == 0 || delay >= 180000) {
        return INFINITY;
    } else if(neigh->network->wired) {
        /* To lose one hello is a misfortune, to lose two is carelessness. */
        if((reach & 0xC000) == 0xC000)
            return neigh->network->cost;
        else if((reach & 0xC000) == 0)
            return INFINITY;
        else if((reach & 0x2000))
            return neigh->network->cost;
        else
            return INFINITY;
    } else {
        int sreach =
            ((reach & 0x8000) >> 2) +
            ((reach & 0x4000) >> 1) +
            (reach & 0x3FFF);
        /* 0 <= sreach <= 0x7FFF */
        int cost = (0x8000 * neigh->network->cost) / (sreach + 1);
        /* cost >= network->cost */
        if(delay >= 40000)
            cost = (cost * (delay - 20000) + 10000) / 20000;

        return MIN(cost, INFINITY);
    }
}

int
neighbour_cost(struct neighbour *neigh)
{
    int a, b;

    if(!neigh->network->up)
        return INFINITY;

    a = neighbour_txcost(neigh);

    if(a >= INFINITY)
        return INFINITY;

    b = neighbour_rxcost(neigh);
    if(b >= INFINITY)
        return INFINITY;

    if(neigh->network->wired || (a <= 256 && b <= 256)) {
        return a;
    } else {
        /* a = 256/alpha, b = 256/beta, where alpha and beta are the expected
           probabilities of a packet getting through in the direct and reverse
           directions. */
        a = MAX(a, 256);
        b = MAX(b, 256);
        /* 1/(alpha * beta), which is just plain ETX. */
        return ((a * b + 128) >> 8);
    }
}
