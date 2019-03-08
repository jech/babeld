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
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <assert.h>

#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "neighbour.h"
#include "source.h"
#include "hmac.h"
#include "route.h"
#include "message.h"
#include "resend.h"
#include "local.h"

struct neighbour *neighs = NULL;

static struct neighbour *
find_neighbour_nocreate(const unsigned char *address, struct interface *ifp)
{
    struct neighbour *neigh;
    FOR_ALL_NEIGHBOURS(neigh) {
        if(memcmp(address, neigh->address, 16) == 0 &&
           neigh->ifp == ifp)
            return neigh;
    }
    return NULL;
}

void
flush_neighbour(struct neighbour *neigh)
{
    flush_neighbour_routes(neigh);
    flush_resends(neigh);

    if(neighs == neigh) {
        neighs = neigh->next;
    } else {
        struct neighbour *previous = neighs;
        while(previous->next != neigh)
            previous = previous->next;
        previous->next = neigh->next;
    }
    local_notify_neighbour(neigh, LOCAL_FLUSH);
    free(neigh->buf.buf);
    free(neigh);
}

struct neighbour *
find_neighbour(const unsigned char *address, struct interface *ifp)
{
    struct neighbour *neigh;
    const struct timeval zero = {0, 0};
    unsigned char *buf;

    neigh = find_neighbour_nocreate(address, ifp);
    if(neigh)
        return neigh;

    debugf("Creating neighbour %s on %s.\n",
           format_address(address), ifp->name);

    buf = malloc(ifp->buf.size);
    if(buf == NULL) {
        perror("malloc(neighbour->buf)");
        return NULL;
    }

    neigh = calloc(1, sizeof(struct neighbour));
    if(neigh == NULL) {
        free(buf);
        perror("malloc(neighbour)");
        return NULL;
    }

    neigh->hello.seqno = neigh->uhello.seqno = -1;
    memcpy(neigh->address, address, 16);
    neigh->txcost = INFINITY;
    neigh->ihu_time = now;
    neigh->hello.time = neigh->uhello.time = zero;
    neigh->hello_rtt_receive_time = zero;
    neigh->echo_receive_time = zero;
    neigh->rtt_time = zero;
    neigh->challenge_deadline = now;
    neigh->ifp = ifp;
    neigh->buf.buf = buf;
    neigh->buf.size = ifp->buf.size;
    neigh->buf.flush_interval = ifp->buf.flush_interval;
    neigh->buf.sin6.sin6_family = AF_INET6;
    memcpy(&neigh->buf.sin6.sin6_addr, address, 16);
    neigh->buf.sin6.sin6_port = htons(protocol_port);
    neigh->buf.sin6.sin6_scope_id = ifp->ifindex;
    neigh->next = neighs;
    neighs = neigh;
    local_notify_neighbour(neigh, LOCAL_ADD);
    return neigh;
}

/* Recompute a neighbour's rxcost.  Return true if anything changed.
   This does not call local_notify_neighbour, see update_neighbour_metric. */
int
update_neighbour(struct neighbour *neigh, struct hello_history *hist,
                 int unicast, int hello, int hello_interval)
{
    int missed_hellos;
    int rc = 0;

    if(hello < 0) {
        if(hist->interval <= 0)
            return rc;
        missed_hellos =
            ((int)timeval_minus_msec(&now, &hist->time) -
             hist->interval * 7) /
            (hist->interval * 10);
        if(missed_hellos <= 0)
            return rc;
        timeval_add_msec(&hist->time, &hist->time,
                         missed_hellos * hist->interval * 10);
    } else {
        if(hist->seqno >= 0 && hist->reach > 0) {
            missed_hellos = seqno_minus(hello, hist->seqno) - 1;
            if(missed_hellos < -8) {
                /* Probably a neighbour that rebooted and lost its seqno.
                   Reboot the universe. */
                hist->reach = 0;
                missed_hellos = 0;
                rc = 1;
            } else if(missed_hellos < 0) {
                /* Late hello. Probably due to the link layer buffering
                   packets during a link outage or a cpu overload. */
                   fprintf(stderr,
                        "Late hello: bufferbloated neighbor %s\n",
                         format_address(neigh->address));
                hist->reach <<= -missed_hellos;
                missed_hellos = 0;
                rc = 1;
            }
        } else {
            missed_hellos = 0;
        }
        if(hello_interval != 0) {
            hist->time = now;
            hist->interval = hello_interval;
        }
    }

    if(missed_hellos > 0) {
        hist->reach >>= missed_hellos;
        hist->seqno = seqno_plus(hist->seqno, missed_hellos);
        missed_hellos = 0;
        rc = 1;
    }

    if(hello >= 0) {
        hist->seqno = hello;
        hist->reach >>= 1;
        hist->reach |= 0x8000;
        if((hist->reach & 0xFC00) != 0xFC00)
            rc = 1;
    }

    if(unicast)
        return rc;

    /* Make sure to give neighbours some feedback early after association */
    if((hist->reach & 0xBF00) == 0x8000) {
        /* A new neighbour */
        send_hello(neigh->ifp);
    } else {
        /* Don't send hellos, in order to avoid a positive feedback loop. */
        int a = (hist->reach & 0xC000);
        int b = (hist->reach & 0x3000);
        if((a == 0xC000 && b == 0) || (a == 0 && b == 0x3000)) {
            /* Reachability is either 1100 or 0011 */
            send_self_update(neigh->ifp);
        }
    }

    return rc;
}

static int
reset_txcost(struct neighbour *neigh)
{
    unsigned delay;

    delay = timeval_minus_msec(&now, &neigh->ihu_time);

    if(neigh->ihu_interval > 0 && delay < neigh->ihu_interval * 10 * 3)
        return 0;

    /* If we're losing a lot of packets, we probably lost an IHU too */
    if(delay >= 180000 || (neigh->hello.reach & 0xFFF0) == 0 ||
       (neigh->ihu_interval > 0 &&
        delay >= neigh->ihu_interval * 10 * 10)) {
        neigh->txcost = INFINITY;
        neigh->ihu_time = now;
        return 1;
    }

    return 0;
}

unsigned
neighbour_txcost(struct neighbour *neigh)
{
    return neigh->txcost;
}

unsigned
check_neighbours()
{
    struct neighbour *neigh;
    unsigned msecs = 50000;

    debugf("Checking neighbours.\n");

    neigh = neighs;
    while(neigh) {
        int changed, rc;
        changed = update_neighbour(neigh, &neigh->hello, 0, -1, 0);
        rc = update_neighbour(neigh, &neigh->uhello, 1, -1, 0);
        changed = changed || rc;

        if(neigh->hello.reach == 0 ||
           neigh->hello.time.tv_sec > now.tv_sec || /* clock stepped */
           timeval_minus_msec(&now, &neigh->hello.time) > 300000) {
            struct neighbour *old = neigh;
            neigh = neigh->next;
            flush_neighbour(old);
            continue;
        }

        rc = reset_txcost(neigh);
        changed = changed || rc;

        update_neighbour_metric(neigh, changed);

        if(neigh->hello.interval > 0)
            msecs = MIN(msecs, neigh->hello.interval * 10);
        if(neigh->uhello.interval > 0)
            msecs = MIN(msecs, neigh->uhello.interval * 10);
        if(neigh->ihu_interval > 0)
            msecs = MIN(msecs, neigh->ihu_interval * 10);
        neigh = neigh->next;
    }

    return msecs;
}

/* To lose one hello is a misfortune, to lose two is carelessness. */
static int
two_three(int reach)
{
    if((reach & 0xC000) == 0xC000)
        return 1;
    else if((reach & 0xC000) == 0)
        return 0;
    else if((reach & 0x2000))
        return 1;
    else
        return 0;
}

unsigned
neighbour_rxcost(struct neighbour *neigh)
{
    unsigned delay, udelay;
    unsigned short reach = neigh->hello.reach;
    unsigned short ureach = neigh->uhello.reach;

    delay = timeval_minus_msec(&now, &neigh->hello.time);
    udelay = timeval_minus_msec(&now, &neigh->uhello.time);

    if(((reach & 0xFFF0) == 0 || delay >= 180000) &&
       ((ureach & 0xFFF0) == 0 || udelay >= 180000)) {
        return INFINITY;
    } else if((neigh->ifp->flags & IF_LQ)) {
        int sreach =
            ((reach & 0x8000) >> 2) +
            ((reach & 0x4000) >> 1) +
            (reach & 0x3FFF);
        /* 0 <= sreach <= 0x7FFF */
        int cost = (0x8000 * neigh->ifp->cost) / (sreach + 1);
        /* cost >= interface->cost */
        if(delay >= 40000)
            cost = (cost * (delay - 20000) + 10000) / 20000;
        return MIN(cost, INFINITY);
    } else {
        if(two_three(reach) || two_three(ureach))
            return neigh->ifp->cost;
        else
            return INFINITY;
    }
}

unsigned
neighbour_rttcost(struct neighbour *neigh)
{
    struct interface *ifp = neigh->ifp;

    if(!ifp->max_rtt_penalty || !valid_rtt(neigh))
        return 0;

    /* Function: linear behaviour between rtt_min and rtt_max. */
    if(neigh->rtt <= ifp->rtt_min) {
        return 0;
    } else if(neigh->rtt <= ifp->rtt_max) {
        unsigned long long tmp =
            (unsigned long long)ifp->max_rtt_penalty *
            (neigh->rtt - ifp->rtt_min) /
            (ifp->rtt_max - ifp->rtt_min);
        assert((tmp & 0x7FFFFFFF) == tmp);
        return tmp;
    } else {
        return ifp->max_rtt_penalty;
    }
}

unsigned
neighbour_cost(struct neighbour *neigh)
{
    unsigned a, b, cost;

    if(!if_up(neigh->ifp))
        return INFINITY;

    a = neighbour_txcost(neigh);

    if(a >= INFINITY)
        return INFINITY;

    b = neighbour_rxcost(neigh);
    if(b >= INFINITY)
        return INFINITY;

    if(!(neigh->ifp->flags & IF_LQ) || (a < 256 && b < 256)) {
        cost = a;
    } else {
        /* a = 256/alpha, b = 256/beta, where alpha and beta are the expected
           probabilities of a packet getting through in the direct and reverse
           directions. */
        a = MAX(a, 256);
        b = MAX(b, 256);
        /* 1/(alpha * beta), which is just plain ETX. */
        /* Since a and b are capped to 16 bits, overflow is impossible. */
        cost = (a * b + 128) >> 8;
    }

    cost += neighbour_rttcost(neigh);

    return MIN(cost, INFINITY);
}

int
valid_rtt(struct neighbour *neigh)
{
    return (timeval_minus_msec(&now, &neigh->rtt_time) < 180000) ? 1 : 0;
}
