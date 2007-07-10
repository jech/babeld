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
#include <sys/time.h>
#include <time.h>

#include "babel.h"
#include "util.h"
#include "neighbour.h"
#include "destination.h"
#include "route.h"
#include "xroute.h"
#include "message.h"

struct neighbour neighs[MAXNEIGHBOURS];
int numneighs = 0;

void
flush_neighbour(struct neighbour *neigh)
{
    flush_neighbour_xroutes(neigh);
    flush_neighbour_routes(neigh);
    memset(neigh, 0, sizeof(*neigh));
    if(neigh == &neighs[numneighs - 1]) {
       numneighs--;
       VALGRIND_MAKE_MEM_UNDEFINED(neigh, sizeof(*neigh));
    } else {
        VALGRIND_MAKE_MEM_UNDEFINED(neigh, sizeof(*neigh));
        neigh->id[0] = 0xFF;
    }
}

struct neighbour *
find_neighbour(const unsigned char *address, struct network *net)
{
    int i;
    for(i = 0; i < numneighs; i++) {
        if(neighs[i].id[0] == 0xFF)
            continue;
        if(memcmp(address, neighs[i].address, 16) == 0 &&
           neighs[i].network == net)
            return &neighs[i];
    }
    return NULL;
}

struct neighbour *
add_neighbour(const unsigned char *id, const unsigned char *address,
              struct network *net)
{
    struct neighbour *neigh;
    int i;

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
    debugf("Creating neighbour %s (%s).\n",
           format_address(id), format_address(address));
    for(i = 0; i < numneighs; i++) {
        if(neighs[i].id[0] == 0xFF)
            neigh = &neighs[i];
    }
    if(!neigh) {
        if(numneighs >= MAXNEIGHBOURS) {
            fprintf(stderr, "Too many neighbours.\n");
            return NULL;
        }
        neigh = &neighs[numneighs++];
    }
    memcpy(neigh->id, id, 16);
    memcpy(neigh->address, address, 16);
    neigh->hello_interval = 0;
    neigh->reach = 0;
    neigh->txcost = INFINITY;
    neigh->txcost_time = now.tv_sec;
    neigh->hello_time = 0;
    neigh->hello_interval = 0;
    neigh->hello_seqno = -1;
    neigh->network = net;
    send_hello(net);
    return neigh;
}

void
update_neighbour(struct neighbour *neigh, int hello, int hello_interval)
{
    int missed_hellos;

    if(hello < 0) {
        if(neigh->hello_interval <= 0)
            return;
        missed_hellos =
            (now.tv_sec - 3 - neigh->hello_time) / neigh->hello_interval;
        if(missed_hellos <= 0)
            return;
        neigh->hello_time += missed_hellos * neigh->hello_interval;
    } else {
        if(neigh->hello_seqno >= 0 && neigh->reach > 0) {
            missed_hellos = seqno_minus(hello, neigh->hello_seqno) - 1;
            if(missed_hellos < 0) {
                /* This neighbour has increased its hello interval, and we
                   didn't notice. */
                neigh->reach <<= -missed_hellos;
                missed_hellos = 0;
            }
        } else {
            missed_hellos = 0;
        }
        neigh->hello_time = now.tv_sec;
        neigh->hello_interval = hello_interval;
    }

    neigh->reach >>= missed_hellos;
    missed_hellos = 0;

    if(hello >= 0) {
        neigh->hello_seqno = hello;
        neigh->reach >>= 1;
        neigh->reach |= 0x8000;
    }

    /* Make sure to give neighbours some feedback early after association */
    if((neigh->reach & 0xFC00) == 0x8000) {
        /* A new neighbour */
        send_hello(neigh->network);
        send_txcost(neigh, NULL);
    } else {
        /* Don't send hellos, in order to avoid a positive feedback loop. */
        int a = (neigh->reach & 0xC000);
        int b = (neigh->reach & 0x3000);
        if((a == 0xC000 && b == 0) || (a == 0 && b == 0x3000)) {
            /* Reachability is either 1100 or 0011 */
            send_txcost(neigh, NULL);
            send_self_update(neigh->network, 0);
            send_neighbour_update(neigh, NULL);
        }
    }

    if((neigh->reach & 0xFF00) == 0xC000) {
        /* This is a newish neighbour.  If we don't have another route to it,
           request a full route dump.  This assumes that the neighbour's ID
           is also its IP address. */
        struct destination *dest;
        struct route *route = NULL;
        dest = find_destination(neigh->id, 0, 0);
        if(dest)
            route = find_installed_route(dest);
        if(!route || route->metric >= INFINITY || route->nexthop == neigh)
            send_unicast_request(neigh, NULL, 0, -1);
    }
}

void
check_neighbour(struct neighbour *neigh)
{
    update_neighbour(neigh, -1, 0);
    if(neigh->reach == 0) {
        flush_neighbour(neigh);
        return;
    }

    if(!neigh->network->wired) {
        while(neigh->txcost < INFINITY &&
              neigh->txcost_time <= now.tv_sec - 40) {
            neigh->txcost = MIN((int)neigh->txcost * 3 / 2, INFINITY);
            neigh->txcost_time += 10;
        }
    }
}

int
neighbour_rxcost(struct neighbour *neigh)
{
    update_neighbour(neigh, -1, 0);
    if((neigh->reach & 0xF800) == 0)
        return INFINITY;
    else if(neigh->network->wired) {
        if((neigh->reach & 0xE000) != 0) {
            int c = neigh->network->cost;
            int d = now.tv_sec - neigh->hello_time;
            if(d >= 60)
                c = (c * (d - 40) + 19) / 20;
            return MIN(c, INFINITY);
        } else {
            return INFINITY;
        }
    } else {
        int r = (neigh->reach & 0x7FFF) + ((neigh->reach & 0x8000) >> 1);
        /* 0 <= r <= 0xBFFF */
        int c = (0xC000 * 0x100) / r;
        int d = now.tv_sec - neigh->hello_time;
        if(d >= 40)
            c = (c * (d - 20) + 10) / 20;

        return MIN(c + neigh->network->cost, INFINITY);
    }
}

int
neighbour_cost(struct neighbour *neigh)
{
    int a, b;

    a = neigh->txcost;

    if(a >= INFINITY)
        return INFINITY;

    b = neighbour_rxcost(neigh);
    if(b >= INFINITY)
        return INFINITY;

    if(a <= 256 && b <= 256) {
        return MAX(a, b);
    } else {
        /* a = 256/alpha, b = 256/beta, where alpha and beta are the expected
           probabilities of a packet getting through in the direct and reverse
           directions. */
        a = MAX(a, 256);
        b = MAX(b, 256);
        /* (1/(alpha * beta) + 1/beta) / 2, which is half the expected
           number of transmissions, in both directions.
           ETX uses 1/(alpha * beta), which is the expected number of
           transmissions in the forward direction. */
        return (((a * b + 128) >> 8) + b + 1) >> 1;
    }
}
