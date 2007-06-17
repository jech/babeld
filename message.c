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
#include <assert.h>

#include <arpa/inet.h>

#include "babel.h"
#include "util.h"
#include "net.h"
#include "destination.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"

struct timeval update_flush_time = {0, 0};

static const unsigned char zeroes[16] = {0};
const unsigned char packet_header[4] = {42, 0, 0, 0};

unsigned int jitter;
unsigned int update_jitter;
int add_cost = 0;
int parasitic = 0;
int silent_time = 30;
int broadcast_txcost = 0;
int split_horizon = 1;

unsigned char seqno = 0;
int seqno_time = 0;
int seqno_interval = -1;

struct destination *buffered_updates[MAX_BUFFERED_UPDATES];
struct network *update_net = NULL;
int updates = 0;

void
parse_packet(const unsigned char *from, struct network *net,
             const unsigned char *packet, int len)
{
    int i, j;
    const unsigned char *message;
    struct neighbour *neigh;
    struct xroute pxroutes[20];
    int numpxroutes = 0;

    if(len % 20 != 4 || packet[0] != 42) {
        fprintf(stderr, "Received malformed packet on %s from %s.\n",
                net->ifname, format_address(from));
        return;
    }

    j = 0;
    for(i = 0; i < (len - 4) / 20; i++) {
        message = packet + 4 + 20 * i;
        if(message[0] != 4 && message[0] != 2) {
            if(numpxroutes > 0) {
                fprintf(stderr, "Received unexpected xroute on %s from %s.\n",
                        net->ifname, format_address(from));
            }
            numpxroutes = 0;
            VALGRIND_MAKE_MEM_UNDEFINED(pxroutes, sizeof(pxroutes));
        }
        if(message[0] == 0) {
            if(memcmp(message + 4, myid, 16) == 0)
                    continue;
            debugf("Received hello on %s from %s (%s).\n",
                   net->ifname,
                   format_address(message + 4),
                   format_address(from));
            neigh = add_neighbour(message + 4, from, net);
            update_neighbour(neigh, message[1], (message[2] << 8 | message[3]));
            update_neighbour_metric(neigh);
        } else {
            neigh = find_neighbour(from, net);
            if(neigh == NULL)
                continue;
            if(message[0] == 1) {
                debugf("Received request on %s from %s (%s) for %s.\n",
                       net->ifname,
                       format_address(neigh->id),
                       format_address(from),
                       format_address(message + 4));
                if(memcmp(message + 4, zeroes, 16) == 0) {
                    /* If a neighbour is requesting a full route dump from us,
                       we might as well send its txcost. */
                    send_txcost(neigh, NULL);
                    send_update(NULL, neigh->network);
                } else if(memcmp(message + 4, myid, 16) == 0) {
                    send_self_update(neigh->network, 1);
                } else {
                    struct destination *dest;
                    dest = find_destination(message + 4, 0, 0);
                    if(dest)
                        send_update(dest, neigh->network);
                }
            } else if(message[0] == 2) {
                debugf("Received update on %s from %s (%s) for %s.\n",
                       net->ifname,
                       format_address(neigh->id),
                       format_address(from),
                       format_address(message + 4));
                if(memcmp(message + 4, myid, 16) == 0) {
                    int metric = ((message[2] << 8) | (message[3] & 0xFF));
                    int theirseqno = message[1];
                    if(metric >= INFINITY) {
                        /* Oh my, someone is retracting a route to me. */
                        send_txcost(neigh, NULL);
                        send_self_update(neigh->network,
                                         seqno_compare(theirseqno, seqno) < 0);
                    }
                    continue;
                }

                update_route(message + 4,
                             message[1], (message[2] << 8 | message[3]),
                             neigh, pxroutes, numpxroutes);
                numpxroutes = 0;
                VALGRIND_MAKE_MEM_UNDEFINED(pxroutes, sizeof(pxroutes));
            } else if(message[0] == 3) {
                debugf("Received txcost from %s.\n", format_address(from));
                if(memcmp(myid, message + 4, 16) == 0 ||
                   memcmp(zeroes, message + 4, 16) == 0) {
                    neigh->txcost = (message[2] << 8 | message[3]);
                    neigh->txcost_time = now.tv_sec;
                }
                update_neighbour_metric(neigh);
            } else if(message[0] == 4) {
                debugf("Received xroute from %s.\n",
                       format_address(from));
                if(numpxroutes >= 20) {
                    fprintf(stderr, "Too many xroutes in update.\n");
                    continue;
                }
                memcpy(pxroutes[numpxroutes].prefix, message + 4, 16);
                pxroutes[numpxroutes].plen = message[1];
                pxroutes[numpxroutes].cost =
                    ((message[2] << 8) | (message[3] & 0xFF));
                numpxroutes++;
            } else {
                debugf("Received unknown packet type %d from %s.\n",
                       message[0], format_address(from));
            }
        }
    }
    return;
}

/* Under normal circumstances, there are enough moderation mechanisms
   elsewhere in the protocol to make sure that this last-ditch check
   should never trigger.  But I'm superstitious. */

static int
check_bucket(struct network *net)
{
    if(net->bucket > 0 && now.tv_sec > net->bucket_time) {
        net->bucket =
            MAX(0, (int)net->bucket - 40 * (now.tv_sec - net->bucket_time));
    }

    net->bucket_time = now.tv_sec;

    if(net->bucket < 400) {
        net->bucket++;
        return 1;
    } else {
        return 0;
    }
}

void
flushbuf(struct network *net)
{
    int rc;
    struct sockaddr_in6 sin6;

    if(update_net == net) {
        flushupdates();
        return;
    }

    if(net->buffered > 0) {
        debugf("  (flushing %d buffered bytes on %s)\n",
               net->buffered, net->ifname);
        if(check_bucket(net)) {
            memset(&sin6, 0, sizeof(sin6));
            sin6.sin6_family = AF_INET6;
            memcpy(&sin6.sin6_addr, protocol_group, 16);
            sin6.sin6_port = htons(protocol_port);
            sin6.sin6_scope_id = net->ifindex;
            rc = babel_send(protocol_socket,
                            packet_header, sizeof(packet_header),
                            net->sendbuf, net->buffered,
                            (struct sockaddr*)&sin6, sizeof(sin6));
            if(rc < 0)
                perror("send");
        } else {
            fprintf(stderr, "Warning: bucket full, dropping packet to %s.\n",
                    net->ifname);
        }
    }
    VALGRIND_MAKE_MEM_UNDEFINED(net->sendbuf, net->bufsize);
    net->buffered = 0;
    net->flush_time.tv_sec = 0;
    net->flush_time.tv_usec = 0;
}

static void
schedule_flush(struct network *net)
{
    int msecs = jitter / 2 + random() % jitter;
    if(net->flush_time.tv_sec != 0 &&
       timeval_minus_msec(&net->flush_time, &now) < msecs)
        return;
    net->flush_time.tv_usec = (now.tv_usec + msecs * 1000) % 1000000;
    net->flush_time.tv_sec = now.tv_sec + (now.tv_usec / 1000 + msecs) / 1000;
}

static void
start_message(struct network *net, int bytes)
{
    if(net->bufsize - net->buffered < bytes)
        flushbuf(net);
}

static void
accumulate_byte(struct network *net, unsigned char byte)
{
    assert(net->bufsize - net->buffered >= 1);
    net->sendbuf[net->buffered] = byte;
    net->buffered++;
}

static void
accumulate_short(struct network *net, unsigned short s)
{
    assert(net->bufsize - net->buffered >= 2);
    net->sendbuf[net->buffered] = s >> 8;
    net->sendbuf[net->buffered + 1] = (s & 0xFF);
    net->buffered += 2;
}

static void
accumulate_data(struct network *net,
                const unsigned char *data, unsigned int len)
{
    assert(net->bufsize - net->buffered >= len);
    memcpy(net->sendbuf + net->buffered, data, len);
    net->buffered += len;
}

void
send_hello(struct network *net)
{
    debugf("Sending hello to %s.\n", net->ifname);
    start_message(net, 20);
    accumulate_byte(net, 0);
    net->hello_seqno = ((net->hello_seqno + 1) & 0xFF);
    accumulate_byte(net, net->hello_seqno);
    accumulate_short(net, net->hello_interval);
    accumulate_data(net, myid, 16);
    schedule_flush(net);
    net->hello_time = now.tv_sec;
}

void
send_request(struct network *net, struct destination *dest)
{
    int i;

    if(net == NULL) {
        for(i = 0; i < numnets; i++)
            send_request(&nets[i], dest);
        return;
    }

    debugf("Sending request to %s for %s.\n",
           net->ifname, dest ? format_address(dest->address) : "::/0");
    start_message(net, 20);
    accumulate_byte(net, 1);
    accumulate_byte(net, 0);
    accumulate_short(net, 0);
    accumulate_data(net, dest ? dest->address : zeroes, 16);
    schedule_flush(net);
}

static void
send_unicast_packet(struct neighbour *neigh, unsigned char *buf, int buflen)
{
    struct sockaddr_in6 sin6;
    int rc;

    if(check_bucket(neigh->network)) {
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        memcpy(&sin6.sin6_addr, neigh->address, 16);
        sin6.sin6_port = htons(protocol_port);
        sin6.sin6_scope_id = neigh->network->ifindex;
        rc = babel_send(protocol_socket,
                        packet_header, sizeof(packet_header),
                        buf, buflen,
                        (struct sockaddr*)&sin6, sizeof(sin6));
        if(rc < 0)
            perror("send(unicast)");
    } else {
        fprintf(stderr, "Warning: bucket full, dropping packet to %s.\n",
                neigh->network->ifname);
    }
}


void
send_unicast_request(struct neighbour *neigh, struct destination *dest)
{
    unsigned char buf[20];

    debugf("Sending unicast request to %s (%s) for %s.\n",
           format_address(neigh->id),
           format_address(neigh->address),
           dest ? format_address(dest->address) : "::/0");

    buf[0] = 1;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    if(dest == NULL)
        memset(buf + 4, 0, 16);
    else
        memcpy(buf + 4, dest->address, 16);

    send_unicast_packet(neigh, buf, 20);
}

void
flushupdates(void)
{
    int i, j;

    if(updates > 0) {
        /* Ensure that we won't be recursively called by flushbuf. */
        int n = updates;
        struct network *net = update_net;
        updates = 0;
        update_net = NULL;

        debugf("  (flushing %d buffered updates)\n", n);
        for(i = 0; i < n; i++) {
            if(buffered_updates[i] == NULL) {
                start_message(net, MIN(20 + 20 * nummyxroutes, 1000));
                for(j = 0; j < nummyxroutes; j++) {
                    if(!myxroutes[j].installed)
                        continue;
                    if(net->bufsize - net->buffered < 40)
                        /* We cannot just call start_message, as this would
                           split the xroutes from the update.  Bail out
                           for now, and never mind the missing updates. */
                        break;
                    start_message(net, 20);
                    accumulate_byte(net, 4);
                    accumulate_byte(net, myxroutes[j].plen);
                    accumulate_short(net, myxroutes[j].cost);
                    accumulate_data(net, myxroutes[j].prefix, 16);
                }
                start_message(net, 20);
                accumulate_byte(net, 2);
                accumulate_byte(net, seqno);
                accumulate_short(net, 0);
                accumulate_data(net, myid, 16);
            } else {
                struct route *route;
                int seqno;
                int metric;
                route = find_installed_route(buffered_updates[i]);
                if(route) {
                    if(split_horizon && net->wired &&
                       route->nexthop->network == net)
                        continue;
                    seqno = route->seqno;
                    metric = MIN(route->metric + add_cost, INFINITY);
                } else {
                    seqno = buffered_updates[i]->seqno;
                    metric = INFINITY;
                }

                update_destination(buffered_updates[i], seqno, metric);

                /* Don't send xroutes if the metric is infinite as the seqno
                   might be originated by us. */
                if(metric < INFINITY) {
                    int numpxroutes;
                    numpxroutes = 0;
                    for(j = 0; j < numxroutes; j++) {
                        if(xroutes[j].gateway == buffered_updates[i])
                            numpxroutes++;
                    }
                    start_message(net, MIN(20 + 20 * numpxroutes, 1000));
                    for(j = 0; j < numxroutes; j++) {
                        if(xroutes[j].gateway != buffered_updates[i])
                            continue;
                        /* See comment above */
                        if(net->bufsize - net->buffered < 40)
                            break;
                        start_message(net, 20);
                        accumulate_byte(net, 4);
                        accumulate_byte(net, xroutes[j].plen);
                        accumulate_short(net, xroutes[j].cost);
                        accumulate_data(net, xroutes[j].prefix, 16);
                    }
                }
                start_message(net, 20);
                accumulate_byte(net, 2);
                accumulate_byte(net, seqno);
                accumulate_short(net, metric);
                accumulate_data(net, buffered_updates[i]->address, 16);
            }
        }
        schedule_flush_now(net);
        VALGRIND_MAKE_MEM_UNDEFINED(buffered_updates,
                                    MAX_BUFFERED_UPDATES *
                                    sizeof(struct destination));
    }
    update_flush_time.tv_sec = 0;
    update_flush_time.tv_usec = 0;
}

static void
schedule_update_flush(void)
{
    int msecs = update_jitter / 2 + random() % update_jitter;
    if(update_flush_time.tv_sec != 0 &&
       timeval_minus_msec(&update_flush_time, &now) < msecs)
        return;
    update_flush_time.tv_usec = (now.tv_usec + msecs * 1000) % 1000000;
    update_flush_time.tv_sec = now.tv_sec + (now.tv_usec / 1000 + msecs) / 1000;
}

static void
buffer_update(struct network *net, struct destination *dest)
{
    int i;

    if(update_net && update_net != net)
        flushupdates();

    update_net = net;

    for(i = 0; i < updates; i++)
        if(buffered_updates[i] == dest)
            return;

    if(updates >= MAX_BUFFERED_UPDATES)
        flushupdates();
    buffered_updates[updates++] = dest;
}

void
send_update(struct destination *dest, struct network *net)
{
    int i;

    if(net == NULL) {
        for(i = 0; i < numnets; i++)
            send_update(dest, &nets[i]);
        return;
    }

    if(parasitic ||
       (silent_time && now.tv_sec < reboot_time + silent_time)) {
        net->update_time = now.tv_sec;
        if(dest == NULL)
            send_self_update(net, 0);
        return;
    }

    silent_time = 0;

    if(dest) {
        if(updates >= net->bufsize / 20) {
            /* Update won't fit in a single packet -- send a full dump. */
            send_update(NULL, net);
            return;
        }
        debugf("Sending update to %s for %s.\n",
               net->ifname, format_address(dest->address));
        buffer_update(net, dest);
    } else {
        debugf("Sending update to %s for ::/0.\n", net->ifname);
        if(now.tv_sec - net->update_time < 2)
            return;
        for(i = 0; i < numroutes; i++)
            if(routes[i].installed)
                buffer_update(net, routes[i].dest);
        net->update_time = now.tv_sec;
        send_self_update(net, 0);
    }
    schedule_update_flush();
}

void
send_self_update(struct network *net, int force_seqno)
{
    if(force_seqno || seqno_time + seqno_interval < now.tv_sec) {
        seqno = ((seqno + 1) & 0xFF);
        seqno_time = now.tv_sec;
    }

    if(net == NULL) {
        int i;
        for(i = 0; i < numnets; i++)
            send_self_update(&nets[i], 0);
        return;
    }

    debugf("Sending self update to %s.\n", net->ifname);

    buffer_update(net, NULL);
    net->self_update_time = now.tv_sec;
    schedule_update_flush();
}

void
send_self_retract(struct network *net)
{
    if(net == NULL) {
        int i;
        for(i = 0; i < numnets; i++)
            send_self_retract(&nets[i]);
        return;
    }

    debugf("Retracting self on %s.\n", net->ifname);

    seqno = ((seqno + 1) & 0xFF);
    seqno_time = now.tv_sec;

    start_message(net, 20);
    accumulate_byte(net, 2);
    accumulate_byte(net, seqno);
    accumulate_short(net, 0xFFFF);
    accumulate_data(net, myid, 16);
    schedule_flush(net);
    net->self_update_time = now.tv_sec;
}

void
send_neighbour_update(struct neighbour *neigh, struct network *net)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].installed && routes[i].nexthop == neigh)
            send_update(routes[i].dest, net);
    }
    schedule_update_flush();
}

void
send_txcost(struct neighbour *neigh, struct network *net)
{
    int i;

    if(neigh == NULL && net == NULL) {
        for(i = 0; i < numnets; i++)
            send_txcost(NULL, &nets[i]);
        return;
    }

    if(neigh == NULL) {
        if(broadcast_txcost && net->wired) {
            debugf("Sending broadcast txcost to %s.\n", net->ifname);
            start_message(net, 20);
            accumulate_byte(net, 3);
            accumulate_byte(net, 0);
            accumulate_short(net, net->cost);
            accumulate_data(net, zeroes, 16);
            schedule_flush(net);
        } else {
            for(i = 0; i < numneighs; i++) {
                if(neighs[i].id[0] != 0) {
                    if(neighs[i].network == net)
                        send_txcost(&neighs[i], net);
                }
            }
        }
        net->txcost_time = now.tv_sec;
    } else {
        if(net && neigh->network != net)
            return;

        net = neigh->network;

        debugf("Sending txcost on %s to %s (%s).\n",
               neigh->network->ifname,
               format_address(neigh->id),
               format_address(neigh->address));

        start_message(net, 20);
        accumulate_byte(net, 3);
        accumulate_byte(net, 0);
        accumulate_short(net, neighbour_rxcost(neigh));
        accumulate_data(net, neigh->id, 16);
        schedule_flush(net);
    }
}


void
schedule_flush_now(struct network *net)
{
    int msecs = random() % 10;
    if(net->flush_time.tv_sec != 0 &&
       timeval_minus_msec(&net->flush_time, &now) < msecs)
        return;
    net->flush_time.tv_usec = (now.tv_usec + msecs * 1000) % 1000000;
    net->flush_time.tv_sec = now.tv_sec + (now.tv_usec / 1000 + msecs) / 1000;
}
