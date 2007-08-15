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
#include "source.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"

struct timeval update_flush_time = {0, 0};

const unsigned char packet_header[8] = {42, 1};

unsigned int jitter;
unsigned int update_jitter;
int add_cost = 0;
int parasitic = 0;
int silent_time = 30;
int broadcast_ihu = 0;
int split_horizon = 1;

unsigned short myseqno = 0;
int seqno_time = 0;
int seqno_interval = -1;

struct buffered_update {
    unsigned char prefix[16];
    unsigned char plen;
};
struct buffered_update buffered_updates[MAX_BUFFERED_UPDATES];
struct network *update_net = NULL;
int updates = 0;

void
parse_packet(const unsigned char *from, struct network *net,
             const unsigned char *packet, int len)
{
    int i, j;
    const unsigned char *message;
    unsigned char type, plen;
    unsigned short seqno;
    unsigned short metric;
    const unsigned char *address;
    struct neighbour *neigh;
    int have_current_source = 0;
    unsigned char current_source[16];

    if(from[0] != 0xFE || (from[1] & 0xC0) != 0x80) {
        fprintf(stderr, "Received packet from non-local address %s.\n",
                format_address(from));
        return;
    }

    if(packet[0] != 42) {
        fprintf(stderr, "Received malformed packet on %s from %s.\n",
                net->ifname, format_address(from));
        return;
    }

    if(packet[1] != 1) {
        fprintf(stderr,
                "Received packet with unknown version %d on %s from %s.\n",
                packet[1], net->ifname, format_address(from));
        return;
    }

    if(len % 24 != 8) {
        fprintf(stderr, "Received malformed packet on %s from %s.\n",
                net->ifname, format_address(from));
        return;
    }

    j = 0;
    for(i = 0; i < (len - 8) / 24; i++) {
        message = packet + 8 + 24 * i;
        type = message[0];
        plen = message[1];
        seqno = ntohs(*(uint16_t*)(message + 4));
        metric = ntohs(*(uint16_t*)(message + 6));
        address = message + 8;
        if(type == 0) {
            int changed;
            if(memcmp(address, myid, 16) == 0)
                continue;
            debugf("Received hello on %s from %s (%s).\n",
                   net->ifname,
                   format_address(address),
                   format_address(from));
            net->activity_time = now.tv_sec;
            neigh = add_neighbour(address, from, net);
            if(neigh == NULL)
                continue;
            changed = update_neighbour(neigh, seqno, metric);
            if(changed)
                update_neighbour_metric(neigh);
        } else {
            neigh = find_neighbour(from, net);
            if(neigh == NULL)
                continue;
            net->activity_time = now.tv_sec;
            if(type == 1) {
                debugf("Received ihu for %s from %s (%s).\n",
                       format_address(address),
                       format_address(neigh->id),
                       format_address(from));
                if(plen == 0xFF || memcmp(myid, address, 16) == 0) {
                    neigh->txcost = metric;
                    neigh->ihu_time = now.tv_sec;
                    update_neighbour_metric(neigh);
                }
            } else if(type == 2) {
                debugf("Received request on %s from %s (%s) for %s "
                       "(%d hops).\n",
                       net->ifname,
                       format_address(neigh->id),
                       format_address(from),
                       plen == 0xFF ?
                       "any" :
                       format_prefix(address, plen),
                       metric);
                if(plen == 0xFF) {
                    /* If a neighbour is requesting a full route dump from us,
                       we might as well send it an ihu. */
                    send_ihu(neigh, NULL);
                    send_update(neigh->network, NULL, 0);
                } else {
                    send_update(neigh->network, address, plen);
                }
            } else if(type == 3) {
                if(plen == 0xFF)
                    debugf("Received update for %s/none on %s from %s (%s).\n",
                           format_address(message + 8),
                           net->ifname,
                           format_address(neigh->id),
                           format_address(from));
                else
                    debugf("Received update for %s on %s from %s (%s).\n",
                           format_prefix(message + 8, plen),
                           net->ifname,
                           format_address(neigh->id),
                           format_address(from));
                memcpy(current_source, address, 16);
                have_current_source = 1;
                if(memcmp(address, myid, 16) == 0)
                    continue;
                if(plen <= 128)
                    update_route(address, mask_prefix(address, plen), plen,
                                 seqno, metric, neigh);
            } else if(type == 4) {
                debugf("Received prefix %s on %s from %s (%s).\n",
                       format_prefix(address, plen),
                       net->ifname,
                       format_address(neigh->id),
                       format_address(from));
                if(!have_current_source) {
                    fprintf(stderr, "Received prefix with no source "
                            "on %s from %s (%s).\n",
                            net->ifname,
                            format_address(neigh->id),
                            format_address(from));
                    continue;
                }
                if(memcmp(current_source, myid, 16) == 0)
                    continue;
                update_route(current_source, mask_prefix(address, plen), plen,
                             seqno, metric, neigh);
            } else {
                debugf("Received unknown packet type %d from %s (%s).\n",
                       type, format_address(neigh->id), format_address(from));
            }
        }
    }
    return;
}

/* Under normal circumstances, there are enough moderation mechanisms
   elsewhere in the protocol to make sure that this last-ditch check
   should never trigger.  But I'm supersticious. */

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

    assert(net->buffered <= net->bufsize);

    if(update_net == net)
        flushupdates();

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

static void
start_message(struct network *net, int bytes)
{
    assert(net->buffered % 8 == 0);
    if(net->bufsize - net->buffered < bytes)
        flushbuf(net);
}

static void
accumulate_byte(struct network *net, unsigned char byte)
{
    net->sendbuf[net->buffered] = byte;
    net->buffered++;
}

static void
accumulate_short(struct network *net, unsigned short s)
{
    *(uint16_t *)(net->sendbuf + net->buffered) = htons(s);
    net->buffered += 2;
}

static void
accumulate_data(struct network *net,
                const unsigned char *data, unsigned int len)
{
    memcpy(net->sendbuf + net->buffered, data, len);
    net->buffered += len;
}

static void
send_message(struct network *net,
             unsigned char type,  unsigned char plen,
             unsigned short seqno, unsigned short metric,
             const unsigned char *address)
{
    start_message(net, 24);
    accumulate_byte(net, type);
    accumulate_byte(net, plen);
    accumulate_short(net, 0);
    accumulate_short(net, seqno);
    accumulate_short(net, metric);
    accumulate_data(net, address, 16);
    schedule_flush(net);
}

static const unsigned char *
message_source_id(struct network *net)
{
    int i;
    assert(net->buffered % 24 == 0);

    i = net->buffered / 24 - 1;
    while(i >= 0) {
        const unsigned char *message;
        message = (const unsigned char*)(net->sendbuf + i * 24);
        if(message[0] == 3)
            return message + 8;
        else if(message[0] == 4)
            i--;
        else
            break;
    }

    return NULL;
}

void
send_hello(struct network *net)
{
    debugf("Sending hello to %s.\n", net->ifname);
    update_hello_interval(net);
    net->hello_seqno = ((net->hello_seqno + 1) & 0xFFFF);
    net->hello_time = now.tv_sec;
    send_message(net, 0, 0, net->hello_seqno,
                 100 * net->hello_interval > 0xFFFF ?
                 0 : 100 * net->hello_interval,
                 myid);
}

void
send_request(struct network *net,
             const unsigned char *prefix, unsigned char plen)
{
    int i;

    if(net == NULL) {
        for(i = 0; i < numnets; i++)
            send_request(&nets[i], prefix, plen);
        return;
    }

    debugf("Sending request to %s for %s.\n",
           net->ifname, prefix ? format_prefix(prefix, plen) : "any");
    if(prefix)
        send_message(net, 2, plen, 0, 0, prefix);
    else
        send_message(net, 2, 0xFF, 0, 0, ones);
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
send_unicast_request(struct neighbour *neigh,
                     const unsigned char *prefix, unsigned char plen)
{
    unsigned char buf[24];

    debugf("Sending unicast request to %s (%s) for %s.\n",
           format_address(neigh->id),
           format_address(neigh->address),
           prefix ? format_prefix(prefix, plen) : "any");

    memset(buf, 0, 24);
    buf[0] = 1;
    if(prefix) {
        memcpy(buf + 8, prefix, 16);
        buf[7] = plen;
    } else {
        memcpy(buf + 8, ones, 16);
        buf[7] = 0xFF;
    }
    send_unicast_packet(neigh, buf, 24);
}

static void
really_send_update(struct network *net,
                   const unsigned char *address,
                   const unsigned char *prefix, unsigned char plen,
                   unsigned short seqno, unsigned short metric)
{
    if(in_prefix(address, prefix, plen)) {
        send_message(net, 3, plen, seqno, metric, address);
    } else {
        unsigned const char *sid;
        start_message(net, 48);
        sid = message_source_id(net);
        if(sid == NULL || memcmp(address, sid, 16) != 0)
            send_message(net, 3, 0xFF, 0, 0xFFFF, address);
        send_message(net, 4, plen, seqno, metric, prefix);
    }
}

void
flushupdates(void)
{
    int i;

    if(updates > 0) {
        /* Ensure that we won't be recursively called by flushbuf. */
        int n = updates;
        struct network *net = update_net;
        updates = 0;
        update_net = NULL;

        debugf("  (flushing %d buffered updates)\n", n);

        for(i = 0; i < n; i++) {
            struct xroute *xroute;
            struct route *route;
            struct source *src;
            unsigned short seqno;
            unsigned short metric;
            xroute = find_exported_xroute(buffered_updates[i].prefix,
                                          buffered_updates[i].plen);
            if(xroute) {
                really_send_update(net, myid,
                                   xroute->prefix, xroute->plen,
                                   myseqno, xroute->metric);
                continue;
            }
            route = find_installed_route(buffered_updates[i].prefix,
                                         buffered_updates[i].plen);
            if(route) {
                if(split_horizon &&
                   net->wired && route->nexthop->network == net)
                    continue;
                seqno = route->seqno;
                metric = MIN((int)route->metric + add_cost, INFINITY);
                really_send_update(net, route->src->address,
                                   route->src->prefix,
                                   route->src->plen,
                                   seqno, metric);
                update_source(route->src, seqno, metric);
                continue;
            }
            src = find_recent_source(buffered_updates[i].prefix,
                                     buffered_updates[i].plen);
            if(src) {
                really_send_update(net, src->address, src->prefix, src->plen,
                                   src->metric >= INFINITY ?
                                   src->seqno : (src->seqno + 1) & 0xFFFF,
                                   INFINITY);
                continue;
            }
        }
        schedule_flush_now(net);
        VALGRIND_MAKE_MEM_UNDEFINED(&buffered_updates,
                                    sizeof(buffered_updates));
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
buffer_update(struct network *net,
              const unsigned char *prefix, unsigned char plen)
{
    int i;

    if(update_net && update_net != net)
        flushupdates();

    update_net = net;

    for(i = 0; i < updates; i++) {
        if(buffered_updates[i].plen == plen &&
           memcmp(buffered_updates[i].prefix, prefix, 16) == 0)
            return;
    }

    if(updates >= MAX_BUFFERED_UPDATES)
        flushupdates();
    memcpy(buffered_updates[updates].prefix, prefix, 16);
    buffered_updates[updates].plen = plen;
    updates++;
}

void
send_update(struct network *net,
            const unsigned char *prefix, unsigned char plen)
{
    int i;

    if(net == NULL) {
        for(i = 0; i < numnets; i++)
            send_update(&nets[i], prefix, plen);
        return;
    }

    if(parasitic || (silent_time && now.tv_sec < reboot_time + silent_time)) {
        if(prefix == NULL) {
            send_self_update(net, 0);
            net->update_time = now.tv_sec;
        } else if(find_exported_xroute(prefix, plen)) {
            buffer_update(net, prefix, plen);
        }
        return;
    }

    silent_time = 0;

    if(prefix) {
        if(updates > net->bufsize / 24 - 2) {
            /* Update won't fit in a single packet -- send a full dump. */
            send_update(net, NULL, 0);
            return;
        }
        debugf("Sending update to %s for %s.\n",
               net->ifname, format_prefix(prefix, plen));
        buffer_update(net, prefix, plen);
    } else {
        send_self_update(net, 0);
        if(now.tv_sec - net->update_time < 1)
            return;
        debugf("Sending update to %s for any.\n", net->ifname);
        for(i = 0; i < numroutes; i++)
            if(routes[i].installed)
                buffer_update(net, routes[i].src->prefix, routes[i].src->plen);
        net->update_time = now.tv_sec;
    }
    schedule_update_flush();
}

void
send_self_update(struct network *net, int force_seqno)
{
    int i;
    if(force_seqno || seqno_time + seqno_interval < now.tv_sec) {
        myseqno = ((myseqno + 1) & 0xFFFF);
        seqno_time = now.tv_sec;
    }

    if(net == NULL) {
        for(i = 0; i < numnets; i++)
            send_self_update(&nets[i], 0);
        return;
    }

    debugf("Sending self update to %s.\n", net->ifname);

    net->self_update_time = now.tv_sec;

    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].exported)
            send_update(net, xroutes[i].prefix, xroutes[i].plen);
    }
    schedule_update_flush();
}

void
send_self_retract(struct network *net)
{
    int i;

    if(net == NULL) {
        int i;
        for(i = 0; i < numnets; i++)
            send_self_retract(&nets[i]);
        return;
    }

    flushupdates();

    debugf("Retracting self on %s.\n", net->ifname);

    myseqno = ((myseqno + 1) & 0xFFFF);
    seqno_time = now.tv_sec;
    net->self_update_time = now.tv_sec;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].exported)
            really_send_update(net, myid, xroutes[i].prefix, xroutes[i].plen,
                               myseqno, 0xFFFF);
    }
}

void
send_neighbour_update(struct neighbour *neigh, struct network *net)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].installed && routes[i].nexthop == neigh)
            send_update(net, routes[i].src->prefix, routes[i].src->plen);
    }
}

void
send_ihu(struct neighbour *neigh, struct network *net)
{
    int i;

    if(neigh == NULL && net == NULL) {
        for(i = 0; i < numnets; i++)
            send_ihu(NULL, &nets[i]);
        return;
    }

    if(neigh == NULL) {
        if(broadcast_ihu && net->wired) {
            debugf("Sending broadcast ihu to %s.\n", net->ifname);
            send_message(net, 1, 0xFF, 0, net->cost, ones);
        } else {
            for(i = 0; i < numneighs; i++) {
                if(neighs[i].id[0] != 0xFF) {
                    if(neighs[i].network == net)
                        send_ihu(&neighs[i], net);
                }
            }
        }
        net->ihu_time = now.tv_sec;
    } else {
        int rxcost;

        if(net && neigh->network != net)
            return;

        net = neigh->network;

        debugf("Sending ihu on %s to %s (%s).\n",
               neigh->network->ifname,
               format_address(neigh->id),
               format_address(neigh->address));

        rxcost = neighbour_rxcost(neigh);
        send_message(net, 1, 128, 0, rxcost, neigh->id);
    }
}
