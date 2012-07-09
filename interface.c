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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "babeld.h"
#include "util.h"
#include "kernel.h"
#include "interface.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "configuration.h"

struct interface *interfaces = NULL;

static struct interface *
last_interface(void)
{
    struct interface *ifp = interfaces;

    if(!ifp)
        return NULL;

    while(ifp->next)
        ifp = ifp->next;

    return ifp;
}

struct interface *
add_interface(char *ifname, struct interface_conf *if_conf)
{
    struct interface *ifp;

    assert(!if_conf || strcmp(ifname, if_conf->ifname) == 0);

    FOR_ALL_INTERFACES(ifp) {
        if(strcmp(ifp->name, ifname) == 0) {
            assert(if_conf == NULL);
            return ifp;
        }
    }

    ifp = malloc(sizeof(struct interface));
    if(ifp == NULL)
        return NULL;

    memset(ifp, 0, sizeof(struct interface));
    strncpy(ifp->name, ifname, IF_NAMESIZE);
    ifp->conf = if_conf;
    ifp->bucket_time = now.tv_sec;
    ifp->bucket = BUCKET_TOKENS_MAX;
    ifp->hello_seqno = (random() & 0xFFFF);

    if(interfaces == NULL)
        interfaces = ifp;
    else
        last_interface()->next = ifp;

    return ifp;
}

/* This should be no more than half the hello interval, so that hellos
   aren't sent late.  The result is in milliseconds. */
unsigned
jitter(struct interface *ifp, int urgent)
{
    unsigned interval = ifp->hello_interval;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return roughly(interval) / 4;
}

unsigned
update_jitter(struct interface *ifp, int urgent)
{
    unsigned interval = ifp->hello_interval;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return roughly(interval);
}

void
set_timeout(struct timeval *timeout, int msecs)
{
    timeval_add_msec(timeout, &now, roughly(msecs));
}

static int
check_interface_ipv4(struct interface *ifp)
{
    unsigned char ipv4[4];
    int rc;

    if(ifp->ifindex > 0)
        rc = kernel_interface_ipv4(ifp->name, ifp->ifindex, ipv4);
    else
        rc = 0;

    if(rc > 0) {
        if(!ifp->ipv4 || memcmp(ipv4, ifp->ipv4, 4) != 0) {
            debugf("Noticed IPv4 change for %s.\n", ifp->name);
            flush_interface_routes(ifp, 0);
            if(!ifp->ipv4)
                ifp->ipv4 = malloc(4);
            if(ifp->ipv4)
                memcpy(ifp->ipv4, ipv4, 4);
            return 1;
        }
    } else {
        if(ifp->ipv4) {
            debugf("Noticed IPv4 change for %s.\n", ifp->name);
            flush_interface_routes(ifp, 0);
            free(ifp->ipv4);
            ifp->ipv4 = NULL;
            return 1;
        }
    }
    return 0;
}

static int
check_interface_channel(struct interface *ifp)
{
    int channel = IF_CONF(ifp, channel);

    if(channel == IF_CHANNEL_UNKNOWN) {
        if((ifp->flags & IF_WIRED)) {
            channel = IF_CHANNEL_NONINTERFERING;
        } else {
            channel = kernel_interface_channel(ifp->name, ifp->ifindex);
            if(channel < 0)
                fprintf(stderr,
                        "Couldn't determine channel of interface %s: %s.\n",
                       ifp->name, strerror(errno));
            if(channel <= 0)
                channel = IF_CHANNEL_INTERFERING;
        }
    }

    if(ifp->channel != channel) {
        ifp->channel = channel;
        return 1;
    }
    return 0;
}

int
interface_up(struct interface *ifp, int up)
{
    int mtu, rc, wired;
    struct ipv6_mreq mreq;

    if((!!up) == if_up(ifp))
        return 0;

    if(up)
        ifp->flags |= IF_UP;
    else
        ifp->flags &= ~IF_UP;

    if(up) {
        struct kernel_route ll[32];
        if(ifp->ifindex <= 0) {
            fprintf(stderr,
                    "Upping unknown interface %s.\n", ifp->name);
            return interface_up(ifp, 0);
        }

        rc = kernel_setup_interface(1, ifp->name, ifp->ifindex);
        if(rc < 0) {
            fprintf(stderr, "kernel_setup_interface(%s, %d) failed.\n",
                    ifp->name, ifp->ifindex);
            return interface_up(ifp, 0);
        }

        mtu = kernel_interface_mtu(ifp->name, ifp->ifindex);
        if(mtu < 0) {
            fprintf(stderr, "Warning: couldn't get MTU of interface %s (%d).\n",
                    ifp->name, ifp->ifindex);
            mtu = 1280;
        }

        /* We need to be able to fit at least two messages into a packet,
           so MTUs below 116 require lower layer fragmentation. */
        /* In IPv6, the minimum MTU is 1280, and every host must be able
           to reassemble up to 1500 bytes, but I'd rather not rely on this. */
        if(mtu < 128) {
            fprintf(stderr, "Suspiciously low MTU %d on interface %s (%d).\n",
                    mtu, ifp->name, ifp->ifindex);
            mtu = 128;
        }

        if(ifp->sendbuf)
            free(ifp->sendbuf);

        /* 40 for IPv6 header, 8 for UDP header, 12 for good luck. */
        ifp->bufsize = mtu - sizeof(packet_header) - 60;
        ifp->sendbuf = malloc(ifp->bufsize);
        if(ifp->sendbuf == NULL) {
            fprintf(stderr, "Couldn't allocate sendbuf.\n");
            ifp->bufsize = 0;
            return interface_up(ifp, 0);
        }

        rc = resize_receive_buffer(mtu);
        if(rc < 0)
            fprintf(stderr, "Warning: couldn't resize "
                    "receive buffer for interface %s (%d) (%d bytes).\n",
                    ifp->name, ifp->ifindex, mtu);

        if(IF_CONF(ifp, wired) == CONFIG_NO) {
            wired = 0;
        } else if(IF_CONF(ifp, wired) == CONFIG_YES) {
            wired = 1;
        } else if(all_wireless) {
            wired = 0;
        } else {
            rc = kernel_interface_wireless(ifp->name, ifp->ifindex);
            if(rc < 0) {
                fprintf(stderr,
                        "Warning: couldn't determine whether %s (%d) "
                        "is a wireless interface.\n",
                        ifp->name, ifp->ifindex);
                wired = 0;
            } else {
                wired = !rc;
            }
        }

        if(wired) {
            ifp->flags |= IF_WIRED;
            ifp->cost = IF_CONF(ifp, cost);
            if(ifp->cost <= 0) ifp->cost = 96;
            if(IF_CONF(ifp, split_horizon) == CONFIG_NO)
                ifp->flags &= ~IF_SPLIT_HORIZON;
            else if(IF_CONF(ifp, split_horizon) == CONFIG_YES)
                ifp->flags |= IF_SPLIT_HORIZON;
            else if(split_horizon)
                ifp->flags |= IF_SPLIT_HORIZON;
            else
                ifp->flags &= ~IF_SPLIT_HORIZON;
            if(IF_CONF(ifp, lq) == CONFIG_YES)
                ifp->flags |= IF_LQ;
            else
                ifp->flags &= ~IF_LQ;
        } else {
            ifp->flags &= ~IF_WIRED;
            ifp->cost = IF_CONF(ifp, cost);
            if(ifp->cost <= 0) ifp->cost = 256;
            if(IF_CONF(ifp, split_horizon) == CONFIG_YES)
                ifp->flags |= IF_SPLIT_HORIZON;
            else
                ifp->flags &= ~IF_SPLIT_HORIZON;
            if(IF_CONF(ifp, lq) == CONFIG_NO)
                ifp->flags &= ~IF_LQ;
            else
                ifp->flags |= IF_LQ;
        }

        if(IF_CONF(ifp, faraway) == CONFIG_YES)
            ifp->flags |= IF_FARAWAY;

        if(IF_CONF(ifp, hello_interval) > 0)
            ifp->hello_interval = IF_CONF(ifp, hello_interval);
        else if((ifp->flags & IF_WIRED))
            ifp->hello_interval = default_wired_hello_interval;
        else
            ifp->hello_interval = default_wireless_hello_interval;

        ifp->update_interval =
            IF_CONF(ifp, update_interval) > 0 ?
            IF_CONF(ifp, update_interval) :
           ifp->hello_interval * 4;

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
        mreq.ipv6mr_interface = ifp->ifindex;

        rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0) {
            perror("setsockopt(IPV6_JOIN_GROUP)");
            /* This is probably due to a missing link-local address,
               so down this interface, and wait until the main loop
               tries to up it again. */
            return interface_up(ifp, 0);
        }

        if(ifp->ll)
            free(ifp->ll);
        ifp->numll = 0;
        ifp->ll = NULL;
        rc = kernel_addresses(ifp->name, ifp->ifindex, 1, ll, 32);
        if(rc < 0) {
            perror("kernel_ll_addresses");
        } else if(rc > 0) {
            ifp->ll = malloc(16 * rc);
            if(ifp->ll == NULL) {
                perror("malloc(ll)");
            } else {
                int i;
                for(i = 0; i < rc; i++)
                    memcpy(ifp->ll[i], ll[i].prefix, 16);
                ifp->numll = rc;
            }
        }
        check_interface_channel(ifp);
        update_interface_metric(ifp);
        rc = check_interface_ipv4(ifp);

        debugf("Upped interface %s (%s, cost=%d, channel=%d%s).\n",
               ifp->name,
               (ifp->flags & IF_WIRED) ? "wired" : "wireless",
               ifp->cost,
               ifp->channel,
               ifp->ipv4 ? ", IPv4" : "");

        set_timeout(&ifp->hello_timeout, ifp->hello_interval);
        set_timeout(&ifp->update_timeout, ifp->update_interval);
        send_hello(ifp);
        if(rc > 0)
            send_update(ifp, 0, NULL, 0);
        send_request(ifp, NULL, 0);
    } else {
        flush_interface_routes(ifp, 0);
        ifp->buffered = 0;
        ifp->bufsize = 0;
        free(ifp->sendbuf);
        ifp->num_buffered_updates = 0;
        ifp->update_bufsize = 0;
        if(ifp->buffered_updates)
            free(ifp->buffered_updates);
        ifp->buffered_updates = NULL;
        ifp->sendbuf = NULL;
        if(ifp->ifindex > 0) {
            memset(&mreq, 0, sizeof(mreq));
            memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
            mreq.ipv6mr_interface = ifp->ifindex;
            rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                            (char*)&mreq, sizeof(mreq));
            if(rc < 0)
                perror("setsockopt(IPV6_LEAVE_GROUP)");
            kernel_setup_interface(0, ifp->name, ifp->ifindex);
        }
        if(ifp->ll)
            free(ifp->ll);
        ifp->ll = NULL;
        ifp->numll = 0;
    }

    return 1;
}

int
interface_ll_address(struct interface *ifp, const unsigned char *address)
{
    int i;

    if(!if_up(ifp))
        return 0;

    for(i = 0; i < ifp->numll; i++)
        if(memcmp(ifp->ll[i], address, 16) == 0)
           return 1;

    return 0;
}

void
check_interfaces(void)
{
    struct interface *ifp;
    int rc, ifindex_changed = 0;
    unsigned int ifindex;

    FOR_ALL_INTERFACES(ifp) {
        ifindex = if_nametoindex(ifp->name);
        if(ifindex != ifp->ifindex) {
            debugf("Noticed ifindex change for %s.\n", ifp->name);
            ifp->ifindex = 0;
            interface_up(ifp, 0);
            ifp->ifindex = ifindex;
            ifindex_changed = 1;
        }

        if(ifp->ifindex > 0)
            rc = kernel_interface_operational(ifp->name, ifp->ifindex);
        else
            rc = 0;
        if((rc > 0) != if_up(ifp)) {
            debugf("Noticed status change for %s.\n", ifp->name);
            interface_up(ifp, rc > 0);
        }

        if(if_up(ifp)) {
            check_interface_channel(ifp);
            rc = check_interface_ipv4(ifp);
            if(rc > 0) {
                send_request(ifp, NULL, 0);
                send_update(ifp, 0, NULL, 0);
            }
        }
    }

    if(ifindex_changed)
        renumber_filters();
}
