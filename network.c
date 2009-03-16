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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "babel.h"
#include "util.h"
#include "kernel.h"
#include "network.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "config.h"

struct network *networks = NULL;

static struct network *
last_network(void)
{
    struct network *net = networks;

    if(!net)
        return NULL;

    while(net->next)
        net = net->next;

    return net;
}

struct network *
add_network(char *ifname, struct network_conf *conf)
{
    struct network *net;

    if(conf) {
        if(strcmp(ifname, conf->ifname) != 0)
            return NULL;
    }

    FOR_ALL_NETS(net) {
        if(strcmp(net->ifname, ifname) == 0)
            return net;
    }

    net = malloc(sizeof(struct network));
    if(net == NULL)
        return NULL;

    memset(net, 0, sizeof(struct network));
    strncpy(net->ifname, ifname, IF_NAMESIZE);
    net->conf = conf;
    net->activity_time = now.tv_sec;
    net->bucket_time = now.tv_sec;
    net->bucket = BUCKET_TOKENS_MAX;
    net->hello_seqno = (random() & 0xFFFF);

    if(networks == NULL)
        networks = net;
    else
        last_network()->next = net;
    return net;
}

int
network_idle(struct network *net)
{
    return (idle_hello_interval > 0 &&
            net->activity_time < now.tv_sec - idle_time);
}

int
update_hello_interval(struct network *net)
{
    int rc = 0;

    if(network_idle(net)) {
        if(net->hello_interval != idle_hello_interval) {
            net->hello_interval = idle_hello_interval;
            rc = 1;
        }
    } else if((net->flags & NET_WIRED)) {
        if(net->hello_interval != wired_hello_interval) {
            net->hello_interval = wired_hello_interval;
            rc = 1;
        }
    } else {
        if(net->hello_interval != wireless_hello_interval) {
            net->hello_interval = wireless_hello_interval;
            rc = 1;
        }
    }

    net->self_update_interval =
        MAX(update_interval / 2, net->hello_interval);

    return rc;
}

/* This should be no more than half the hello interval, so that hellos
   aren't sent late.  The result is in milliseconds. */
unsigned
jitter(struct network *net, int urgent)
{
    unsigned interval = net->hello_interval;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return roughly(interval) / 4;
}

unsigned
update_jitter(struct network *net, int urgent)
{
    unsigned interval = net->hello_interval;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return roughly(interval);
}

void
delay_jitter(struct timeval *timeout, int msecs)
{
    timeval_plus_msec(timeout, &now, roughly(msecs));
}

static int
check_network_ipv4(struct network *net)
{
    unsigned char ipv4[4];
    int rc;

    if(net->ifindex > 0)
        rc = kernel_interface_ipv4(net->ifname, net->ifindex, ipv4);
    else
        rc = 0;

    if(rc > 0) {
        if(!net->ipv4 || memcmp(ipv4, net->ipv4, 4) != 0) {
            debugf("Noticed IPv4 change for %s.\n", net->ifname);
            if(!net->ipv4)
                net->ipv4 = malloc(4);
            if(net->ipv4)
                memcpy(net->ipv4, ipv4, 4);
            return 1;
        }
    } else {
        debugf("Noticed IPv4 change for %s.\n", net->ifname);
        if(net->ipv4) {
            free(net->ipv4);
            net->ipv4 = NULL;
            return 1;
        }
    }
    return 0;
}

int
network_up(struct network *net, int up)
{
    int mtu, rc, wired;
    struct ipv6_mreq mreq;

    if((!!up) == net_up(net))
        return 0;

    if(up)
        net->flags |= NET_UP;
    else
        net->flags &= ~NET_UP;

    if(up) {
        unsigned char ll[32][16];
        if(net->ifindex <= 0) {
            fprintf(stderr,
                    "Upping unknown interface %s.\n", net->ifname);
            return network_up(net, 0);
        }

        rc = kernel_setup_interface(1, net->ifname, net->ifindex);
        if(rc < 0) {
            fprintf(stderr, "kernel_setup_interface(%s, %d) failed.\n",
                    net->ifname, net->ifindex);
            return network_up(net, 0);
        }

        mtu = kernel_interface_mtu(net->ifname, net->ifindex);
        if(mtu < 0) {
            fprintf(stderr, "Warning: couldn't get MTU of interface %s (%d).\n",
                    net->ifname, net->ifindex);
            mtu = 1280;
        }

        /* We need to be able to fit at least two messages into a packet,
           so MTUs below 116 require lower layer fragmentation. */
        /* In IPv6, the minimum MTU is 1280, and every host must be able
           to reassemble up to 1500 bytes, but I'd rather not rely on this. */
        if(mtu < 128) {
            fprintf(stderr, "Suspiciously low MTU %d on interface %s (%d).\n",
                    mtu, net->ifname, net->ifindex);
            mtu = 128;
        }

        if(net->sendbuf)
            free(net->sendbuf);

        /* 40 for IPv6 header, 8 for UDP header, 12 for good luck. */
        net->bufsize = mtu - sizeof(packet_header) - 60;
        net->sendbuf = malloc(net->bufsize);
        if(net->sendbuf == NULL) {
            fprintf(stderr, "Couldn't allocate sendbuf.\n");
            net->bufsize = 0;
            return network_up(net, 0);
        }

        resize_receive_buffer(mtu);

        if(all_wireless) {
            wired = 0;
        } else {
            rc = kernel_interface_wireless(net->ifname, net->ifindex);
            if(rc < 0) {
                fprintf(stderr,
                        "Warning: couldn't determine whether %s (%d) "
                        "is a wireless interface.\n",
                        net->ifname, net->ifindex);
                wired = 0;
            } else {
                wired = !rc;
            }
        }

        if(wired) {
            net->flags |= NET_WIRED;
            net->cost = 96;
            if(split_horizon)
                net->flags |= NET_SPLIT_HORIZON;
        } else {
            net->flags &= ~NET_WIRED;
            net->cost = 256;
        }
        update_hello_interval(net);

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
        mreq.ipv6mr_interface = net->ifindex;

        rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0) {
            perror("setsockopt(IPV6_JOIN_GROUP)");
            /* This is probably due to a missing link-local address,
               so down this network, and wait until the main loop
               tries to up it again. */
            return network_up(net, 0);
        }

        if(net->ll)
            free(net->ll);
        net->numll = 0;
        net->ll = NULL;
        rc = kernel_ll_addresses(net->ifname, net->ifindex, ll, 32);
        if(rc < 0) {
            perror("kernel_ll_addresses");
        } else if(rc > 0) {
            net->ll = malloc(16 * rc);
            if(net->ll == NULL) {
                perror("malloc(ll)");
            } else {
                net->numll = rc;
                memcpy(net->ll, ll, rc * 16);
            }
        }
        delay_jitter(&net->hello_timeout, net->hello_interval);
        delay_jitter(&net->self_update_timeout, net->self_update_interval);
        delay_jitter(&net->update_timeout, update_interval);
        send_hello(net);
        send_request(net, NULL, 0);
    } else {
        net->buffered = 0;
        net->bufsize = 0;
        free(net->sendbuf);
        net->num_buffered_updates = 0;
        net->update_bufsize = 0;
        if(net->buffered_updates)
            free(net->buffered_updates);
        net->buffered_updates = NULL;
        net->sendbuf = NULL;
        if(net->ifindex > 0) {
            memset(&mreq, 0, sizeof(mreq));
            memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
            mreq.ipv6mr_interface = net->ifindex;
            rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                            (char*)&mreq, sizeof(mreq));
            if(rc < 0)
                perror("setsockopt(IPV6_LEAVE_GROUP)");
            kernel_setup_interface(0, net->ifname, net->ifindex);
        }
        if(net->ll)
            free(net->ll);
        net->ll = NULL;
        net->numll = 0;
    }

    update_network_metric(net);
    rc = check_network_ipv4(net);
    if(up && rc > 0)
        send_update(net, 0, NULL, 0);

    return 1;
}

int
network_ll_address(struct network *net, const unsigned char *address)
{
    int i;

    if(!net_up(net))
        return 0;

    for(i = 0; i < net->numll; i++)
        if(memcmp(net->ll[i], address, 16) == 0)
           return 1;

    return 0;
}

void
check_networks(void)
{
    struct network *net;
    int rc, ifindex, ifindex_changed = 0;

    FOR_ALL_NETS(net) {
        ifindex = if_nametoindex(net->ifname);
        if(ifindex != net->ifindex) {
            debugf("Noticed ifindex change for %s.\n", net->ifname);
            net->ifindex = 0;
            network_up(net, 0);
            net->ifindex = ifindex;
            ifindex_changed = 1;
        }

        if(net->ifindex > 0)
            rc = kernel_interface_operational(net->ifname, net->ifindex);
        else
            rc = 0;
        if((rc > 0) != net_up(net)) {
            debugf("Noticed status change for %s.\n", net->ifname);
            network_up(net, rc > 0);
        }

        rc = check_network_ipv4(net);
        if(rc > 0) {
            send_request(net, NULL, 0);
            send_update(net, 0, NULL, 0);
         }
    }

    if(ifindex_changed)
        renumber_filters();
}
