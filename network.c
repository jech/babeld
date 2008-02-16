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
#include "filter.h"

struct network nets[MAXNETS];
int numnets = 0;

struct network *
add_network(char *ifname)
{
    if(numnets >= MAXNETS) {
        fprintf(stderr, "Too many networks.\n");
        return NULL;
    }

    memset(nets + numnets, 0, sizeof(struct network));
    nets[numnets].up = 0;
    nets[numnets].ifindex = 0;
    nets[numnets].ipv4 = NULL;
    nets[numnets].activity_time = now.tv_sec;
    nets[numnets].bufsize = 0;
    strncpy(nets[numnets].ifname, ifname, IF_NAMESIZE);
    nets[numnets].sendbuf = NULL;
    nets[numnets].buffered = 0;
    nets[numnets].bucket_time = now.tv_sec;
    nets[numnets].bucket = 0;
    nets[numnets].hello_interval = 10000;
    nets[numnets].hello_seqno = (random() & 0xFFFF);
    numnets++;
    return &nets[numnets - 1];
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
    } else if(net->wired) {
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

    if(net->ihu_interval != 3 * net->hello_interval) {
        net->ihu_interval = 3 * net->hello_interval;
        rc = 1;
    }

    net->self_update_interval =
        MAX(15 + net->hello_interval / 2, net->hello_interval);

    return rc;
}

/* This should be no more than half the hello interval, so that hellos
   aren't sent late.  The result is in milliseconds. */
unsigned int
jitter(struct network *net)
{
    unsigned interval = net->hello_interval * 1000;
    interval = MIN(interval, 2000);
    return (interval / 2 + random() % interval) / 4;
}

unsigned int
update_jitter(struct network *net, int urgent)
{
    unsigned interval = net->hello_interval * 1000;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return (interval / 2 + random() % interval);
}

int
network_up(struct network *net, int up)
{
    int mtu, rc, wired;
    struct ipv6_mreq mreq;

    if(up == net->up)
        return 0;

    net->up = up;

    if(up) {
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
        /* 40 for IPv6 header, 8 for UDP header, 12 for good luck. */
        mtu -= 60;

        if(net->sendbuf)
            free(net->sendbuf);
        net->bufsize = mtu - sizeof(packet_header);
        net->sendbuf = malloc(net->bufsize);
        if(net->sendbuf == NULL) {
            fprintf(stderr, "Couldn't allocate sendbuf.\n");
            net->bufsize = 0;
            return network_up(net, 0);
        }

        if(all_wireless) {
            wired = 1;
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

        net->wired = wired;
        net->cost = wired ? 128 : 256;
        update_hello_interval(net);

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
        mreq.ipv6mr_interface = net->ifindex;

        rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0) {
            perror("setsockopt(IPV6_JOIN_GROUP)");
            /* But don't bail out for now. */
        }
    } else {
        net->buffered = 0;
        net->bufsize = 0;
        free(net->sendbuf);
        net->sendbuf = NULL;
        if(net->ifindex > 0) {
            memset(&mreq, 0, sizeof(mreq));
            memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
            mreq.ipv6mr_interface = net->ifindex;
            rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                            (char*)&mreq, sizeof(mreq));
            if(rc < 0) {
                perror("setsockopt(IPV6_LEAVE_GROUP)");
            }
            kernel_setup_interface(0, net->ifname, net->ifindex);
        }
    }

    if(!up)
        flush_network_routes(net);

    return 1;
}

void
check_networks(void)
{
    int i, rc, ifindex, changed = 0, ifindex_changed = 0;
    unsigned char ipv4[4];

    for(i = 0; i < numnets; i++) {
        ifindex = if_nametoindex(nets[i].ifname);
        if(ifindex != nets[i].ifindex) {
            debugf("Noticed ifindex change for %s.\n", nets[i].ifname);
            network_up(&nets[i], 0);
            nets[i].ifindex = ifindex;
            changed = 1;
            ifindex_changed = 1;
        }

        if(nets[i].ifindex > 0)
            rc = kernel_interface_operational(nets[i].ifname, nets[i].ifindex);
        else
            rc = 0;
        if((rc > 0) != nets[i].up) {
            debugf("Noticed status change for %s.\n", nets[i].ifname);
            network_up(&nets[i], rc > 0);
            if(rc > 0)
                send_request(&nets[i], NULL, 0, 0, 0, 0);
            changed = 1;
        }
    }

    if(changed)
        send_update(NULL, 0, NULL, 0);

    if(ifindex_changed)
        renumber_filters();
}
