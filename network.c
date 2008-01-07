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

#include "babel.h"
#include "util.h"
#include "kernel.h"
#include "network.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"

struct network nets[MAXNETS];
int numnets = 0;

struct network *
add_network(char *ifname, int ifindex, int mtu, int wired, unsigned int cost)
{
    void *p;
    unsigned char ipv4[4];
    int rc;

    if(numnets >= MAXNETS) {
        fprintf(stderr, "Too many networks.\n");
        return NULL;
    }

    memset(nets + numnets, 0, sizeof(struct network));
    nets[numnets].up = (kernel_interface_operational(ifname, ifindex) > 0);
    nets[numnets].ifindex = ifindex;
    nets[numnets].ipv4 = NULL;
    if(do_ipv4) {
        rc = kernel_interface_ipv4(ifname, ifindex, ipv4);
        if(rc >= 0) {
            nets[numnets].ipv4 = malloc(4);
            if(nets[numnets].ipv4)
                memcpy(nets[numnets].ipv4, ipv4, 4);
        }
    }

    nets[numnets].wired = wired;
    nets[numnets].cost = cost;
    nets[numnets].activity_time = now.tv_sec;
    update_hello_interval(&nets[numnets]);
    nets[numnets].bufsize = mtu - sizeof(packet_header);
    strncpy(nets[numnets].ifname, ifname, IF_NAMESIZE);
    p = malloc(nets[numnets].bufsize);
    if(p == NULL) {
        perror("malloc");
        return NULL;
    }
    nets[numnets].sendbuf = p;
    nets[numnets].buffered = 0;
    nets[numnets].bucket_time = now.tv_sec;
    nets[numnets].bucket = 0;
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
    return (interval / 2 + random() % interval) / 4;
}

unsigned int
update_jitter(struct network *net, int urgent)
{
    unsigned interval = net->hello_interval * 1000;
    if(urgent)
        interval = MIN(interval, 100);
    return (interval / 2 + random() % interval);
}

void
check_networks(void)
{
    int i, rc, changed = 0;
    unsigned char ipv4[4];

    for(i = 0; i < numnets; i++) {
        rc = do_ipv4 ?
            kernel_interface_ipv4(nets[i].ifname, nets[i].ifindex, ipv4) :
            0;
        if(rc > 0) {
            if(!nets[i].ipv4 || memcmp(ipv4, nets[i].ipv4, 4) != 0) {
                if(!nets[i].ipv4)
                    nets[i].ipv4 = malloc(4);
                if(nets[i].ipv4)
                    memcpy(nets[i].ipv4, ipv4, 4);
                changed = 1;
            }
        } else {
            if(nets[i].ipv4) {
                free(nets[i].ipv4);
                nets[i].ipv4 = NULL;
                changed = 1;
            }
        }
        rc = kernel_interface_operational(nets[i].ifname, nets[i].ifindex);
        if((rc > 0) != nets[i].up) {
            debugf("Noticed status change for %s.\n", nets[i].ifname);
            nets[i].up = (rc > 0);
            if(rc > 0) {
                send_self_update(&nets[i], 0);
                send_request(&nets[i], NULL, 0, 0, 0, 0);
            } else {
                flush_network_routes(&nets[i]);
            }
        }
        if(changed) {
            if(nets[i].up)
                send_update(&nets[i], 0, NULL, 0);
        }
    }
}
