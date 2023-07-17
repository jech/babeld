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

#define __APPLE_USE_RFC_3542
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
#include "local.h"
#include "xroute.h"
#include "hmac.h"

#define MIN_MTU 512

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

    FOR_ALL_INTERFACES(ifp) {
        if(strcmp(ifp->name, ifname) == 0) {
            if(if_conf)
                fprintf(stderr,
                        "Warning: attempting to add existing interface (%s), "
                        "new configuration ignored.\n", ifname);
            return ifp;
        }
    }

    ifp = calloc(1, sizeof(struct interface));
    if(ifp == NULL)
        return NULL;

    strncpy(ifp->name, ifname, IF_NAMESIZE);
    ifp->conf = if_conf ? if_conf : default_interface_conf;
    ifp->hello_seqno = (random() & 0xFFFF);

    if(interfaces == NULL)
        interfaces = ifp;
    else
        last_interface()->next = ifp;

    local_notify_interface(ifp, LOCAL_ADD);
    schedule_interfaces_check(200, 0);

    return ifp;
}

int
flush_interface(char *ifname)
{
    struct interface *ifp, *prev;

    prev = NULL;
    ifp = interfaces;
    while(ifp) {
        if(strcmp(ifp->name, ifname) == 0)
            break;
        prev = ifp;
        ifp = ifp->next;
    }

    if(ifp == NULL)
        return 0;

    interface_updown(ifp, 0);
    if(prev)
        prev->next = ifp->next;
    else
        interfaces = ifp->next;

    if(ifp->conf != NULL && ifp->conf != default_interface_conf)
        flush_ifconf(ifp->conf);

    local_notify_interface(ifp, LOCAL_FLUSH);

    free(ifp->ipv4);
    free(ifp);

    return 1;
}

/* This should be no more than half the hello interval, so that hellos
   aren't sent late.  The result is in milliseconds. */
unsigned
jitter(struct buffered *buf, int urgent)
{
    unsigned interval = buf->flush_interval;
    if(urgent)
        interval = MIN(interval, 20);
    else
        interval = MIN(interval, 2000);
    return roughly(interval / 2);
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
            local_notify_interface(ifp, LOCAL_CHANGE);
            return 1;
        }
    } else {
        if(ifp->ipv4) {
            debugf("Noticed IPv4 change for %s.\n", ifp->name);
            flush_interface_routes(ifp, 0);
            free(ifp->ipv4);
            ifp->ipv4 = NULL;
            local_notify_interface(ifp, LOCAL_CHANGE);
            return 1;
        }
    }
    return 0;
}

static int
check_link_local_addresses(struct interface *ifp)
{
    struct kernel_route ll[32];
    int rc, i;

    rc = kernel_addresses(ifp->ifindex, 1, ll, 32);
    if(rc <= 0) {
        if(rc < 0)
            perror("kernel_addresses(link local)");
        else
            fprintf(stderr, "Interface %s has no link-local address.\n",
                    ifp->name);
        if(ifp->ll) {
            free(ifp->ll);
            ifp->numll = 0;
            ifp->ll = NULL;
        }
        local_notify_interface(ifp, LOCAL_CHANGE);
        /* Most probably DAD hasn't finished yet.  Reschedule us
           real soon. */
        schedule_interfaces_check(2000, 0);
        return -1;
    } else {
        int changed;
        if(rc == ifp->numll) {
            changed = 0;
            for(i = 0; i < rc; i++) {
                if(memcmp(ifp->ll[i], ll[i].prefix, 16) != 0) {
                    changed = 1;
                    break;
                }
            }
        } else {
            changed = 1;
        }

        if(changed) {
            free(ifp->ll);
            ifp->numll = 0;
            ifp->ll = malloc(16 * rc);
            if(ifp->ll == NULL) {
                perror("malloc(ll)");
            } else {
                for(i = 0; i < rc; i++)
                    memcpy(ifp->ll[i], ll[i].prefix, 16);
                ifp->numll = rc;
            }
            local_notify_interface(ifp, LOCAL_CHANGE);
        }
    }

    return 0;
}

int
interface_updown(struct interface *ifp, int up)
{
    int mtu, rc, type;
    struct ipv6_mreq mreq;
    int v4viav6;

    if((!!up) == if_up(ifp))
        return 0;

    if(up) {
        ifp->flags |= IF_UP;
        if(ifp->ifindex <= 0) {
            fprintf(stderr,
                    "Upping unknown interface %s.\n", ifp->name);
            goto fail;
        }

        rc = kernel_setup_interface(1, ifp->name, ifp->ifindex);
        if(rc < 0) {
            fprintf(stderr, "kernel_setup_interface(%s, %u) failed.\n",
                    ifp->name, ifp->ifindex);
            goto fail;
        }

        memset(&ifp->buf.sin6, 0, sizeof(ifp->buf.sin6));
        ifp->buf.sin6.sin6_family = AF_INET6;
        memcpy(&ifp->buf.sin6.sin6_addr, protocol_group, 16);
        ifp->buf.sin6.sin6_port = htons(protocol_port);
        ifp->buf.sin6.sin6_scope_id = ifp->ifindex;

        mtu = kernel_interface_mtu(ifp->name, ifp->ifindex);
        if(mtu < 0) {
            fprintf(stderr,
                    "Warning: couldn't get MTU of interface %s (%u), "
                    "using 1280\n",
                    ifp->name, ifp->ifindex);
            mtu = 1280;
        }

        /* We need to be able to fit at least a router-ID and an update,
           up to 116 bytes, and that's not counting sub-TLVs or crypto keys.
           In IPv6, the minimum MTU is 1280, and every host must be able
           to reassemble up to 1500 bytes.  In IPv4, every host must be
           able to reassemble up to 576 bytes.  At any rate, the Babel spec
           says that every node must be able to parse packets of size 512. */
        if(mtu < MIN_MTU) {
            fprintf(stderr,
                    "Suspiciously low MTU %d on interface %s (%u), using %d.\n",
                    mtu, ifp->name, ifp->ifindex, MIN_MTU);
            mtu = 512;
        }

        if(ifp->buf.buf)
            free(ifp->buf.buf);

        /* 40 for IPv6 header, 8 for UDP header. */
        ifp->buf.size = mtu - sizeof(packet_header) - 48;
        ifp->buf.buf = malloc(ifp->buf.size);
        if(ifp->buf.buf == NULL) {
            fprintf(stderr, "Couldn't allocate sendbuf.\n");
            ifp->buf.size = 0;
            goto fail;
        }
        ifp->buf.hello = -1;

        rc = resize_receive_buffer(mtu);
        if(rc < 0)
            fprintf(stderr, "Warning: couldn't resize "
                    "receive buffer for interface %s (%u) (%d bytes).\n",
                    ifp->name, ifp->ifindex, mtu);

        type = IF_CONF(ifp, type);
        if(type == IF_TYPE_DEFAULT) {
            if(all_wireless) {
                type = IF_TYPE_WIRELESS;
            } else {
                rc = kernel_interface_wireless(ifp->name, ifp->ifindex);
                if(rc < 0) {
                    fprintf(stderr,
                            "Warning: couldn't determine whether %s (%u) "
                            "is a wireless interface.\n",
                            ifp->name, ifp->ifindex);
                } else if(rc) {
                    type = IF_TYPE_WIRELESS;
                }
            }
        }

        /* Type is CONFIG_TYPE_AUTO if interface is not known to be
           wireless, so provide sane defaults for that case. */

        if(type == IF_TYPE_WIRELESS)
            ifp->flags |= IF_WIRELESS;
        else
            ifp->flags &= ~IF_WIRELESS;

        ifp->cost = IF_CONF(ifp, cost);
        if(ifp->cost <= 0)
            ifp->cost = type == IF_TYPE_WIRELESS ? 256 : 96;

        if(IF_CONF(ifp, split_horizon) == CONFIG_YES)
            ifp->flags |= IF_SPLIT_HORIZON;
        else if(IF_CONF(ifp, split_horizon) == CONFIG_NO)
            ifp->flags &= ~IF_SPLIT_HORIZON;
        else if(type == IF_TYPE_WIRED)
            ifp->flags |= IF_SPLIT_HORIZON;
        else
            ifp->flags &= ~IF_SPLIT_HORIZON;

        if(IF_CONF(ifp, lq) == CONFIG_YES)
            ifp->flags |= IF_LQ;
        else if(IF_CONF(ifp, lq) == CONFIG_NO)
            ifp->flags &= ~IF_LQ;
        else if(type == IF_TYPE_WIRELESS)
            ifp->flags |= IF_LQ;
        else
            ifp->flags &= ~IF_LQ;

        if(IF_CONF(ifp, faraway) == CONFIG_YES)
            ifp->flags |= IF_FARAWAY;

        if(IF_CONF(ifp, unicast) == CONFIG_YES)
            ifp->flags |= IF_UNICAST;
        if(IF_CONF(ifp, accept_bad_signatures) == CONFIG_YES)
            ifp->flags |= IF_ACCEPT_BAD_SIGNATURES;
        else
            ifp->flags &= ~IF_ACCEPT_BAD_SIGNATURES;
        if(IF_CONF(ifp, hello_interval) > 0)
            ifp->hello_interval = IF_CONF(ifp, hello_interval);
        else if(type == IF_TYPE_WIRELESS)
            ifp->hello_interval = default_wireless_hello_interval;
        else
            ifp->hello_interval = default_wired_hello_interval;

        ifp->update_interval =
            IF_CONF(ifp, update_interval) > 0 ?
            IF_CONF(ifp, update_interval) :
            ifp->hello_interval * 4;

        /* This must be no more than half the Hello interval, or else
           Hellos will arrive late. */
        ifp->buf.flush_interval = ifp->hello_interval / 2;

        ifp->rtt_decay =
            IF_CONF(ifp, rtt_decay) > 0 ?
            IF_CONF(ifp, rtt_decay) : 42;

        ifp->rtt_min =
            IF_CONF(ifp, rtt_min) > 0 ?
            IF_CONF(ifp, rtt_min) : 10000;
        ifp->rtt_max =
            IF_CONF(ifp, rtt_max) > 0 ?
            IF_CONF(ifp, rtt_max) : 120000;
        if(ifp->rtt_max <= ifp->rtt_min) {
            fprintf(stderr,
                    "Uh, rtt-max is less than or equal to rtt-min (%u <= %u). "
                    "Setting it to %u.\n", ifp->rtt_max, ifp->rtt_min,
                    ifp->rtt_min + 10000);
            ifp->rtt_max = ifp->rtt_min + 10000;
        }
        ifp->max_rtt_penalty = IF_CONF(ifp, max_rtt_penalty);
        if(ifp->max_rtt_penalty == 0 && type == IF_TYPE_TUNNEL)
            ifp->max_rtt_penalty = 96;

        if(IF_CONF(ifp, enable_timestamps) == CONFIG_YES)
            ifp->flags |= IF_TIMESTAMPS;
        else if(IF_CONF(ifp, enable_timestamps) == CONFIG_NO)
            ifp->flags &= ~IF_TIMESTAMPS;
        else if(type == IF_TYPE_TUNNEL)
            ifp->flags |= IF_TIMESTAMPS;
        else
            ifp->flags &= ~IF_TIMESTAMPS;
        if(ifp->max_rtt_penalty > 0 && !(ifp->flags & IF_TIMESTAMPS))
            fprintf(stderr,
                    "Warning: max_rtt_penalty is set "
                    "but timestamps are disabled on interface %s.\n",
                    ifp->name);

        if(IF_CONF(ifp, rfc6126) == CONFIG_YES)
            ifp->flags |= IF_RFC6126;
        else
            ifp->flags &= ~IF_RFC6126;

        if(IF_CONF(ifp, v4viav6) == CONFIG_NO)
            v4viav6 = 0;
        else if(IF_CONF(ifp, v4viav6) == CONFIG_YES)
            v4viav6 = 1;
        else
            v4viav6 = kernel_safe_v4viav6();
        if(v4viav6)
            ifp->flags |= IF_V4VIAV6;
        else
            ifp->flags &= ~IF_V4VIAV6;

        if(IF_CONF(ifp, probe_mtu) == CONFIG_YES)
            ifp->flags |= IF_PROBE_MTU;

        rc = check_link_local_addresses(ifp);
        if(rc < 0) {
            goto fail;
        }
        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
        mreq.ipv6mr_interface = ifp->ifindex;
        rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0) {
            perror("setsockopt(IPV6_JOIN_GROUP)");
            goto fail;
        }

        update_interface_metric(ifp);
        rc = check_interface_ipv4(ifp);

        if(IF_CONF(ifp, key) != ifp->key) {
            if(ifp->key != NULL)
                release_key(ifp->key);
            if(IF_CONF(ifp, key) != NULL)
                ifp->key = retain_key(IF_CONF(ifp, key));
            else
                ifp->key = NULL;
        }

        debugf("Upped interface %s (cost=%d%s).\n",
               ifp->name,
               ifp->cost,
               ifp->ipv4 ? ", IPv4" : "");

        set_timeout(&ifp->hello_timeout, ifp->hello_interval);
        set_timeout(&ifp->update_timeout, ifp->update_interval);
        send_hello(ifp);
        if(rc > 0)
            send_update(ifp, 0, NULL, 0, NULL, 0);
        send_multicast_request(ifp, NULL, 0, NULL, 0);
    } else {
        ifp->flags &= ~IF_UP;
        flush_interface_routes(ifp, 0);
        ifp->buf.len = 0;
        ifp->buf.size = 0;
        free(ifp->buf.buf);
        ifp->num_buffered_updates = 0;
        ifp->update_bufsize = 0;
        if(ifp->buffered_updates)
            free(ifp->buffered_updates);
        ifp->buffered_updates = NULL;
        ifp->buf.buf = NULL;
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

    local_notify_interface(ifp, LOCAL_CHANGE);

    return 1;

 fail:
    assert(up);
    interface_updown(ifp, 0);
    local_notify_interface(ifp, LOCAL_CHANGE);
    return -1;
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
            interface_updown(ifp, 0);
            ifp->ifindex = ifindex;
            ifindex_changed = 1;
        }

        if(ifp->ifindex > 0)
            rc = kernel_interface_operational(ifp->name, ifp->ifindex);
        else
            rc = 0;
        if((rc > 0) != if_up(ifp)) {
            debugf("Noticed status change for %s.\n", ifp->name);
            interface_updown(ifp, rc > 0);
        }

        if(if_up(ifp)) {
            /* Bother, said Pooh.  We should probably check for a change
               in IPv4 addresses at this point. */
            check_link_local_addresses(ifp);
            rc = check_interface_ipv4(ifp);
            if(rc > 0) {
                send_multicast_request(ifp, NULL, 0, NULL, 0);
                send_update(ifp, 0, NULL, 0, NULL, 0);
            }
        }
    }

    if(ifindex_changed)
        renumber_filters();
}
