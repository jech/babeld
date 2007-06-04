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
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>

#include "babel.h"
#include "kernel.h"
#include "util.h"

static int old_forwarding = -1;
static int old_accept_redirects = -1;
static int ifindex_lo = -1;

static int
read_proc(char *filename)
{
    char buf[100];
    int fd, rc;
    fd = open(filename, O_RDONLY);
    if(fd < 0)
        return -1;
    rc = read(fd, buf, 99);
    if(rc < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    close(fd);

    if(rc == 0)
        return -1;

    buf[rc] = '\0';
    return atoi(buf);
}

static int
write_proc(char *filename, int value)
{
    char buf[100];
    int fd, rc, n;
    n = snprintf(buf, 100, "%d", value);

    fd = open(filename, O_WRONLY);
    if(fd < 0)
        return -1;

    rc = write(fd, buf, n);
    if(rc < n) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    close(fd);
    return 1;
}

int
kernel_setup(int setup)
{
    int rc;

    if(setup) {
        old_forwarding = read_proc("/proc/sys/net/ipv6/conf/all/forwarding");
        if(old_forwarding < 0) {
            perror("Couldn't read forwarding knob.");
            return -1;
        }

        rc = write_proc("/proc/sys/net/ipv6/conf/all/forwarding", 1);
        if(rc < 0) {
            perror("Couldn't write forwarding knob.");
            return -1;
        }

        old_accept_redirects =
            read_proc("/proc/sys/net/ipv6/conf/all/accept_redirects");
        if(old_accept_redirects < 0) {
            perror("Couldn't read accept_redirects knob.");
            return -1;
        }

        rc = write_proc("/proc/sys/net/ipv6/conf/all/accept_redirects", 0);
        if(rc < 0) {
            perror("Couldn't write accept_redirects knob.");
            return -1;
        }
        return 1;
    } else {
        if(old_forwarding >= 0) {
            rc = write_proc("/proc/sys/net/ipv6/conf/all/forwarding",
                            old_forwarding);
            if(rc < 0) {
                perror("Couldn't write accept_redirects knob.\n");
                return -1;
            }
        }
        if(old_accept_redirects >= 0) {
            rc = write_proc("/proc/sys/net/ipv6/conf/all/accept_redirects",
                            old_accept_redirects);
            if(rc < 0) {
                perror("Couldn't write accept_redirects knob.\n");
                return -1;
            }
        }
        return 1;
    }
}

int
kernel_setup_interface(int setup, const char *ifname, int ifindex)
{
    return 1;
}

int
kernel_interface_mtu(const char *ifname, int ifindex)
{
    struct ifreq req;
    int s, rc;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(s, SIOCGIFMTU, &req);
    if(rc < 0) {
        close(s);
        return -1;
    }

    return req.ifr_mtu;
}

int
kernel_interface_wireless(const char *ifname, int ifindex)
{
#ifndef SIOCGIWNAME
#define SIOCGIWNAME 0x8B01
#endif
    struct ifreq req;
    int s, rc;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(s, SIOCGIWNAME, &req);
    if(rc < 0) {
        if(errno == EOPNOTSUPP || errno == EINVAL)
            rc = 0;
        else {
            perror("ioctl(SIOCGIWNAME)");
            rc = -1;
        }
    } else {
        rc = 1;
    }
    close(s);
    return rc;
}

static int route_socket = -1;

int
kernel_route(int add, const unsigned char *dest, unsigned short plen,
             const unsigned char *gate, int ifindex, unsigned int metric)
{
    struct in6_rtmsg msg;
    int rc;

    if(route_socket < 0) {
        route_socket = socket(AF_INET6, SOCK_DGRAM, 0);
        if(route_socket < 0)
            return -1;
    }

    if(ifindex_lo < 0) {
        ifindex_lo = if_nametoindex("lo");
        if(ifindex_lo <= 0)
            return -1;
    }

    memset(&msg, 0, sizeof(msg));

    msg.rtmsg_flags = RTF_UP;
    memcpy(&msg.rtmsg_dst, dest, sizeof(struct in6_addr));
    msg.rtmsg_dst_len = plen;
    msg.rtmsg_metric = metric;

    if(plen >= 128)
        msg.rtmsg_flags |= RTF_HOST;

    if(metric >= KERNEL_INFINITY) {
        msg.rtmsg_ifindex = ifindex_lo;
    } else {
        msg.rtmsg_ifindex = ifindex;
        if(plen < 128 || memcmp(dest, gate, 16) != 0)
            msg.rtmsg_flags |= RTF_GATEWAY;
    }

    memcpy(&msg.rtmsg_gateway, gate, sizeof(struct in6_addr));

    rc = ioctl(route_socket, add ? SIOCADDRT : SIOCDELRT, &msg);
    if(rc < 0)
        return -1;
    return 1;
}

/* This function should not return routes installed by us.  It currently
   does, which could lead to routing loops in some cases. */
int
kernel_routes(int maxplen, struct kernel_route *routes, int maxroutes)
{
    FILE *f;
    char dst[33], src[33], gw[33], iface[IF_NAMESIZE];
    unsigned int dst_plen, src_plen, metric, use, refcnt, flags;
    int n, rc;

    f = fopen("/proc/net/ipv6_route", "r");
    if(f == NULL)
        return -1;

    n = 0;

    while(n < maxroutes) {
        rc = fscanf(f, "%32s %02x %32s %02x %32s %08x %08x %08x %08x %s",
                     dst, &dst_plen, src, &src_plen, gw,
                     &metric, &use, &refcnt, &flags, iface);
        if(rc != 10)
            break;

        if(!(flags & RTF_UP) || dst_plen > maxplen || src_plen != 0)
            goto skip;

        rc = parse_address(dst, routes[n].prefix);
        if(rc < 0)
            goto skip;

        routes[n].plen = dst_plen;
        routes[n].metric = MIN(metric, (unsigned)KERNEL_INFINITY);
        routes[n].ifindex = if_nametoindex(iface);
        if(routes[n].ifindex < 0)
            goto skip;

        if(flags & RTF_GATEWAY)
            rc = parse_address(gw, routes[n].gw);
        else
            memset(routes[n].gw, 0, 16);
    skip:
        n++;
    }

    fclose(f);
    return n;
}
