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
#include <time.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

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

struct netlink {
    unsigned int seqno;
    int sock;
    struct sockaddr_nl sockaddr;
    socklen_t socklen;
};

static struct netlink nl_command = { 0, -1, {0}, 0 };
static struct netlink nl_listen = { 0, -1, {0}, 0 };

static int
netlink_socket(struct netlink *nl, uint32_t groups)
{
    int rc;

    nl->sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(nl->sock < 0)
        return -1;

    memset(&nl->sockaddr, 0, sizeof(nl->sockaddr));
    nl->sockaddr.nl_family = AF_NETLINK;
    nl->sockaddr.nl_groups = groups;
    nl->socklen = sizeof(nl->sockaddr);

    nl->seqno = time(NULL);

    rc = fcntl(nl->sock, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(nl->sock, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = bind(nl->sock, (struct sockaddr *)&nl->sockaddr, nl->socklen);
    if(rc < 0)
        goto fail;

    rc = getsockname(nl->sock, (struct sockaddr *)&nl->sockaddr, &nl->socklen);
    if(rc < 0)
        goto fail;

    return 0;

 fail:
    {
        int saved_errno = errno;
        close(nl->sock);
        nl->sock = -1;
        errno = saved_errno;
        return -1;
    }
}

static int
netlink_read(int (*filter)(struct nlmsghdr *, void *data), void *data)
{
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    struct nlmsghdr *nh;
    int len;

    char buf[8192];

    if(nl_command.sock < 0) {
        fprintf(stderr,"netlink_read: netlink not initialized.\n");
        return -1;
    }

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = &buf;

    while(1) {
        int i = 0;

        iov.iov_len = sizeof(buf);
        len = recvmsg(nl_command.sock, &msg, 0);

        if(len < 0 && (errno == EAGAIN || errno == EINTR)) {
            int rc;
            rc = wait_for_fd(0, nl_command.sock, 100);
            if(rc <= 0) {
                if(rc == 0)
                    errno = EAGAIN;
            } else {
                len = recvmsg(nl_command.sock, &msg, 0);
            }
        }

        if(len < 0) {
            perror("recvmsg(nl_command)");
            continue;
        } else if(len == 0) {
            fprintf(stderr, "EOF on netlink\n");
            errno = EIO;
            return -1;
        } else if(msg.msg_namelen != nl_command.socklen) {
            fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
            errno = EIO;
            return -1;
        } else if(nladdr.nl_pid != 0) {
            debugf("Netlink message not for us.\n");
            continue;
        }

        debugf("Netlink message: ");

        for(nh = (struct nlmsghdr *)buf;
             NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {
            debugf("%d %s", i,
                   (nh->nlmsg_flags & NLM_F_MULTI) ? "(multi) " : "");
            i++;
            if(nh->nlmsg_pid != nl_command.sockaddr.nl_pid ||
                nh->nlmsg_seq != nl_command.seqno) {
                debugf("(wrong seqno/pid), ");
                continue;
            } else if(nh->nlmsg_type == NLMSG_DONE) {
                debugf("(done)\n");
                goto done;
            } else if(nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
                if(err->error == 0) {
                    debugf("ACK\n");
                    if(!(nh->nlmsg_flags & NLM_F_MULTI))
                        return 0;
                    continue;
                }
                errno = -err->error;
                perror("netlink_read");
                errno = -err->error;
                return -1;
            }

            if(filter)
                filter(nh, data);
            if(!(nh->nlmsg_flags & NLM_F_MULTI))
                break;
        }
        debugf("\n");

        if(msg.msg_flags & MSG_TRUNC) {
            fprintf(stderr, "Netlink message truncated\n");
            continue;
        }
    }

 done:
    return 0;
}

static int
netlink_talk(struct nlmsghdr *nh)
{

    int rc;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;

    if(nl_command.sock < 0) {
        fprintf(stderr,"netlink_talk: netlink not initialized.\n");
        return -1;
    }

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = nh;
    iov.iov_len = nh->nlmsg_len;

    nh->nlmsg_flags |= NLM_F_ACK;
    nh->nlmsg_seq = ++nl_command.seqno;

    rc = sendmsg(nl_command.sock, &msg, 0);
    if(rc < 0 && (errno == EAGAIN || errno == EINTR)) {
        rc = wait_for_fd(1, nl_command.sock, 100);
        if(rc <= 0) {
            if(rc == 0)
                errno = EAGAIN;
        } else {
            rc = sendmsg(nl_command.sock, &msg, 0);
        }
    }

    if(rc < nh->nlmsg_len) {
        int saved_errno = errno;
        perror("sendmsg");
        errno = saved_errno;
        return -1;
    }

    return netlink_read(NULL,NULL); /* ACK */
}

static int
netlink_send_dump(int type, void *data, int len) {

    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov[2];
    union {
        char raw[NLMSG_ALIGN(sizeof(struct nlmsghdr))];
        struct nlmsghdr nh;
    } buf;
    int rc;

    if(nl_command.sock < 0) {
        fprintf(stderr,"netlink_send_dump: netlink not initialized.\n");
        errno = EIO;
        return -1;
    }

    /* At least we should send an 'struct rtgenmsg' */
    if(data == NULL || len == 0) {
        errno = EIO;
        return -1;
    }

    /* And more : using anything else that 'struct rtgenmsg' is currently */
    /* ignored by the linux kernel (today: 2.6.21) because NLM_F_MATCH is */
    /* not yet implemented */

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    iov[0].iov_base = buf.raw;
    iov[0].iov_len = sizeof(buf.raw);
    iov[1].iov_base = data;
    iov[1].iov_len = len;

    memset(buf.raw, 0, sizeof(buf.raw));
    buf.nh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    buf.nh.nlmsg_type = type;
    buf.nh.nlmsg_seq = ++nl_command.seqno;
    buf.nh.nlmsg_len = NLMSG_LENGTH(len);

    rc = sendmsg(nl_command.sock, &msg, 0);
    if(rc < buf.nh.nlmsg_len) {
        int saved_errno = errno;
        perror("sendmsg");
        errno = saved_errno;
        return -1;
    }

    return 0;
}

static int
netlink_listen(int (*monitor)(struct nlmsghdr *nh, void *data), void *data) {

    int err;
    struct msghdr msg;
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct nlmsghdr *nh;
    int len;
    int interesting = 0;

    char buf[8192];

    if(nl_listen.sock < 0) {
        fprintf(stderr,"netlink_listen: netlink not initialized.\n");
        errno = EIO;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    len = recvmsg(nl_listen.sock, &msg, 0);

    if(len < 0) {
        int saved_errno = errno;
        if(errno == EINTR || errno == EAGAIN)
            return 0;
        perror("recvmsg(netlink)");
        errno = saved_errno;
        return -1;
    }

    if(len == 0) {
        fprintf(stderr, "recvmsg(netlink): EOF\n");
        errno = EIO;
        return -1;
    }

    if(msg.msg_namelen != nl_listen.socklen) {
        fprintf(stderr,
                "netlink_listen: unexpected sender address length (%d)\n",
                msg.msg_namelen);
        errno = EIO;
        return -1;
    }

    for(nh = (struct nlmsghdr *)buf;
        NLMSG_OK(nh, len);
        nh = NLMSG_NEXT(nh, len)) {
        if(nh->nlmsg_type == NLMSG_DONE) {
            continue;
        } else if(nh->nlmsg_type == NLMSG_ERROR) {
            continue;
        }

        if(nh->nlmsg_pid == nl_command.sockaddr.nl_pid)
            continue;

        if(monitor) {
            err = monitor(nh,data);
            if(err < 0) return err;
            interesting = interesting || err;
        }
    }

    if(msg.msg_flags & MSG_TRUNC) {
        fprintf(stderr, "Netlink message truncated\n");
    }
    return interesting;
}

int
kernel_setup(int setup)
{
    int rc;

    if(setup) {
        rc = netlink_socket(&nl_command, 0);
        if(rc < 0) {
            perror("netlink_socket(0)");
            return -1;
        }

        rc = netlink_socket(&nl_listen, RTMGRP_IPV6_ROUTE);
        if(rc < 0) {
            perror("netlink_socket(RTMGRP_IPV6_ROUTE)");
            return -1;
        }

        kernel_socket = nl_listen.sock;

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

        close(nl_command.sock);
        nl_command.sock = -1;

        close(nl_listen.sock);
        nl_listen.sock = -1;
        kernel_socket = -1;

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

int
kernel_route(int operation, const unsigned char *dest, unsigned short plen,
             const unsigned char *gate, int ifindex,
             unsigned int metric, unsigned int newmetric)
{

    union { char raw[1024]; struct nlmsghdr nh; } buf;
    struct rtmsg *rtm;
    struct rtattr *rta;
    int len = sizeof(buf.raw);
    int rc;

    if(operation == ROUTE_MODIFY) {
        if(newmetric == metric)
            return 0;
        rc = kernel_route(ROUTE_ADD, dest, plen, gate, ifindex, newmetric, 0);
        if(rc < 0 && errno != EEXIST)
            return rc;
        rc = kernel_route(ROUTE_FLUSH, dest, plen, gate, ifindex, metric, 0);
        if(rc < 0 && errno == ESRCH)
            rc = 1;
        return rc;
    }

    debugf("kernel_route: %s %s/%d metric %d dev %d nexthop %s\n",
           operation == ROUTE_ADD ? "add" :
           operation == ROUTE_FLUSH ? "flush" : "???",
           format_address(dest), plen, metric, ifindex,
           format_address(gate));

    if(ifindex_lo < 0) {
        ifindex_lo = if_nametoindex("lo");
        if(ifindex_lo <= 0)
            return -1;
    }

    memset(buf.raw, 0, sizeof(buf.raw));
    if(operation == ROUTE_ADD) {
        buf.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
        buf.nh.nlmsg_type = RTM_NEWROUTE;
    } else {
        buf.nh.nlmsg_flags = NLM_F_REQUEST;
        buf.nh.nlmsg_type = RTM_DELROUTE;
    }

    rtm = NLMSG_DATA(&buf.nh);
    rtm->rtm_family = AF_INET6;
    rtm->rtm_dst_len = plen;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    if(metric < KERNEL_INFINITY)
        rtm->rtm_type = RTN_UNICAST;
    else
        rtm->rtm_type = RTN_UNREACHABLE;
    rtm->rtm_protocol = RTPROT_BABEL;

    rta = RTM_RTA(rtm);

    rta = RTA_NEXT(rta, len);
    rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
    rta->rta_type = RTA_DST;
    memcpy(RTA_DATA(rta), dest, sizeof(struct in6_addr));

    rta = RTA_NEXT(rta, len);
    rta->rta_len = RTA_LENGTH(sizeof(int));
    rta->rta_type = RTA_PRIORITY;

    if(metric < KERNEL_INFINITY) {
        *(int*)RTA_DATA(rta) = metric;
        rta = RTA_NEXT(rta, len);
        rta->rta_len = RTA_LENGTH(sizeof(int));
        rta->rta_type = RTA_OIF;
        *(int*)RTA_DATA(rta) = ifindex;

        rta = RTA_NEXT(rta, len);
        rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
        rta->rta_type = RTA_GATEWAY;
        memcpy(RTA_DATA(rta), gate, sizeof(struct in6_addr));
    } else {
        *(int*)RTA_DATA(rta) = -1;
    }
    buf.nh.nlmsg_len = (char*)rta + rta->rta_len - buf.raw;

    return netlink_talk(&buf.nh);
}

static int
parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route)
{
    int table = RT_TABLE_MAIN;
    struct rtattr *rta= RTM_RTA(rtm);;
    len -= NLMSG_ALIGN(sizeof(*rtm));

    memset(&route->prefix,0,sizeof(struct in6_addr));
    memset(&route->gw,0,sizeof(struct in6_addr));
    route->plen = rtm->rtm_dst_len;
    route->metric = KERNEL_INFINITY;
    route->ifindex = 0;

    while(RTA_OK(rta, len)) {
        switch (rta->rta_type) {
        case RTA_DST:
            memcpy(&route->prefix,RTA_DATA(rta),16);
            break;
        case RTA_GATEWAY:
            memcpy(&route->gw,RTA_DATA(rta),16);
            break;
        case RTA_OIF:
            route->ifindex = *(int*)RTA_DATA(rta);
            break;
        case RTA_PRIORITY:
            route->metric = *(int*)RTA_DATA(rta);
            if(route->metric < 0 || route->metric > KERNEL_INFINITY)
                route->metric = KERNEL_INFINITY;
            break;
#ifdef RTA_TABLE
       case RTA_TABLE:
            table = *(int*)RTA_DATA(rta);
            break;
#endif
        default:
            break;
        }
        rta = RTA_NEXT(rta, len);
    }

    if(table != RT_TABLE_MAIN)
        return -1;
    return 0;
}

static void
print_kernel_route(int add, int protocol, int type,
                   struct kernel_route *route)
{
    char ifname[IFNAMSIZ];
    char addr_prefix[INET6_ADDRSTRLEN];
    char addr_gw[INET6_ADDRSTRLEN];

    if(!inet_ntop(AF_INET6, route->prefix,
                  addr_prefix, sizeof(addr_prefix)) ||
       !inet_ntop(AF_INET6,route->gw, addr_gw, sizeof(addr_gw)) ||
       !if_indextoname(route->ifindex, ifname)) {
        debugf("Couldn't format kernel route for printing.");
        return;
    }

    debugf("%s kernel route: dest: %s/%d gw: %s metric: %d if: %s "
           "(proto: %d, type: %d)\n",
           add == RTM_NEWROUTE ? "Add" : "Delete",
           addr_prefix, route->plen, addr_gw, route->metric, ifname,
           protocol, type);
}

static int
monitor_kernel_route(struct nlmsghdr *nh, void *data)
{
    int rc;
    struct kernel_route route;

    int len = nh->nlmsg_len;
    struct rtmsg *rtm;

    if(nh->nlmsg_type != RTM_NEWROUTE && nh->nlmsg_type != RTM_DELROUTE)
        return 0;

    rtm = (struct rtmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    if(rtm->rtm_protocol == RTPROT_BOOT || rtm->rtm_protocol == RTPROT_BABEL)
        return 0;

    if(debug >= 2) {
        rc = parse_kernel_route_rta(rtm, len, &route);
        if(rc >= 0)
            print_kernel_route(nh->nlmsg_type, rtm->rtm_protocol,
                               rtm->rtm_type, &route);
    }

    return 1;
}

static int
filter_kernel_routes(struct nlmsghdr *nh, void *data)
{
    int rc;
    void **args = (void**)data;
    int maxplen = *(int*)args[0];
    int maxroutes = *(int*)args[1];
    struct kernel_route *routes = (struct kernel_route *)args[2];
    int *found = (int*)args[3];

    struct rtmsg *rtm;

    int len = nh->nlmsg_len;

    if(*found >= maxroutes)
        return 0;

    if(nh->nlmsg_type != RTM_NEWROUTE)
        return 0;

    rtm = (struct rtmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    if(rtm->rtm_protocol == RTPROT_BOOT || rtm->rtm_protocol == RTPROT_BABEL)
        return 0;

    if(rtm->rtm_scope >= RT_SCOPE_LINK)
        return 0;

    if(rtm->rtm_dst_len > maxplen || rtm->rtm_src_len != 0)
        return 0;

    if(rtm->rtm_table != RT_TABLE_MAIN)
        return 0;

    rc = parse_kernel_route_rta(rtm, len, &routes[*found]);
    if(rc < 0)
        return 0;

    if(rtm->rtm_dst_len >= 8 &&
       (routes[*found].prefix[0] == 0xFF || routes[*found].prefix[0] == 0))
       return 0;

    *found = (*found)+1;

    return 1;

}

/* This function should not return routes installed by us. */
int
kernel_routes(int maxplen, struct kernel_route *routes, int maxroutes)
{
    int rc;
    int maxp = maxplen;
    int maxr = maxroutes;
    int found = 0;
    void *data[4] = { &maxp, &maxr, routes, &found };
    struct rtgenmsg g;

    memset(&g, 0, sizeof(g));
    g.rtgen_family = AF_INET6;
    rc = netlink_send_dump(RTM_GETROUTE, &g, sizeof(g));
    if(rc < 0)
        return -1;

    rc = netlink_read(filter_kernel_routes, (void*)data);
    if(rc < 0)
        return -1;

    return found;
}

int
kernel_callback(int (*fn)(void*), void *closure)
{
    int rc;

    if(nl_listen.sock < 0)
        return -1;

    rc = netlink_listen(monitor_kernel_route, NULL);
    if(rc)
        return fn(closure);

    return 0;
}
