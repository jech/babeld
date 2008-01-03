/*
Copyright 2007, 2008 by Grégoire Henry, Julien Cristau and Juliusz Chroboczek

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

#if (__GLIBC__ < 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ <= 5)
#define RTA_TABLE 15
#endif

#include "babel.h"
#include "kernel.h"
#include "util.h"

static int old_forwarding = -1;
static int old_ipv4_forwarding = -1;
static int old_accept_redirects = -1;
static int old_rp_filter = -1;

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
    unsigned short seqno;
    int sock;
    struct sockaddr_nl sockaddr;
    socklen_t socklen;
};

static struct netlink nl_command = { 0, -1, {0}, 0 };
static struct netlink nl_listen = { 0, -1, {0}, 0 };
static int nl_setup = 0;

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
netlink_read(struct netlink *nl, struct netlink *nl_ignore, int answer,
             int (*fn)(struct nlmsghdr *nh, void *data), void *data)
{

    /* 'answer' must be true when we just have send a request on 'nl_socket' */

    /* 'nl_ignore' is used in kernel_callback to ignore message originating  */
    /*  from 'nl_command' while reading 'nl_listen'                          */

    /* Return code :                                       */
    /* -1 : error                                          */
    /*  0 : if(fn) found_interesting; else found_ack;      */
    /*  1 : only if(fn) nothing interesting has been found */
    /*  2 : nothing found, retry                           */

    int err;
    struct msghdr msg;
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct nlmsghdr *nh;
    int len;
    int interesting = 0;
    int done = 0;

    char buf[8192];

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = &buf;

    do {
        iov.iov_len = sizeof(buf);
        len = recvmsg(nl->sock, &msg, 0);

        if(len < 0 && (errno == EAGAIN || errno == EINTR)) {
            int rc;
            rc = wait_for_fd(0, nl->sock, 100);
            if(rc <= 0) {
                if(rc == 0)
                    errno = EAGAIN;
            } else {
                len = recvmsg(nl->sock, &msg, 0);
            }
        }

        if(len < 0) {
            perror("netlink_read: recvmsg()");
            return 2;
        } else if(len == 0) {
            fprintf(stderr, "netlink_read: EOF\n");
            goto socket_error;
        } else if(msg.msg_namelen != nl->socklen) {
            fprintf(stderr,
                    "netlink_read: unexpected sender address length (%d)\n",
                    msg.msg_namelen);
            goto socket_error;
        } else if(nladdr.nl_pid != 0) {
            debugf("netlink_read: message not sent by kernel.\n");
            return 2;
        }

        debugf("Netlink message: ");

        for(nh = (struct nlmsghdr *)buf;
            NLMSG_OK(nh, len);
            nh = NLMSG_NEXT(nh, len)) {
            debugf("%s", (nh->nlmsg_flags & NLM_F_MULTI) ? "[multi] " : "");
            if(!answer)
                done = 1;
            if(nl_ignore && nh->nlmsg_pid == nl_ignore->sockaddr.nl_pid) {
                debugf("(ignore), ");
                continue;
            } else if(answer && (nh->nlmsg_pid != nl->sockaddr.nl_pid ||
                                 nh->nlmsg_seq != nl->seqno)) {
                debugf("(wrong seqno %d %d /pid %d %d), ",
                       nh->nlmsg_seq, nl->seqno,
                       nh->nlmsg_pid, nl->sockaddr.nl_pid);
                continue;
            } else if(nh->nlmsg_type == NLMSG_DONE) {
                debugf("(done)\n");
                done = 1;
                break;
            } else if(nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
                if(err->error == 0) {
                    debugf("(ACK)\n");
		    return 0;
                } else {
                    errno = -err->error;
                    perror("netlink_read");
                    errno = -err->error;
                    return -1;
                }
            } else if(fn) {
                debugf("(msg -> \"");
                err = fn(nh,data);
                debugf("\" %d), ", err);
                if(err < 0) return err;
                interesting = interesting || err;
                continue;
            }
            debugf(", ");
        }
        debugf("\n");

        if(msg.msg_flags & MSG_TRUNC)
            fprintf(stderr, "netlink_read: message truncated\n");

    } while (!done);

    return interesting;

    socket_error:
        close(nl->sock);
        nl->sock = -1;
        errno = EIO;
        return -1;
    }

static int
netlink_talk(struct nlmsghdr *nh)
{

    int rc;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;

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

    rc = netlink_read(&nl_command, NULL, 1, NULL, NULL); /* ACK */

    return rc;
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

int
kernel_setup(int setup, int ipv4)
{
    int rc;

    if(setup) {
        rc = netlink_socket(&nl_command, 0);
        if(rc < 0) {
            perror("netlink_socket(0)");
            return -1;
        }
        nl_setup = 1;

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

        if(ipv4) {
            old_ipv4_forwarding =
                read_proc("/proc/sys/net/ipv4/conf/all/forwarding");
            if(old_ipv4_forwarding < 0) {
                perror("Couldn't read IPv4 forwarding knob.");
                return -1;
            }

            rc = write_proc("/proc/sys/net/ipv4/conf/all/forwarding", 1);
            if(rc < 0) {
                perror("Couldn't write IPv4 forwarding knob.");
                return -1;
            }
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

        old_rp_filter =
            read_proc("/proc/sys/net/ipv4/conf/all/rp_filter");
        if(old_rp_filter < 0) {
            perror("Couldn't read rp_filter knob.");
            return -1;
        }

        rc = write_proc("/proc/sys/net/ipv4/conf/all/rp_filter", 0);
        if(rc < 0) {
            perror("Couldn't write rp_filter knob.");
            return -1;
        }

        return 1;
    } else {
        if(old_forwarding >= 0) {
            rc = write_proc("/proc/sys/net/ipv6/conf/all/forwarding",
                            old_forwarding);
            if(rc < 0) {
                perror("Couldn't write forwarding knob.\n");
                return -1;
            }
        }

        if(old_ipv4_forwarding >= 0) {
            rc = write_proc("/proc/sys/net/ipv4/conf/all/forwarding",
                            old_ipv4_forwarding);
            if(rc < 0) {
                perror("Couldn't write IPv4 forwarding knob.\n");
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

        if(old_rp_filter >= 0) {
            rc = write_proc("/proc/sys/net/ipv4/conf/all/rp_filter",
                            old_accept_redirects);
            if(rc < 0) {
                perror("Couldn't write rp_filter knob.\n");
                return -1;
            }
        }

        close(nl_command.sock);
        nl_command.sock = -1;

        nl_setup = 0;
        return 1;

    }
}

int
kernel_setup_socket(int setup)
{
    int rc;

    if(setup) {
        rc = netlink_socket(&nl_listen, RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE);
        if(rc < 0) {
            perror("netlink_socket(RTMGRP_ROUTE)");
            kernel_socket = -1;
            return -1;
        }

        kernel_socket = nl_listen.sock;

        return 1;

    } else {

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
kernel_interface_ipv4(const char *ifname, int ifindex, char *addr_r)
{
    struct ifreq req;
    int s, rc;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    req.ifr_addr.sa_family = AF_INET;
    rc = ioctl(s, SIOCGIFADDR, &req);
    if(rc < 0) {
        close(s);
        return -1;
    }

    memcpy(addr_r, &((struct sockaddr_in*)&req.ifr_addr)->sin_addr, 4);
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
             const unsigned char *gate, int ifindex, unsigned int metric,
             const unsigned char *newgate, int newifindex,
             unsigned int newmetric)
{

    union { char raw[1024]; struct nlmsghdr nh; } buf;
    struct rtmsg *rtm;
    struct rtattr *rta;
    int len = sizeof(buf.raw);
    int rc, ipv4;

    if(!nl_setup) {
        fprintf(stderr,"kernel_route: netlink not initialized.\n");
        errno = EIO;
        return -1;
    }

    /* if the socket has been closed after an IO error, */
    /* we try to re-open it. */
    if(nl_command.sock < 0) {
        rc = netlink_socket(&nl_command, 0);
        if(rc < 0) {
            int olderrno = errno;
            perror("kernel_route: netlink_socket()");
            errno = olderrno;
            return -1;
        }
    }

    /* Check that the protocol family is consistent. */
    if(plen >= 96 && v4mapped(dest)) {
        if(!v4mapped(gate)) {
            errno = EINVAL;
            return -1;
        }
    } else {
        if(v4mapped(gate)) {
            errno = EINVAL;
            return -1;
        }
    }

    ipv4 = v4mapped(gate);

    if(operation == ROUTE_MODIFY) {
        if(newmetric == metric && memcmp(newgate, gate, 16) == 0 &&
           newifindex == ifindex)
            return 0;
        rc = kernel_route(ROUTE_ADD, dest, plen, newgate, newifindex, newmetric,
                          NULL, 0, 0);
        if(rc < 0 && errno != EEXIST)
            return rc;
        rc = kernel_route(ROUTE_FLUSH, dest, plen, gate, ifindex, metric,
                          NULL, 0, 0);
        if(rc < 0 && (errno == ENOENT || errno == ESRCH))
            rc = 1;
        return rc;
    }

    debugf("kernel_route: %s %s/%d metric %d dev %d nexthop %s\n",
           operation == ROUTE_ADD ? "add" :
           operation == ROUTE_FLUSH ? "flush" : "???",
           format_address(dest), plen, metric, ifindex,
           format_address(gate));

    /* Unreachable default routes cause all sort of weird interactions;
       ignore them. */
    if(metric >= KERNEL_INFINITY && (plen == 0 || (ipv4 && plen == 96)))
        return 0;

    memset(buf.raw, 0, sizeof(buf.raw));
    if(operation == ROUTE_ADD) {
        buf.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
        buf.nh.nlmsg_type = RTM_NEWROUTE;
    } else {
        buf.nh.nlmsg_flags = NLM_F_REQUEST;
        buf.nh.nlmsg_type = RTM_DELROUTE;
    }

    rtm = NLMSG_DATA(&buf.nh);
    rtm->rtm_family = ipv4 ? AF_INET : AF_INET6;
    rtm->rtm_dst_len = ipv4 ? plen - 96 : plen;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    if(metric < KERNEL_INFINITY)
        rtm->rtm_type = RTN_UNICAST;
    else
        rtm->rtm_type = RTN_UNREACHABLE;
    rtm->rtm_protocol = RTPROT_BABEL;
    rtm->rtm_flags |= RTNH_F_ONLINK;

    rta = RTM_RTA(rtm);

    if(ipv4) {
        rta = RTA_NEXT(rta, len);
        rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
        rta->rta_type = RTA_DST;
        memcpy(RTA_DATA(rta), dest + 12, sizeof(struct in_addr));
    } else {
        rta = RTA_NEXT(rta, len);
        rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
        rta->rta_type = RTA_DST;
        memcpy(RTA_DATA(rta), dest, sizeof(struct in6_addr));
    }

    rta = RTA_NEXT(rta, len);
    rta->rta_len = RTA_LENGTH(sizeof(int));
    rta->rta_type = RTA_PRIORITY;

    if(metric < KERNEL_INFINITY) {
        *(int*)RTA_DATA(rta) = metric;
        rta = RTA_NEXT(rta, len);
        rta->rta_len = RTA_LENGTH(sizeof(int));
        rta->rta_type = RTA_OIF;
        *(int*)RTA_DATA(rta) = ifindex;

        if(ipv4) {
            rta = RTA_NEXT(rta, len);
            rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
            rta->rta_type = RTA_GATEWAY;
            memcpy(RTA_DATA(rta), gate + 12, sizeof(struct in_addr));
        } else {
            rta = RTA_NEXT(rta, len);
            rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
            rta->rta_type = RTA_GATEWAY;
            memcpy(RTA_DATA(rta), gate, sizeof(struct in6_addr));
        }
    } else {
        *(int*)RTA_DATA(rta) = -1;
    }
    buf.nh.nlmsg_len = (char*)rta + rta->rta_len - buf.raw;

    return netlink_talk(&buf.nh);
}

static int
parse_kernel_route_rta(struct rtmsg *rtm, int len, struct kernel_route *route)
{
    int table = rtm->rtm_table;
    struct rtattr *rta= RTM_RTA(rtm);;
    len -= NLMSG_ALIGN(sizeof(*rtm));

    memset(&route->prefix, 0, sizeof(struct in6_addr));
    memset(&route->gw, 0, sizeof(struct in6_addr));
    route->plen = rtm->rtm_dst_len;
    if(rtm->rtm_family == AF_INET) route->plen += 96;
    route->metric = KERNEL_INFINITY;
    route->ifindex = 0;

#define COPY_ADDR(d, s) \
    do { \
        if(rtm->rtm_family == AF_INET6) \
            memcpy(d, s, 16); \
        else if(rtm->rtm_family == AF_INET) \
            v4tov6(d, s); \
        else \
            return -1; \
    } while(0)

    while(RTA_OK(rta, len)) {
        switch (rta->rta_type) {
        case RTA_DST:
            COPY_ADDR(route->prefix, RTA_DATA(rta));
            break;
        case RTA_GATEWAY:
            COPY_ADDR(route->gw, RTA_DATA(rta));
            break;
        case RTA_OIF:
            route->ifindex = *(int*)RTA_DATA(rta);
            break;
        case RTA_PRIORITY:
            route->metric = *(int*)RTA_DATA(rta);
            if(route->metric < 0 || route->metric > KERNEL_INFINITY)
                route->metric = KERNEL_INFINITY;
            break;
       case RTA_TABLE:
            table = *(int*)RTA_DATA(rta);
            break;
        default:
            break;
        }
        rta = RTA_NEXT(rta, len);
    }
#undef COPY_ADDR

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
           "(proto: %d, type: %d)",
           add == RTM_NEWROUTE ? "Add" : "Delete",
           addr_prefix, route->plen, addr_gw, route->metric, ifname,
           protocol, type);
}

static int
filter_kernel_routes(struct nlmsghdr *nh, void *data)
{
    int rc;

    struct kernel_route *current_route;
    struct kernel_route route;

    int maxplen = 128;
    int maxroutes = 0;
    struct kernel_route *routes = NULL;
    int *found = NULL;
    int len;

    struct rtmsg *rtm;

    if(data) {
        void **args = (void**)data;
        maxplen = *(int*)args[0];
        maxroutes = *(int*)args[1];
        routes = (struct kernel_route *)args[2];
        found = (int*)args[3];
    }

    len = nh->nlmsg_len;

    if(data && *found >= maxroutes)
        return 0;

    if(nh->nlmsg_type != RTM_NEWROUTE &&
       (data || nh->nlmsg_type != RTM_DELROUTE))
        return 0;

    rtm = (struct rtmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    if(rtm->rtm_protocol == RTPROT_BOOT || rtm->rtm_protocol == RTPROT_BABEL)
        return 0;

    if(rtm->rtm_scope >= RT_SCOPE_LINK)
        return 0;

    if(rtm->rtm_src_len != 0)
        return 0;

    if(data)
        current_route = &routes[*found];
    else
        current_route = &route;

    rc = parse_kernel_route_rta(rtm, len, current_route);
    if(rc < 0)
        return 0;

    if(current_route->plen > maxplen)
        return 0;

    if(martian_prefix(current_route->prefix, current_route->plen))
        return 0;

    /* Ignore default unreachable routes; no idea where they come from. */
    if(current_route->plen == 0 && current_route->metric >= KERNEL_INFINITY)
        return 0;

    if(debug >= 2) {
        if(rc >= 0) {
            print_kernel_route(nh->nlmsg_type, rtm->rtm_protocol,
                               rtm->rtm_type, current_route);
        }
    }

    if (data) *found = (*found)+1;

    return 1;

}

/* This function should not return routes installed by us. */
int
kernel_routes(int maxplen, struct kernel_route *routes, int maxroutes)
{
    int i, rc;
    int maxp = maxplen;
    int maxr = maxroutes;
    int found = 0;
    void *data[4] = { &maxp, &maxr, routes, &found };
    int families[2] = { AF_INET6, AF_INET };
    struct rtgenmsg g;

    if(!nl_setup) {
        fprintf(stderr,"kernel_routes: netlink not initialized.\n");
        errno = EIO;
        return -1;
    }

    if(nl_command.sock < 0) {
        rc = netlink_socket(&nl_command, 0);
        if(rc < 0) {
            perror("kernel_routes: netlink_socket()");
            return -1;
        }
    }

    for(i = 0; i < 2; i++) {
        memset(&g, 0, sizeof(g));
        g.rtgen_family = families[i];
        rc = netlink_send_dump(RTM_GETROUTE, &g, sizeof(g));
        if(rc < 0)
            return -1;

        rc = netlink_read(&nl_command, NULL, 1,
                          filter_kernel_routes, (void *)data);

        if(rc < 0)
            return -1;
    }

    return found;
}

int
kernel_callback(int (*fn)(void*), void *closure)
{
    int rc;

    debugf("\nReceived changes in kernel tables.\n");
    
    if(nl_listen.sock < 0) {
        rc = kernel_setup_socket(1);
        if(rc < 0) {
            perror("kernel_callback: kernel_setup_socket(1)");
            return -1;
        }
    }
    rc = netlink_read(&nl_listen, &nl_command, 0, filter_kernel_routes, NULL);

    if(rc < 0 && nl_listen.sock < 0)
      kernel_setup_socket(1);

    /* if netlink return 0 (found something interesting) */
    /* or -1 (i.e. IO error), we call... back ! */
    if(rc)
        return fn(closure);

    return 0;
}
