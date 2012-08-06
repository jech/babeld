/*
Copyright 2007-2010 by Grégoire Henry, Julien Cristau and Juliusz Chroboczek

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
#include <linux/if_bridge.h>
#include <netinet/ether.h>

#if (__GLIBC__ < 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ <= 5)
#define RTA_TABLE 15
#endif

#include "babeld.h"
#include "kernel.h"
#include "util.h"
#include "interface.h"

int export_table = -1, import_table = -1;

static int old_forwarding = -1;
static int old_ipv4_forwarding = -1;
static int old_accept_redirects = -1;
static int old_rp_filter = -1;

static int dgram_socket = -1;

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#define NO_ARPHRD
#endif

/* Determine an interface's hardware address, in modified EUI-64 format */
int
if_eui64(char *ifname, int ifindex, unsigned char *eui)
{
    int s, rc;
    struct ifreq ifr;

    s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(s < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    rc = ioctl(s, SIOCGIFHWADDR, &ifr);
    if(rc < 0) {
        int saved_errno = errno;
        close(s);
        errno = saved_errno;
        return -1;
    }
    close(s);

    switch(ifr.ifr_hwaddr.sa_family) {
    case ARPHRD_ETHER:
#ifndef NO_ARPHRD
    case ARPHRD_FDDI:
    case ARPHRD_IEEE802_TR:
    case ARPHRD_IEEE802:
#endif
    {
        unsigned char *mac;
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        /* Check for null address and group and global bits */
        if(memcmp(mac, zeroes, 6) == 0 ||
           (mac[0] & 1) != 0 || (mac[0] & 2) != 0) {
            errno = ENOENT;
            return -1;
        }
        memcpy(eui, mac, 3);
        eui[3] = 0xFF;
        eui[4] = 0xFE;
        memcpy(eui + 5, mac + 3, 3);
        eui[0] ^= 2;
        return 1;
    }
#ifndef NO_ARPHRD
    case ARPHRD_EUI64:
    case ARPHRD_IEEE1394:
    case ARPHRD_INFINIBAND: {
        unsigned char *mac;
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        if(memcmp(mac, zeroes, 8) == 0 ||
           (mac[0] & 1) != 0 || (mac[0] & 2) != 0) {
            errno = ENOENT;
            return -1;
        }
        memcpy(eui, mac, 8);
        eui[0] ^= 2;
        return 1;
    }
#endif
    default:
        errno = ENOENT;
        return -1;
    }
}

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
            kdebugf("netlink_read: message not sent by kernel.\n");
            return 2;
        }

        kdebugf("Netlink message: ");

        for(nh = (struct nlmsghdr *)buf;
            NLMSG_OK(nh, len);
            nh = NLMSG_NEXT(nh, len)) {
            kdebugf("%s", (nh->nlmsg_flags & NLM_F_MULTI) ? "[multi] " : "");
            if(!answer)
                done = 1;
            if(nl_ignore && nh->nlmsg_pid == nl_ignore->sockaddr.nl_pid) {
                kdebugf("(ignore), ");
                continue;
            } else if(answer && (nh->nlmsg_pid != nl->sockaddr.nl_pid ||
                                 nh->nlmsg_seq != nl->seqno)) {
                kdebugf("(wrong seqno %d %d /pid %d %d), ",
                       nh->nlmsg_seq, nl->seqno,
                       nh->nlmsg_pid, nl->sockaddr.nl_pid);
                continue;
            } else if(nh->nlmsg_type == NLMSG_DONE) {
                kdebugf("(done)\n");
                done = 1;
                break;
            } else if(nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
                if(err->error == 0) {
                    kdebugf("(ACK)\n");
                    return 0;
                } else {
                    kdebugf("netlink_read: %s\n", strerror(-err->error));
                    errno = -err->error;
                    return -1;
                }
            } else if(fn) {
                kdebugf("(msg -> \"");
                err = fn(nh,data);
                kdebugf("\" %d), ", err);
                if(err < 0) return err;
                interesting = interesting || err;
                continue;
            }
            kdebugf(", ");
        }
        kdebugf("\n");

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
kernel_setup(int setup)
{
    int rc;

    if(setup) {
        if(export_table < 0)
            export_table = RT_TABLE_MAIN;

        if(import_table < 0)
            import_table = RT_TABLE_MAIN;

        dgram_socket = socket(PF_INET, SOCK_DGRAM, 0);
        if(dgram_socket < 0)
            return -1;

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
        close(dgram_socket);
        dgram_socket = -1;

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
        rc = netlink_socket(&nl_listen,
                RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE
              | RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR);
        if(rc < 0) {
            perror("netlink_socket(RTMGRP_ROUTE | RTMGRP_LINK | RTMGRP_IFADDR)");
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
kernel_interface_operational(const char *ifname, int ifindex)
{
    struct ifreq req;
    int rc;
    int flags = link_detect ? (IFF_UP | IFF_RUNNING) : IFF_UP;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(dgram_socket, SIOCGIFFLAGS, &req);
    if(rc < 0)
        return -1;
    return ((req.ifr_flags & flags) == flags);
}

int
kernel_interface_ipv4(const char *ifname, int ifindex, unsigned char *addr_r)
{
    struct ifreq req;
    int rc;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    req.ifr_addr.sa_family = AF_INET;
    rc = ioctl(dgram_socket, SIOCGIFADDR, &req);
    if(rc < 0)
        return -1;

    memcpy(addr_r, &((struct sockaddr_in*)&req.ifr_addr)->sin_addr, 4);
    return 1;
}

int
kernel_interface_mtu(const char *ifname, int ifindex)
{
    struct ifreq req;
    int rc;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(dgram_socket, SIOCGIFMTU, &req);
    if(rc < 0)
        return -1;

    return req.ifr_mtu;
}

static int
isbridge(const char *ifname, int ifindex)
{
    char buf[256];
    int rc, i;
    unsigned long args[3];
    int indices[256];

    rc = snprintf(buf, 256, "/sys/class/net/%s", ifname);
    if(rc < 0 || rc >= 256)
        goto fallback;

    if(access(buf, R_OK) < 0)
        goto fallback;

    rc = snprintf(buf, 256, "/sys/class/net/%s/bridge", ifname);
    if(rc < 0 || rc >= 256)
        goto fallback;

    if(access(buf, F_OK) >= 0)
        return 1;
    else if(errno == ENOENT)
        return 0;

 fallback:
    args[0] = BRCTL_GET_BRIDGES;
    args[1] = (unsigned long)indices;
    args[2] = 256;

    rc = ioctl(dgram_socket, SIOCGIFBR, args);
    if(rc < 0) {
        if(errno == ENOPKG)
            return 0;
        else
            return -1;
    }

    for(i = 0; i < rc; i++) {
        if(indices[i] == ifindex)
            return 1;
    }

    return 0;
}

int
kernel_interface_wireless(const char *ifname, int ifindex)
{
#ifndef SIOCGIWNAME
#define SIOCGIWNAME 0x8B01
#endif
    struct ifreq req;
    int rc;

    if(isbridge(ifname, ifindex) != 0) {
        /* Give up. */
        return -1;
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(dgram_socket, SIOCGIWNAME, &req);
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
    return rc;
}

/* Sorry for that, but I haven't managed to get <linux/wireless.h>
   to include cleanly. */

#define SIOCGIWFREQ 0x8B05

struct iw_freq {
    int m;
    short e;
    unsigned char i;
    unsigned char flags;
};

struct iwreq_subset {
    union {
        char ifrn_name[IFNAMSIZ];
    } ifr_ifrn;

    union {
        struct iw_freq freq;
    } u;
};

static int
freq_to_chan(struct iw_freq *freq)
{
    int m = freq->m, e = freq->e;

    /* If exponent is 0, assume the channel is encoded directly in m. */
    if(e == 0 && m > 0 && m < 254)
        return m;

    if(e <= 6) {
        int mega, step, c, i;

        /* This encodes 1 MHz */
        mega = 1000000;
        for(i = 0; i < e; i++)
            mega /= 10;

        /* Channels 1 through 13 are 5 MHz apart, with channel 1 at 2412. */
        step = 5 * mega;
        c = 1 + (m - 2412 * mega + step / 2) / step;
        if(c >= 1 && c <= 13)
            return c;

        /* Channel 14 is at 2484 MHz  */
        if(c >= 14 && m < 2484 * mega + step / 2)
            return 14;

        /* 802.11a channel 36 is at 5180 MHz */
        c = 36 + (m - 5180 * mega + step / 2) / step;
        if(c >= 34 && c <= 165)
            return c;
    }

    errno = ENOENT;
    return -1;
}

int
kernel_interface_channel(const char *ifname, int ifindex)
{
    struct iwreq_subset iwreq;
    int rc;

    memset(&iwreq, 0, sizeof(iwreq));
    strncpy(iwreq.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);

    rc = ioctl(dgram_socket, SIOCGIWFREQ, &iwreq);
    if(rc >= 0)
        return freq_to_chan(&iwreq.u.freq);
    else
        return -1;
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
        /* It would be better to add the new route before removing the
           old one, to avoid losing packets.  However, this causes
           problems with non-multipath kernels, which sometimes
           silently fail the request, causing "stuck" routes.  Let's
           stick with the naive approach, and hope that the window is
           small enough to be negligible. */
        kernel_route(ROUTE_FLUSH, dest, plen,
                     gate, ifindex, metric,
                     NULL, 0, 0);
        rc = kernel_route(ROUTE_ADD, dest, plen,
                          newgate, newifindex, newmetric,
                          NULL, 0, 0);
        if(rc < 0) {
            if(errno == EEXIST)
                rc = 1;
            /* Should we try to re-install the flushed route on failure?
               Error handling is hard. */
        }
        return rc;
    }

    kdebugf("kernel_route: %s %s/%d metric %d dev %d nexthop %s\n",
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
    rtm->rtm_table = export_table;
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
    if(rtm->rtm_family == AF_INET) {
        const unsigned char zeroes[4] = {0, 0, 0, 0};
        v4tov6(route->prefix, zeroes);
        route->plen += 96;
    }

    route->metric = 0;
    route->ifindex = 0;
    route->proto = rtm->rtm_protocol;

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

    if(table != import_table)
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
        kdebugf("Couldn't format kernel route for printing.");
        return;
    }

    kdebugf("%s kernel route: dest: %s/%d gw: %s metric: %d if: %s "
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

    int maxroutes = 0;
    struct kernel_route *routes = NULL;
    int *found = NULL;
    int len;

    struct rtmsg *rtm;

    if(data) {
        void **args = (void**)data;
        maxroutes = *(int*)args[0];
        routes = (struct kernel_route *)args[1];
        found = (int*)args[2];
    }

    len = nh->nlmsg_len;

    if(data && *found >= maxroutes)
        return 0;

    if(nh->nlmsg_type != RTM_NEWROUTE &&
       (data || nh->nlmsg_type != RTM_DELROUTE))
        return 0;

    rtm = (struct rtmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    if(rtm->rtm_protocol == RTPROT_BABEL)
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
kernel_routes(struct kernel_route *routes, int maxroutes)
{
    int i, rc;
    int maxr = maxroutes;
    int found = 0;
    void *data[3] = { &maxr, routes, &found };
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

static char *
parse_ifname_rta(struct ifinfomsg *info, int len)
{
    struct rtattr *rta = IFLA_RTA(info);
    char *ifname = NULL;

    len -= NLMSG_ALIGN(sizeof(*info));

    while(RTA_OK(rta, len)) {
        switch (rta->rta_type) {
        case IFLA_IFNAME:
            ifname = RTA_DATA(rta);
            break;
        default:
            break;
        }
        rta = RTA_NEXT(rta, len);
    }
    return ifname;
}

static int
parse_addr_rta(struct ifaddrmsg *addr, int len, struct in6_addr *res)
{
    struct rtattr *rta;
    len -= NLMSG_ALIGN(sizeof(*addr));
    rta = IFA_RTA(addr);

    while (RTA_OK(rta, len)) {
        switch(rta->rta_type) {
            case IFA_LOCAL:
            case IFA_ADDRESS:
                switch (addr->ifa_family) {
                    case AF_INET:
                        if (res)
                            v4tov6(res->s6_addr, RTA_DATA(rta));
                        break;
                    case AF_INET6:
                        if (res)
                            memcpy(res->s6_addr, RTA_DATA(rta), 16);
                        break;
                    default:
                        kdebugf("ifaddr: unexpected address family %d\n", addr->ifa_family);
                        return -1;
                        break;
                }
                break;
            default:
                break;
        }
        rta = RTA_NEXT(rta, len);
    }
    return 0;
}

static int
filter_link(struct nlmsghdr *nh, void *data)
{
    struct ifinfomsg *info;
    int len;
    int ifindex;
    char *ifname;
    unsigned int ifflags;
    struct interface *ifp;

    len = nh->nlmsg_len;

    if(nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK)
        return 0;

    info = (struct ifinfomsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    ifindex = info->ifi_index;
    ifflags = info->ifi_flags;

    ifname = parse_ifname_rta(info, len);
    if(ifname == NULL)
        return 0;
    kdebugf("filter_interfaces: link change on if %s(%d): 0x%x\n",
            ifname, ifindex, (unsigned)ifflags);
    FOR_ALL_INTERFACES(ifp) {
        if (strcmp(ifp->name, ifname) == 0)
            return 1;
    }
    return 0;
}

static int
filter_addresses(struct nlmsghdr *nh, void *data)
{
    int rc;
    int maxroutes = 0;
    struct kernel_route *routes = NULL;
    struct in6_addr addr;
    int *found = NULL;
    int len;
    struct ifaddrmsg *ifa;
    char ifname[IFNAMSIZ];
    int ifindex = 0;
    int ll = 0;

    if (data) {
        void **args = (void **)data;
        maxroutes = *(int *)args[0];
        routes = (struct kernel_route*)args[1];
        found = (int *)args[2];
        ifindex = args[3] ? *(int*)args[3] : 0;
        ll = args[4] ? !!*(int*)args[4] : 0;
    }

    len = nh->nlmsg_len;

    if (data && *found >= maxroutes)
        return 0;

    if (nh->nlmsg_type != RTM_NEWADDR &&
            (data || nh->nlmsg_type != RTM_DELADDR))
        return 0;

    ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    rc = parse_addr_rta(ifa, len, &addr);
    if (rc < 0)
        return 0;

    if (ll == !IN6_IS_ADDR_LINKLOCAL(&addr))
        return 0;

    if (ifindex && ifa->ifa_index != ifindex)
        return 0;

    kdebugf("found address on interface %s(%d): %s\n",
            if_indextoname(ifa->ifa_index, ifname), ifa->ifa_index,
            format_address(addr.s6_addr));

    if (data) {
        struct kernel_route *route = &routes[*found];
        memcpy(route->prefix, addr.s6_addr, 16);
        route->plen = 128;
        route->metric = 0;
        route->ifindex = ifa->ifa_index;
        route->proto = RTPROT_BABEL_LOCAL;
        memset(route->gw, 0, 16);
        *found = (*found)+1;
    }

    return 1;
}

static int
filter_netlink(struct nlmsghdr *nh, void *data)
{
    int rc;
    int *changed = data;

    switch (nh->nlmsg_type) {
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
            rc = filter_kernel_routes(nh, NULL);
            if (changed && rc > 0)
                *changed |= CHANGE_ROUTE;
            return rc;
        case RTM_NEWLINK:
        case RTM_DELLINK:
            rc = filter_link(nh, NULL);
            if (changed && rc > 0)
                *changed |= CHANGE_LINK;
            return rc;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            rc = filter_addresses(nh, NULL);
            if (changed && rc > 0)
                *changed |= CHANGE_ADDR;
            return rc;
        default:
            kdebugf("filter_netlink: unexpected message type %d\n",
                    nh->nlmsg_type);
            break;
    }
    return 0;
}

int
kernel_addresses(char *ifname, int ifindex, int ll,
                 struct kernel_route *routes, int maxroutes)
{
    int maxr = maxroutes;
    int found = 0;
    void *data[] = { &maxr, routes, &found, &ifindex, &ll, NULL };
    struct rtgenmsg g;
    int rc;

    if (!nl_setup) {
        fprintf(stderr, "kernel_addresses: netlink not initialized.\n");
        errno = ENOSYS;
        return -1;
    }

    if (nl_command.sock < 0) {
        rc = netlink_socket(&nl_command, 0);
        if (rc < 0) {
            int save = errno;
            perror("kernel_addresses: netlink_socket()");
            errno = save;
            return -1;
        }
    }

    memset(&g, 0, sizeof(g));
    g.rtgen_family = AF_UNSPEC;
    rc = netlink_send_dump(RTM_GETADDR, &g, sizeof(g));
    if (rc < 0)
        return -1;

    rc = netlink_read(&nl_command, NULL, 1, filter_addresses, (void*)data);

    if (rc < 0)
        return -1;

    return found;
}

int
kernel_callback(int (*fn)(int, void*), void *closure)
{
    int rc;
    int changed = 0;

    kdebugf("\nReceived changes in kernel tables.\n");

    if(nl_listen.sock < 0) {
        rc = kernel_setup_socket(1);
        if(rc < 0) {
            perror("kernel_callback: kernel_setup_socket(1)");
            return -1;
        }
    }
    rc = netlink_read(&nl_listen, &nl_command, 0, filter_netlink, &changed);

    if(rc < 0 && nl_listen.sock < 0)
      kernel_setup_socket(1);

    /* if netlink return 0 (found something interesting) */
    /* or -1 (i.e. IO error), we call... back ! */
    if(rc)
        return fn(changed, closure);

    return 0;
}
