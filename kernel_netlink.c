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
#include <linux/fib_rules.h>
#include <net/if_arp.h>

/* From <linux/if_bridge.h> */
#ifndef BRCTL_GET_BRIDGES
#define BRCTL_GET_BRIDGES 1
#endif

#if(__GLIBC__ < 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ <= 5)
#define RTA_TABLE 15
#endif

#include "babeld.h"
#include "kernel.h"
#include "util.h"
#include "interface.h"
#include "configuration.h"

#ifndef MAX_INTERFACES
#define MAX_INTERFACES 1024
#endif

#define GET_PLEN(p, v4) (v4) ? (p) + 96 : (p)
#define COPY_ADDR(d, rta, v4)                                           \
    do {                                                                \
        if(UNLIKELY(RTA_PAYLOAD(rta) < (v4 ? 4 : 16))) {                \
            fprintf(stderr, "truncated message.");                      \
            return -1;                                                  \
        }                                                               \
        if(v4)                                                          \
            v4tov6(d, RTA_DATA(rta));                                   \
        else                                                            \
            memcpy(d, RTA_DATA(rta), 16);                               \
    } while(0)

int export_table = -1, import_tables[MAX_IMPORT_TABLES], import_table_count = 0;

struct sysctl_setting {
    char *name;
    int want;
    int was;
};
#define NUM_SYSCTLS 4

static struct sysctl_setting sysctl_settings[NUM_SYSCTLS] = {
    {"/proc/sys/net/ipv6/conf/all/forwarding", 1, -1},
    {"/proc/sys/net/ipv4/conf/all/forwarding", 1, -1},
    {"/proc/sys/net/ipv6/conf/all/accept_redirects", 0, -1},
    {"/proc/sys/net/ipv4/conf/all/rp_filter", 0, -1},
};

struct old_if {
    char *ifname;
    int rp_filter;
};

struct old_if *old_if = NULL;
int num_old_if = 0;
int max_old_if = 0;

static int dgram_socket = -1;

#ifndef ARPHRD_ETHER
#warning ARPHRD_ETHER not defined, we might not support exotic link layers
#define ARPHRD_ETHER 1
#define NO_ARPHRD
#endif

static int filter_netlink(struct nlmsghdr *nh, struct kernel_filter *filter);


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
    int rcvsize = 512 * 1024;

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

#ifdef SO_RCVBUFFORCE
    rc = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUFFORCE,
                    &rcvsize, sizeof(rcvsize));
#else
    rc = -1;
#endif
    if(rc < 0) {
        rc = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF,
                        &rcvsize, sizeof(rcvsize));
        if(rc < 0) {
            perror("setsockopt(SO_RCVBUF)");
        }
    }

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
             struct kernel_filter *filter)
{

    /* 'answer' must be true when we just have send a request on 'nl_socket' */

    /* 'nl_ignore' is used in kernel_callback to ignore message originating  */
    /*  from 'nl_command' while reading 'nl_listen'                          */

    /* Return code :                                       */
    /* -1 : error                                          */
    /*  0 : success                                        */

    int err;
    struct msghdr msg;
    struct sockaddr_nl nladdr;
    struct iovec iov;
    struct nlmsghdr *nh;
    int len;
    int done = 0;
    int skip = 0;

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
            return -1;
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
            return -1;
        }

        kdebugf("Netlink message: ");

        for(nh = (struct nlmsghdr *)buf;
            NLMSG_OK(nh, len);
            nh = NLMSG_NEXT(nh, len)) {
            kdebugf("%s{seq:%d}", (nh->nlmsg_flags & NLM_F_MULTI) ? "[multi] " : "",
                    nh->nlmsg_seq);
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
            } else if(nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK ) {
                kdebugf("detected an interface change via netlink - triggering babeld interface check\n");
                check_interfaces();
            } else if(skip) {
                kdebugf("(skip)");
            } if(filter) {
                kdebugf("(msg -> \"");
                err = filter_netlink(nh, filter);
                kdebugf("\" %d), ", err);
                if(err < 0) skip = 1;
                continue;
            }
            kdebugf(", ");
        }
        kdebugf("\n");

        if(msg.msg_flags & MSG_TRUNC)
            fprintf(stderr, "netlink_read: message truncated\n");

    } while(!done);

    return 0;

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

    kdebugf("Sending seqno %d from address %p (talk)\n",
            nl_command.seqno, (void*)&nl_command.seqno);

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

    rc = netlink_read(&nl_command, NULL, 1, NULL); /* ACK */

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

    kdebugf("Sending seqno %d from address %p (dump)\n",
            nl_command.seqno, (void*)&nl_command.seqno);

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
    struct sysctl_setting *s;
    int i, rc;

    if(setup) {
        if(export_table < 0)
            export_table = RT_TABLE_MAIN;

        if(import_table_count < 1)
            import_tables[import_table_count++] = RT_TABLE_MAIN;

        dgram_socket = socket(PF_INET, SOCK_DGRAM, 0);
        if(dgram_socket < 0)
            return -1;

        rc = netlink_socket(&nl_command, 0);
        if(rc < 0) {
            perror("netlink_socket(0)");
            return -1;
        }
        nl_setup = 1;

        if(skip_kernel_setup) return 1;

        for(i=0; i<NUM_SYSCTLS; i++) {
            s = &sysctl_settings[i];
            s->was = read_proc(s->name);
            if(s->was < 0) {
                perror("Couldn't read sysctl");
                return -1;
            }
            if(s->was != s->want) {
                rc = write_proc(s->name, s->want);
                if(rc < 0) {
                    perror("Couldn't write sysctl");
                    return -1;
                }
            }
        }

        return 1;
    } else {
        close(dgram_socket);
        dgram_socket = -1;

        close(nl_command.sock);
        nl_command.sock = -1;
        nl_setup = 0;

        if(skip_kernel_setup) return 1;

        for(i=0; i<NUM_SYSCTLS; i++) {
            s = &sysctl_settings[i];
            if(s->was >= 0 && s->was != s->want) {
                rc = write_proc(s->name,s->was);
                if(rc < 0) {
                    perror("Couldn't write sysctl");
                    return -1;
                }
            }
        }

        return 1;

    }
}

static inline unsigned int
rtnlgrp_to_mask(unsigned int grp)
{
    return grp ? 1 << (grp - 1) : 0;
}

int
kernel_setup_socket(int setup)
{
    int rc;

    if(setup) {
        rc = netlink_socket(&nl_listen,
                            rtnlgrp_to_mask(RTNLGRP_IPV6_ROUTE)
                          | rtnlgrp_to_mask(RTNLGRP_IPV4_ROUTE)
                          | rtnlgrp_to_mask(RTNLGRP_LINK)
                          | rtnlgrp_to_mask(RTNLGRP_IPV4_IFADDR)
                          | rtnlgrp_to_mask(RTNLGRP_IPV6_IFADDR)
    /* We monitor rules, because it can be change by third parties.  For example
       a /etc/init.d/network restart on OpenWRT flush the rules. */
                          | rtnlgrp_to_mask(RTNLGRP_IPV4_RULE)
                          | rtnlgrp_to_mask(RTNLGRP_IPV6_RULE));
        if(rc < 0) {
            perror("netlink_socket(_ROUTE | _LINK | _IFADDR | _RULE)");
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

static int
get_old_if(const char *ifname)
{
    int i;
    for(i = 0; i < num_old_if; i++)
        if(strcmp(old_if[i].ifname, ifname) == 0)
            return i;
    if(num_old_if >= MAX_INTERFACES)
        return -1;
    if(num_old_if >= max_old_if) {
            int n = max_old_if == 0 ? 4 : 2 * max_old_if;
            struct old_if *new =
                realloc(old_if, n * sizeof(struct old_if));
            if(new != NULL) {
                old_if = new;
                max_old_if = n;
            }
    }
    if(num_old_if >= max_old_if)
        return -1;

    old_if[num_old_if].ifname = strdup(ifname);
    if(old_if[num_old_if].ifname == NULL)
        return -1;
    old_if[num_old_if].rp_filter = -1;
    return num_old_if++;
}

int
kernel_setup_interface(int setup, const char *ifname, int ifindex)
{
    char buf[100];
    int i, rc;

    /* rp_filter has weird semantics: both all/rp_filter and ifname/rp_filter
       must be set to 0 for the rp_filter to be disabled.  Deal with it. */

    rc = snprintf(buf, 100, "/proc/sys/net/ipv4/conf/%s/rp_filter", ifname);
    if(rc < 0 || rc >= 100)
        return -1;

    i = get_old_if(ifname);
    if(setup) {
        if(i >= 0)
            old_if[i].rp_filter = read_proc(buf);
        if(i < 0 || old_if[i].rp_filter < 0)
            fprintf(stderr,
                    "Warning: cannot save old configuration for %s.\n",
                    ifname);
	if(old_if[i].rp_filter) {
	    rc = write_proc(buf, 0);
	    if(rc < 0)
		return -1;
	}
    } else {
        if(i >= 0 && old_if[i].rp_filter > 0)
            rc = write_proc(buf, old_if[i].rp_filter);
        else if(i < 0)
            rc = -1;
        else
            rc = 1;

        if(rc < 0)
            fprintf(stderr,
                    "Warning: cannot restore old configuration for %s.\n",
                    ifname);
    }

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

static int
isbatman(const char *ifname, int ifindex)
{
    char buf[256];
    int rc;

    rc = snprintf(buf, 256, "/sys/devices/virtual/net/%s/mesh", ifname);
    if(rc < 0 || rc >= 256)
        return -1;

    if(access(buf, F_OK) >= 0)
        return 1;

    if(errno != ENOENT)
        return -1;

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

    if(isbridge(ifname, ifindex) != 0 || isbatman(ifname, ifindex) != 0)
        return -1;

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

/* Return true if we cannot handle disambiguation ourselves. */

int
kernel_disambiguate(int v4)
{
    return !v4 && has_ipv6_subtrees;
}

int
kernel_has_ipv6_subtrees(void)
{
    return (kernel_older_than("Linux", 3, 11) == 0);
}

int
kernel_route(int operation, int table,
             const unsigned char *dest, unsigned short plen,
             const unsigned char *src, unsigned short src_plen,
             const unsigned char *pref_src,
             const unsigned char *gate, int ifindex, unsigned int metric,
             const unsigned char *newgate, int newifindex,
             unsigned int newmetric, int newtable)
{
    union { char raw[1024]; struct nlmsghdr nh; } buf;
    struct rtmsg *rtm;
    struct rtattr *rta;
    int len = sizeof(buf.raw);
    int rc, ipv4, use_src = 0;

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
        if(!v4mapped(gate) ||
           !v4mapped(src)) {
            errno = EINVAL;
            return -1;
        }
    } else {
        if(v4mapped(gate) || v4mapped(src)) {
            errno = EINVAL;
            return -1;
        }
    }

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
        kernel_route(ROUTE_FLUSH, table, dest, plen,
                     src, src_plen, pref_src,
                     gate, ifindex, metric,
                     NULL, 0, 0, 0);
        rc = kernel_route(ROUTE_ADD, newtable, dest, plen,
                          src, src_plen, pref_src,
                          newgate, newifindex, newmetric,
                          NULL, 0, 0, 0);
        if(rc < 0) {
            if(errno == EEXIST)
                rc = 1;
            /* Should we try to re-install the flushed route on failure?
               Error handling is hard. */
        }
        return rc;
    }


    ipv4 = v4mapped(gate);
    use_src = (!is_default(src, src_plen) && kernel_disambiguate(ipv4));

    kdebugf("kernel_route: %s %s from %s "
            "table %d metric %d dev %d nexthop %s\n",
            operation == ROUTE_ADD ? "add" :
            operation == ROUTE_FLUSH ? "flush" : "???",
            format_prefix(dest, plen), format_prefix(src, src_plen),
            table, metric, ifindex, format_address(gate));

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
    if(use_src)
        rtm->rtm_src_len = src_plen;
    rtm->rtm_table = table;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    if(metric < KERNEL_INFINITY) {
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_flags |= RTNH_F_ONLINK;
    } else
        rtm->rtm_type = RTN_UNREACHABLE;

    rtm->rtm_protocol = RTPROT_BABEL;

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
        if(use_src) {
            rta = RTA_NEXT(rta, len);
            rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr));
            rta->rta_type = RTA_SRC;
            memcpy(RTA_DATA(rta), src, sizeof(struct in6_addr));
        }
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

#define ADD_IPARG(type, addr) \
        do if(ipv4) { \
            rta = RTA_NEXT(rta, len); \
            rta->rta_len = RTA_LENGTH(sizeof(struct in_addr)); \
            rta->rta_type = type; \
            memcpy(RTA_DATA(rta), addr + 12, sizeof(struct in_addr)); \
        } else { \
            rta = RTA_NEXT(rta, len); \
            rta->rta_len = RTA_LENGTH(sizeof(struct in6_addr)); \
            rta->rta_type = type; \
            memcpy(RTA_DATA(rta), addr, sizeof(struct in6_addr)); \
        } while (0)

        ADD_IPARG(RTA_GATEWAY, gate);
        if(pref_src)
            ADD_IPARG(RTA_PREFSRC, pref_src);

#undef ADD_IPARG
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
    int i, is_v4;

    len -= NLMSG_ALIGN(sizeof(*rtm));

    memset(route, 0, sizeof(struct kernel_route));
    if(rtm->rtm_family == AF_INET) {
        /* if RTA_DST is not a TLV, that's a default destination */
        const unsigned char zeroes[4] = {0, 0, 0, 0};
        v4tov6(route->prefix, zeroes);
        v4tov6(route->src_prefix, zeroes);
        route->plen = 96;
        route->src_plen = 96;
    }
    route->proto = rtm->rtm_protocol;

    is_v4 = rtm->rtm_family == AF_INET;

    while(RTA_OK(rta, len)) {
        switch(rta->rta_type) {
        case RTA_DST:
            route->plen = GET_PLEN(rtm->rtm_dst_len, is_v4);
            COPY_ADDR(route->prefix, rta, is_v4);
            break;
        case RTA_SRC:
            route->src_plen = GET_PLEN(rtm->rtm_src_len, is_v4);
            COPY_ADDR(route->src_prefix, rta, is_v4);
            break;
        case RTA_GATEWAY:
            COPY_ADDR(route->gw, rta, is_v4);
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

    for(i = 0; i < import_table_count; i++)
        if(table == import_tables[i])
            return 0;

    return -1;
}

static void
print_kernel_route(int add, int protocol, int type,
                   struct kernel_route *route)
{
    char ifname[IFNAMSIZ];
    char addr_prefix[INET6_ADDRSTRLEN];
    char src_addr_prefix[INET6_ADDRSTRLEN];
    char addr_gw[INET6_ADDRSTRLEN];

    if(!inet_ntop(AF_INET6, route->prefix,
                  addr_prefix, sizeof(addr_prefix)) ||
       !inet_ntop(AF_INET6,route->gw, addr_gw, sizeof(addr_gw)) ||
       !if_indextoname(route->ifindex, ifname)) {
        kdebugf("Couldn't format kernel route for printing.");
        return;
    }

    if(route->src_plen >= 0) {
        if(!inet_ntop(AF_INET6, route->src_prefix,
                      src_addr_prefix, sizeof(src_addr_prefix))) {
            kdebugf("Couldn't format kernel route for printing.");
            return;
        }

        kdebugf("%s kernel route: dest: %s/%d gw: %s metric: %d if: %s "
                "(proto: %d, type: %d, from: %s/%d)",
                add == RTM_NEWROUTE ? "Add" : "Delete",
                addr_prefix, route->plen, addr_gw, route->metric, ifname,
                protocol, type, src_addr_prefix, route->src_plen);
        return;
    }

    kdebugf("%s kernel route: dest: %s/%d gw: %s metric: %d if: %s "
           "(proto: %d, type: %d)",
           add == RTM_NEWROUTE ? "Add" : "Delete",
           addr_prefix, route->plen, addr_gw, route->metric, ifname,
           protocol, type);
}

static int
filter_kernel_routes(struct nlmsghdr *nh, struct kernel_route *route)
{
    int rc, len;
    struct rtmsg *rtm;

    len = nh->nlmsg_len;

    if(nh->nlmsg_type != RTM_NEWROUTE &&
       nh->nlmsg_type != RTM_DELROUTE)
        return 0;

    rtm = (struct rtmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    if(rtm->rtm_protocol == RTPROT_BABEL)
        return 0;

    /* Ignore cached routes, advertised by some kernels (linux 3.x). */
    if(rtm->rtm_flags & RTM_F_CLONED)
        return 0;

    rc = parse_kernel_route_rta(rtm, len, route);
    if(rc < 0)
        return 0;

    /* Ignore default unreachable routes; no idea where they come from. */
    if(route->plen == 0 && route->metric >= KERNEL_INFINITY)
        return 0;

    if(debug >= 2) {
        if(rc >= 0) {
            print_kernel_route(nh->nlmsg_type, rtm->rtm_protocol,
                               rtm->rtm_type, route);
        }
    }

    return 1;

}

/* This function should not return routes installed by us. */
int
kernel_dump(int operation, struct kernel_filter *filter)
{
    int i, rc;
    int families[2] = { AF_INET6, AF_INET };
    struct rtgenmsg g;

    if(!nl_setup) {
        fprintf(stderr,"kernel_dump: netlink not initialized.\n");
        errno = EIO;
        return -1;
    }

    if(nl_command.sock < 0) {
        rc = netlink_socket(&nl_command, 0);
        if(rc < 0) {
            int save = errno;
            perror("kernel_dump: netlink_socket()");
            errno = save;
            return -1;
        }
    }

    for(i = 0; i < 2; i++) {
        memset(&g, 0, sizeof(g));
        g.rtgen_family = families[i];
        if(operation & CHANGE_ROUTE) {
            rc = netlink_send_dump(RTM_GETROUTE, &g, sizeof(g));
            if(rc < 0)
                return -1;

            rc = netlink_read(&nl_command, NULL, 1, filter);
            if(rc < 0)
                return -1;
        }

        memset(&g, 0, sizeof(g));
        g.rtgen_family = families[i];
        if(operation & CHANGE_RULE) {
            rc = netlink_send_dump(RTM_GETRULE, &g, sizeof(g));
            if(rc < 0)
                return -1;

            rc = netlink_read(&nl_command, NULL, 1, filter);
            if(rc < 0)
                return -1;
        }
    }

    if(operation & CHANGE_ADDR) {
        memset(&g, 0, sizeof(g));
        g.rtgen_family = AF_UNSPEC;
        rc = netlink_send_dump(RTM_GETADDR, &g, sizeof(g));
        if(rc < 0)
            return -1;

        rc = netlink_read(&nl_command, NULL, 1, filter);
        if(rc < 0)
            return -1;
    }

    return 0;
}

static char *
parse_ifname_rta(struct ifinfomsg *info, int len)
{
    struct rtattr *rta = IFLA_RTA(info);
    char *ifname = NULL;

    len -= NLMSG_ALIGN(sizeof(*info));

    while(RTA_OK(rta, len)) {
        switch(rta->rta_type) {
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
    int is_local = 0;

    while(RTA_OK(rta, len)) {
        switch(rta->rta_type) {
        case IFA_LOCAL:
            /* On some point-to-point technologies, there's both _LOCAL
               and _ADDRESS, and _ADDRESS is apparently the peer address
               while _LOCAL is the one we want. */
            is_local = 1;
            /* fallthrough */
        case IFA_ADDRESS:
            switch(addr->ifa_family) {
            case AF_INET:
                if(res)
                    v4tov6(res->s6_addr, RTA_DATA(rta));
                break;
            case AF_INET6:
                if(res)
                    memcpy(res->s6_addr, RTA_DATA(rta), 16);
                break;
            default:
                kdebugf("ifaddr: unexpected address family %d\n",
                        addr->ifa_family);
                return -1;
                break;
            }
            if(is_local)
                return 0;
            break;
        default:
            break;
        }
        rta = RTA_NEXT(rta, len);
    }
    return 0;
}

static int
filter_link(struct nlmsghdr *nh, struct kernel_link *link)
{
    struct ifinfomsg *info;
    int len;
    int ifindex;
    unsigned int ifflags;

    len = nh->nlmsg_len;

    if(nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK)
        return 0;

    info = (struct ifinfomsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    ifindex = info->ifi_index;
    ifflags = info->ifi_flags;

    link->ifname = parse_ifname_rta(info, len);
    if(link->ifname == NULL)
        return 0;
    kdebugf("filter_interfaces: link change on if %s(%d): 0x%x\n",
            link->ifname, ifindex, (unsigned)ifflags);
    return 1;
}

/* If data is null, takes all addresses.  If data is not null, takes
   either link-local or global addresses depending of the value of
   data[4]. */

static int
filter_addresses(struct nlmsghdr *nh, struct kernel_addr *addr)
{
    int rc;
    int len;
    struct ifaddrmsg *ifa;
    char ifname[IFNAMSIZ];

    len = nh->nlmsg_len;

    if(nh->nlmsg_type != RTM_NEWADDR &&
       nh->nlmsg_type != RTM_DELADDR)
        return 0;

    ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    rc = parse_addr_rta(ifa, len, &addr->addr);
    if(rc < 0)
        return 0;
    addr->ifindex = ifa->ifa_index;

    kdebugf("found address on interface %s(%d): %s\n",
            if_indextoname(ifa->ifa_index, ifname), ifa->ifa_index,
            format_address(addr->addr.s6_addr));

    return 1;
}

static int
filter_kernel_rules(struct nlmsghdr *nh, struct kernel_rule *rule)
{
    int len, has_priority = 0, has_table = 0;
    struct rtmsg *rtm = NULL;
    struct rtattr *rta = NULL;
    int is_v4 = 0;

    len = nh->nlmsg_len;

    rtm = (struct rtmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    rule->src_plen = rtm->rtm_src_len;
    memset(rule->src, 0, sizeof(rule->src));
    rule->table = rtm->rtm_table;

    if(rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6) {
        kdebugf("filter_rules: Unknown family: %d\n", rtm->rtm_family);
        return -1;
    }
    is_v4 = rtm->rtm_family == AF_INET;

    rta = RTM_RTA(rtm);
    len -= NLMSG_ALIGN(sizeof(*rtm));

    for(; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch(rta->rta_type) {
        case FRA_UNSPEC: break;
        case FRA_SRC:
            rule->src_plen = GET_PLEN(rtm->rtm_src_len, is_v4);
            COPY_ADDR(rule->src, rta, is_v4);
            break;
        case FRA_PRIORITY:
            rule->priority = *(unsigned int*)RTA_DATA(rta);
            has_priority = 1;
            break;
        case FRA_TABLE:
            rule->table = *(int*)RTA_DATA(rta);
            has_table = 1;
            break;
        default:
            kdebugf("filter_rules: Unknown rule attribute: %d.\n",
                    rta->rta_type);
            break;
        }
    }

    kdebugf("filter_rules: from %s prio %d table %d\n",
            format_prefix(rule->src, rule->src_plen),
            has_priority ? rule->priority : -1, rule->table);

    if(!has_priority || !has_table)
        return 0;

    return 1;
}

static int
filter_netlink(struct nlmsghdr *nh, struct kernel_filter *filter)
{
    int rc;
    union {
        struct kernel_route route;
        struct kernel_addr addr;
        struct kernel_link link;
        struct kernel_rule rule;
    } u;

    switch(nh->nlmsg_type) {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
        if(!filter->route) break;
        rc = filter_kernel_routes(nh, &u.route);
        if(rc <= 0) break;
        return filter->route(&u.route, filter->route_closure);
    case RTM_NEWLINK:
    case RTM_DELLINK:
        if(!filter->link) break;
        rc = filter_link(nh, &u.link);
        if(rc <= 0) break;
        return filter->link(&u.link, filter->link_closure);
    case RTM_NEWADDR:
    case RTM_DELADDR:
        if(!filter->addr) break;
        rc = filter_addresses(nh, &u.addr);
        if(rc <= 0) break;
        return filter->addr(&u.addr, filter->addr_closure);
    case RTM_NEWRULE:
    case RTM_DELRULE:
        if(!filter->rule) break;
        rc = filter_kernel_rules(nh, &u.rule);
        if(rc <= 0) break;
        return filter->rule(&u.rule, filter->rule_closure);
    default:
        kdebugf("filter_netlink: unexpected message type %d\n",
                nh->nlmsg_type);
        break;
    }
    return 0;
}

int
kernel_callback(struct kernel_filter *filter)
{
    int rc;

    kdebugf("\nReceived changes in kernel tables.\n");

    if(nl_listen.sock < 0) {
        rc = kernel_setup_socket(1);
        if(rc < 0) {
            perror("kernel_callback: kernel_setup_socket(1)");
            return -1;
        }
    }
    rc = netlink_read(&nl_listen, &nl_command, 0, filter);

    if(rc < 0 && nl_listen.sock < 0)
        kernel_setup_socket(1);

    return 0;
}


/* Routing table's rules */

int
add_rule(int prio, const unsigned char *src_prefix, int src_plen, int table)
{
    char buffer[64] = {0}; /* 56 needed */
    struct nlmsghdr *message_header = (void*)buffer;
    struct rtmsg *message = NULL;
    struct rtattr *current_attribute = NULL;
    int is_v4 = v4mapped(src_prefix);
    int addr_size = is_v4 ? sizeof(struct in_addr) : sizeof(struct in6_addr);

    kdebugf("Add rule v%c prio %d from %s\n", is_v4 ? '4' : '6', prio,
            format_prefix(src_prefix, src_plen));

    if(is_v4) {
        src_prefix += 12;
        src_plen -= 96;
        if(src_plen < 0) {
            errno = EINVAL;
            return -1;
        }
    }

#if RTA_ALIGNTO != NLMSG_ALIGNTO
#error "RTA_ALIGNTO != NLMSG_ALIGNTO"
#endif

    /* Set the header */
    message_header->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    message_header->nlmsg_type  = RTM_NEWRULE;
    message_header->nlmsg_len   = NLMSG_ALIGN(sizeof(struct nlmsghdr));

    /* Append the message */
    message = NLMSG_DATA(message_header);
    message->rtm_family = is_v4 ? AF_INET : AF_INET6;
    message->rtm_dst_len = 0;
    message->rtm_src_len = src_plen;
    message->rtm_tos = 0;
    message->rtm_table = table;
    message->rtm_protocol = RTPROT_BABEL;
    message->rtm_scope = RT_SCOPE_UNIVERSE;
    message->rtm_type = RTN_UNICAST;
    message->rtm_flags = 0;
    message_header->nlmsg_len += NLMSG_ALIGN(sizeof(struct rtmsg));

    /* Append each attribute */
    current_attribute = RTM_RTA(message);
    /* prio */
    current_attribute->rta_len = RTA_LENGTH(sizeof(int));
    current_attribute->rta_type = FRA_PRIORITY;
    *(int*)RTA_DATA(current_attribute) = prio;

    message_header->nlmsg_len += current_attribute->rta_len;
    current_attribute = (void*)
        ((char*)current_attribute + current_attribute->rta_len);

    /* src */
    current_attribute->rta_len = RTA_LENGTH(addr_size);
    current_attribute->rta_type = FRA_SRC;
    memcpy(RTA_DATA(current_attribute), src_prefix, addr_size);

    message_header->nlmsg_len += current_attribute->rta_len;
    current_attribute = (void*)
        ((char*)current_attribute + current_attribute->rta_len);

    /* send message */
    if(message_header->nlmsg_len > 64) {
        errno = EINVAL;
        return -1;
    }
    return netlink_talk(message_header);
}

int
flush_rule(int prio, int family)
{
    char buffer[64] = {0}; /* 36 needed */
    struct nlmsghdr *message_header = (void*)buffer;
    struct rtmsg *message = NULL;
    struct rtattr *current_attribute = NULL;

    memset(buffer, 0, sizeof(buffer));

    kdebugf("Flush rule v%c prio %d\n", family == AF_INET ? '4' : '6', prio);

#if RTA_ALIGNTO != NLMSG_ALIGNTO
#error "RTA_ALIGNTO != NLMSG_ALIGNTO"
#endif

    /* Set the header */
    message_header->nlmsg_flags = NLM_F_REQUEST;
    message_header->nlmsg_type  = RTM_DELRULE;
    message_header->nlmsg_len   = NLMSG_ALIGN(sizeof(struct nlmsghdr));

    /* Append the message */
    message = NLMSG_DATA(message_header);
    message->rtm_family = family;
    message->rtm_dst_len = 0;
    message->rtm_src_len = 0;
    message->rtm_tos = 0;
    message->rtm_table = 0;
    message->rtm_protocol = RTPROT_BABEL;
    message->rtm_scope = RT_SCOPE_UNIVERSE;
    message->rtm_type = RTN_UNSPEC;
    message->rtm_flags = 0;
    message_header->nlmsg_len += NLMSG_ALIGN(sizeof(struct rtmsg));

    /* Append each attribute */
    current_attribute = RTM_RTA(message);
    /* prio */
    current_attribute->rta_len = RTA_LENGTH(sizeof(int));
    current_attribute->rta_type = FRA_PRIORITY;
    *(int*)RTA_DATA(current_attribute) = prio;

    message_header->nlmsg_len += current_attribute->rta_len;
    current_attribute = (void*)
        ((char*)current_attribute + current_attribute->rta_len);

    /* send message */
    if(message_header->nlmsg_len > 64) {
        errno = EINVAL;
        return -1;
    }
    return netlink_talk(message_header);
}

int
change_rule(int new_prio, int old_prio,
            const unsigned char *src, int plen, int table)
{
    int rc;
    kdebugf("/Swap: ");
    rc = add_rule(new_prio, src, plen, table);
    if(rc < 0)
        return rc;
    kdebugf("\\Swap: ");
    return flush_rule(old_prio, v4mapped(src) ? AF_INET : AF_INET6);
}
