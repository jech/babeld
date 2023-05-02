/*
Copyright (c) 2007 by Grégoire Henry
Copyright (c) 2008, 2009 by Juliusz Chroboczek
Copyright (c) 2010 by Vincent Gross

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
#include <strings.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/route.h>

#include "babeld.h"
#include "interface.h"
#include "neighbour.h"
#include "kernel.h"
#include "util.h"



static int get_sdl(struct sockaddr_dl *sdl, char *ifname);

int export_table = -1, import_table_count = 0, import_tables[MAX_IMPORT_TABLES];

int
if_eui64(char *ifname, int ifindex, unsigned char *eui)
{
    struct sockaddr_dl sdl;
    char *tmp = NULL;
    if(get_sdl(&sdl, ifname) < 0) {
        return -1;
    }
    tmp = sdl.sdl_data + sdl.sdl_nlen;
    if(sdl.sdl_alen == 8) {
        memcpy(eui, tmp, 8);
        eui[0] ^= 2;
    } else if(sdl.sdl_alen == 6) {
        memcpy(eui,   tmp,   3);
        eui[3] = 0xFF;
        eui[4] = 0xFE;
        memcpy(eui+5, tmp+3, 3);
    } else {
        return -1;
    }
    return 0;
}

/* fill sdl with the structure corresponding to ifname.
 Warning: make a syscall (and get all interfaces).
 return -1 if an error occurs, 0 otherwise. */
static int
get_sdl(struct sockaddr_dl *sdl, char *ifname)
{
    int mib[6];
    size_t buf_len = 0;
    int offset = 0;
    char *buffer = NULL;
    struct if_msghdr *ifm = NULL;
    struct sockaddr_dl *tmp_sdl = NULL;
    int rc;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;

    rc = sysctl(mib, 6, NULL, &buf_len, NULL, 0);
    if(rc < 0)
        return -1;

    buffer = (char *)malloc(buf_len);
    if(buffer == NULL)
        return -1;

    rc = sysctl(mib, 6, buffer, &buf_len, NULL, 0);
    if(rc < 0)
        goto fail;

    offset = 0;
    while(offset < (int) buf_len) {
        ifm = (struct if_msghdr *) &buffer[offset];
        switch(ifm->ifm_type) {
        case RTM_IFINFO:
            tmp_sdl = (struct sockaddr_dl *) (ifm + 1);
            if(strncmp(ifname, tmp_sdl->sdl_data, tmp_sdl->sdl_nlen) == 0
               && strlen(ifname) == tmp_sdl->sdl_nlen) {
                memcpy(sdl, tmp_sdl, sizeof(struct sockaddr_dl));
                return 0;
            }
        default:
            break;
        }
        offset += ifm->ifm_msglen;
    }

fail:
    free(buffer);
    return -1;
}

/* KAME said : "Following two macros are highly depending on KAME Release" */
#define IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr[2] << 8 | (a).s6_addr[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)         \
    do {                                        \
        (a).s6_addr[2] = ((i) >> 8) & 0xff;     \
        (a).s6_addr[3] = (i) & 0xff;            \
    } while(0)

#if defined(__APPLE__)
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#else
#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif

static int old_forwarding = -1;
static int old_accept_redirects = -1;

static int ifindex_lo = -1;
static int seq;

static int
mask2len(const unsigned char *p, const int size)
{
    int i = 0, j;

    for(j = 0; j < size; j++, p++) {
        if(*p != 0xff)
            break;
        i += 8;
    }
    if(j < size) {
        switch(*p) {
#define MASKLEN(m, l) case m: do { i += l; break; } while(0)
            MASKLEN(0xfe, 7); break;
            MASKLEN(0xfc, 6); break;
            MASKLEN(0xf8, 5); break;
            MASKLEN(0xf0, 4); break;
            MASKLEN(0xe0, 3); break;
            MASKLEN(0xc0, 2); break;
            MASKLEN(0x80, 1); break;
#undef MASKLEN
        }
    }
    return i;
}

static void
plen2mask(int n, struct in6_addr *dest)
{
    unsigned char *p;
    int i;

    static const int pl2m[9] = {
        0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
    };

    memset(dest, 0, sizeof(struct in6_addr));
    p = (u_char *)dest;
    for(i = 0; i < 16; i++, p++, n -= 8) {
        if(n >= 8) {
            *p = 0xff;
            continue;
        }
        *p = pl2m[n];
        break;
    }
    return;
}

int
kernel_setup(int setup)
{
    int rc = 0;
    int forwarding = 1;
    int accept_redirects = 0;
    int mib[4];
    size_t datasize;

    if(skip_kernel_setup) return 1;

    mib[0] = CTL_NET;
    mib[1] = AF_INET6;
    seq = time(NULL);

    mib[2] = IPPROTO_IPV6;
    mib[3] = IPV6CTL_FORWARDING;
    datasize = sizeof(old_forwarding);
    if(setup) {
        rc = sysctl(mib, 4, &old_forwarding, &datasize, NULL, 0);
        if(rc == 0 && old_forwarding != forwarding) {
            rc = sysctl(mib, 4, &old_forwarding, &datasize,
                        &forwarding, datasize);
        }
    }
    else if(old_forwarding >= 0 && old_forwarding != forwarding)
        rc = sysctl(mib, 4, NULL, NULL,
                    &old_forwarding, datasize);
    if(rc == -1) {
        perror("Couldn't tweak forwarding knob.");
        return -1;
    }

    rc = 0;
    mib[2] = IPPROTO_ICMPV6;
#if defined(IPV6CTL_SENDREDIRECTS)
    mib[3] = IPV6CTL_SENDREDIRECTS;
#else
    mib[3] = ICMPV6CTL_REDIRACCEPT;
#endif
    datasize = sizeof(old_accept_redirects);
    if(setup) {
        rc = sysctl(mib, 4, &old_accept_redirects, &datasize, NULL, 0);
        if(rc == 0 && old_accept_redirects != accept_redirects) {
            rc = sysctl(mib, 4, &old_accept_redirects, &datasize,
                        &accept_redirects, datasize);
        }
    } else if(old_accept_redirects >= 0 && old_accept_redirects != accept_redirects)
        rc = sysctl(mib, 4, NULL, NULL,
                    &old_accept_redirects, datasize);
    if(rc == -1) {
        perror("Couldn't tweak accept_redirects knob.");
        return -1;
    }
    return 1;
}

int
kernel_setup_socket(int setup)
{
    int rc;
    int zero = 0;
    if(setup) {
        if(kernel_socket < 0) {
            kernel_socket = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
            if(kernel_socket < 0)
                return -1;
        }
        rc = setsockopt(kernel_socket, SOL_SOCKET, SO_USELOOPBACK,
                        &zero, sizeof(zero));
        if(rc < 0)
            goto error;
        return 1;
    } else {
        close(kernel_socket);
        kernel_socket = -1;
        return 1;
    }

 error: {
        int savederrno = errno;
        perror("setsockopt(kernel_socket)");
        close(kernel_socket);
        errno = savederrno;
        kernel_socket = -1;
        return -1;
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
    int s, rc;
    int flags = link_detect ? (IFF_UP | IFF_RUNNING) : IFF_UP;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(s, SIOCGIFFLAGS, &req);
    close(s);
    if(rc < 0)
        return -1;
    return ((req.ifr_flags & flags) == flags);
}

int
kernel_interface_ipv4(const char *ifname, int ifindex, unsigned char *addr_r)
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
    close(s);
    if(rc < 0) {
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
    struct ifmediareq ifmr;
    int s, rc;

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    memset(&ifmr, 0, sizeof(ifmr));
    strncpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));
    rc = ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr);
    close(s);
    if(rc < 0)
        return rc;
    if((ifmr.ifm_active & IFM_NMASK) == IFM_IEEE80211)
        return 1;
    else
        return 0;
}

int
kernel_has_ipv6_subtrees(void)
{
    return 0;
}

int
kernel_has_v4viav6(void)
{
    return 0;
}

int
kernel_safe_v4viav6(void)
{
    return 0;
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
    struct {
        struct rt_msghdr m_rtm;
        char m_space[512];
    } msg;
    char *data = msg.m_space;
    int rc, ipv4;

    char local6[1][1][16] = IN6ADDR_LOOPBACK_INIT;
    char local4[1][1][16] =
        {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01 }}};

    /* Source-specific routes & preferred source IPs
     * are not implemented yet for BSD. */
    if((!is_default(src, src_plen)) || pref_src) {
        errno = ENOSYS;
        return -1;
    }

    /* Check that the protocol family is consistent. */
    if(plen >= 96 && v4mapped(dest)) {
        if(!v4mapped(gate)) {
            errno = EINVAL;
            return -1;
        }
        ipv4 = 1;
    } else {
        if(v4mapped(gate)) {
            errno = EINVAL;
            return -1;
        }
        ipv4 = 0;
    }

    if(operation == ROUTE_MODIFY && newmetric == metric &&
       memcmp(newgate, gate, 16) == 0 && newifindex == ifindex)
        return 0;


    if(operation == ROUTE_MODIFY) {

        /* Avoid atomic route changes that is buggy on OS X. */
        kernel_route(ROUTE_FLUSH, table, dest, plen,
                     src, src_plen, NULL,
                     gate, ifindex, metric,
                     NULL, 0, 0, 0);
        return kernel_route(ROUTE_ADD, table, dest, plen,
                            src, src_plen, NULL,
                            newgate, newifindex, newmetric,
                            NULL, 0, 0, 0);

    }

    kdebugf("kernel_route: %s %s/%d metric %d dev %d nexthop %s\n",
            operation == ROUTE_ADD ? "add" :
            operation == ROUTE_FLUSH ? "flush" : "change",
            format_address(dest), plen, metric, ifindex,
            format_address(gate));

    if(kernel_socket < 0) kernel_setup_socket(1);

    memset(&msg, 0, sizeof(msg));
    msg.m_rtm.rtm_version = RTM_VERSION;
    switch(operation) {
    case ROUTE_FLUSH:
        msg.m_rtm.rtm_type = RTM_DELETE; break;
    case ROUTE_ADD:
        msg.m_rtm.rtm_type = RTM_ADD; break;
    case ROUTE_MODIFY:
        msg.m_rtm.rtm_type = RTM_CHANGE; break;
    default:
        return -1;
    };
    msg.m_rtm.rtm_index = ifindex;
    msg.m_rtm.rtm_flags = RTF_UP | RTF_PROTO2;
    if(plen == 128) msg.m_rtm.rtm_flags |= RTF_HOST;
    if(metric == KERNEL_INFINITY) {
        msg.m_rtm.rtm_flags |= RTF_BLACKHOLE;
        if(ifindex_lo < 0) {
            ifindex_lo = if_nametoindex("lo0");
            if(ifindex_lo <= 0)
                return -1;
        }
        msg.m_rtm.rtm_index = ifindex_lo;
    }
    msg.m_rtm.rtm_seq = ++seq;
    msg.m_rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;
    if(plen != 128) msg.m_rtm.rtm_addrs |= RTA_NETMASK;

#define PUSHEUI(ifindex) \
    do { char ifname[IFNAMSIZ]; \
         struct sockaddr_dl *sdl = (struct sockaddr_dl*) data; \
         if(!if_indextoname((ifindex), ifname))  \
             return -1; \
         if(get_sdl(sdl, ifname) < 0)   \
             return -1; \
         data = data + ROUNDUP(sdl->sdl_len); \
    } while(0)

#define PUSHADDR(src) \
    do { struct sockaddr_in *sin = (struct sockaddr_in*) data; \
         sin->sin_len = sizeof(struct sockaddr_in);  \
         sin->sin_family = AF_INET; \
         memcpy(&sin->sin_addr, (src) + 12, 4); \
         data = data + ROUNDUP(sin->sin_len); \
    } while(0)

#define PUSHADDR6(src) \
    do { struct sockaddr_in6 *sin6 = (struct sockaddr_in6*) data; \
         sin6->sin6_len = sizeof(struct sockaddr_in6); \
         sin6->sin6_family = AF_INET6; \
         memcpy(&sin6->sin6_addr, (src), 16); \
         if(IN6_IS_ADDR_LINKLOCAL (&sin6->sin6_addr)) \
             SET_IN6_LINKLOCAL_IFINDEX (sin6->sin6_addr, ifindex); \
         data = data + ROUNDUP(sin6->sin6_len); \
    } while(0)

    /* KAME ipv6 stack does not support IPv4 mapped IPv6, so we have to
     * duplicate the codepath */
    if(ipv4) {

        PUSHADDR(dest);
        if(metric == KERNEL_INFINITY) {
            PUSHADDR(**local4);
        } else if(plen == 128 && memcmp(dest+12, gate+12, 4) == 0) {
#if defined(RTF_CLONING)
            msg.m_rtm.rtm_flags |= RTF_CLONING;
#endif
            PUSHEUI(ifindex);
        } else {
            msg.m_rtm.rtm_flags |= RTF_GATEWAY;
            PUSHADDR(gate);
        }
        if((msg.m_rtm.rtm_addrs & RTA_NETMASK) != 0) {
            struct in6_addr tmp_sin6_addr;
            plen2mask(plen, &tmp_sin6_addr);
            PUSHADDR((char *)&tmp_sin6_addr);
        }

    } else {

        PUSHADDR6(dest);
        if(metric == KERNEL_INFINITY) {
            PUSHADDR6(**local6);
        } else {
            msg.m_rtm.rtm_flags |= RTF_GATEWAY;
            PUSHADDR6(gate);
        }
        if((msg.m_rtm.rtm_addrs & RTA_NETMASK) != 0) {
            struct in6_addr tmp_sin6_addr;
            plen2mask(plen, &tmp_sin6_addr);
            PUSHADDR6((char*)&tmp_sin6_addr);
        }

    }

#undef PUSHEUI
#undef PUSHADDR
#undef PUSHADDR6

    msg.m_rtm.rtm_msglen = data - (char *)&msg;
    rc = write(kernel_socket, (char*)&msg, msg.m_rtm.rtm_msglen);
    if(rc < msg.m_rtm.rtm_msglen)
        return -1;

    return 1;
}

static void
print_kernel_route(int add, struct kernel_route *route)
{
    char ifname[IFNAMSIZ];

    if(!if_indextoname(route->ifindex, ifname))
        memcpy(ifname,"unk",4);

    fprintf(stderr,
            "%s kernel route: dest: %s gw: %s metric: %d if: %s(%u) \n",
            add == RTM_ADD ? "Add" :
            add == RTM_DELETE ? "Delete" : "Change",
            format_prefix(route->prefix, route->plen),
            format_address(route->gw),
            route->metric,
            ifname, route->ifindex
            );
}

static int
parse_kernel_route(const struct rt_msghdr *rtm, struct kernel_route *route)
{
    struct sockaddr *sa;
    char *rta = (char*)rtm + sizeof(struct rt_msghdr);
    uint32_t excluded_flags = 0;

    if(ifindex_lo < 0) {
        ifindex_lo = if_nametoindex("lo0");
        if(ifindex_lo <= 0)
            return -1;
    }

    memset(route, 0, sizeof(*route));
    route->metric = 0;
    route->ifindex = rtm->rtm_index;

#if defined(RTF_IFSCOPE)
    /* Filter out kernel route on OS X */
    excluded_flags |= RTF_IFSCOPE;
#endif
#if defined(RTF_MULTICAST)
    /* Filter out multicast route on others BSD */
    excluded_flags |= RTF_MULTICAST;
#endif
    /* Filter out our own route */
    excluded_flags |= RTF_PROTO2;
    if((rtm->rtm_flags & excluded_flags) != 0)
        return -1;

    /* Prefix */
    if(!(rtm->rtm_addrs & RTA_DST))
        return -1;
    sa = (struct sockaddr *)rta;
    rta += ROUNDUP(sa->sa_len);
    if(sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        memcpy(route->prefix, &sin6->sin6_addr, 16);
        if(IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)
           || IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr))
            return -1;
    } else if(sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
#if defined(IN_LINKLOCAL)
        if(IN_LINKLOCAL(ntohl(sin->sin_addr.s_addr)))
            return -1;
#endif
        if(IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
            return -1;
        v4tov6(route->prefix, (unsigned char *)&sin->sin_addr);
    } else {
        return -1;
    }

    /* Gateway */
    if(!(rtm->rtm_addrs & RTA_GATEWAY))
        return -1;
    sa = (struct sockaddr *)rta;
    rta += ROUNDUP(sa->sa_len);
    if(sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        memcpy(route->gw, &sin6->sin6_addr, 16);
        if(IN6_IS_ADDR_LINKLOCAL (&sin6->sin6_addr)) {
            route->ifindex = IN6_LINKLOCAL_IFINDEX(sin6->sin6_addr);
            SET_IN6_LINKLOCAL_IFINDEX(sin6->sin6_addr, 0);
        }
    } else if(sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        v4tov6(route->gw, (unsigned char *)&sin->sin_addr);
    }
    if((int)route->ifindex == ifindex_lo)
        return -1;

    /* Netmask */
    if((rtm->rtm_addrs & RTA_NETMASK) != 0) {
        sa = (struct sockaddr *)rta;
        rta += ROUNDUP(sa->sa_len);
        if(!v4mapped(route->prefix)) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
            route->plen = mask2len((unsigned char*)&sin6->sin6_addr, 16);
        } else {
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            route->plen = mask2len((unsigned char*)&sin->sin_addr, 4);
        }
    }
    if(v4mapped(route->prefix)) route->plen += 96;
    if(rtm->rtm_flags & RTF_HOST) route->plen = 128;

    return 0;
}

static int
kernel_routes(struct kernel_filter *filter) {
    int mib[6];
    char *buf, *p;
    size_t len;
    struct rt_msghdr *rtm;
    int rc;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_UNSPEC;      /* Address family */
    mib[4] = NET_RT_DUMP; /* Dump the kernel routing table */
    mib[5] = 0;           /* No flags */

    rc = sysctl(mib, 6, NULL, &len, NULL, 0);
    if(rc < 0) {
        perror("kernel_routes(len)");
        return -1;
    }

    buf = malloc(len);
    if(!buf) {
        perror("kernel_routes(malloc)");
        return -1;
    }

    rc = sysctl(mib, 6, buf, &len, NULL, 0);
    if(rc < 0) {
        perror("kernel_routes(dump)");
        goto fail;
    }

    for(p = buf; p < buf + len; p += rtm->rtm_msglen) {
        struct kernel_route route;
        rtm = (struct rt_msghdr*)p;
        rc = parse_kernel_route(rtm, &route);
        if(rc < 0)
            continue;

        if(debug > 2)
            print_kernel_route(1, &route);

        filter->route(1, &route, filter->route_closure);
    }

    free(buf);
    return 0;

 fail:
    free(buf);
    return -1;

}

static int
socket_read(int sock, struct kernel_filter *filter)
{
    int rc;
    struct {
        struct rt_msghdr rtm;
        struct sockaddr_storage addr[RTAX_MAX];
    } buf;

    rc = read(sock, &buf, sizeof(buf));
    if(rc <= 0) {
        perror("kernel_callback(read)");
        return 0;
    }

    if(buf.rtm.rtm_msglen != rc) {
        kdebugf("kernel_callback(length)\n");
        return -1;
    }

    if(buf.rtm.rtm_type == RTM_ADD ||
       buf.rtm.rtm_type == RTM_DELETE ||
       buf.rtm.rtm_type == RTM_CHANGE) {
        struct kernel_route route;

        if(buf.rtm.rtm_errno)
            return 0;

        rc = parse_kernel_route(&buf.rtm, &route);
        if(rc < 0)
            return 0;
        filter->route(buf.rtm.rtm_type != RTM_DELETE, &route,
                      filter->route_closure);
        if(debug > 2)
            print_kernel_route(1, &route);
        return 1;

    }

    return 0;

}

static int
kernel_addresses(struct kernel_filter *filter)
{
    struct ifaddrs *ifa, *ifap;
    int rc;

    rc = getifaddrs(&ifa);
    if(rc < 0)
        return -1;

    for(ifap = ifa; ifap != NULL; ifap = ifap->ifa_next) {
        struct kernel_addr addr;
        addr.ifindex = if_nametoindex(ifap->ifa_name);
        if(!addr.ifindex)
            continue;

        if(ifap->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)ifap->ifa_addr;
            memcpy(&addr.addr, &sin6->sin6_addr, 16);
            if(IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
                /* This a perfect example of counter-productive optimisation :
                   KAME encodes interface index onto bytes 2 and 3, so we have
                   to reset those bytes to 0 before passing them to babeld. */
                memset(((char*)&addr.addr) + 2, 0, 2);
        } else if(ifap->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)ifap->ifa_addr;
#if defined(IN_LINKLOCAL)
            if(IN_LINKLOCAL(htonl(sin->sin_addr.s_addr)))
                continue;
#endif
            v4tov6((void*)&addr.addr, (void*) &sin->sin_addr);
        } else {
            continue;
        }
        filter->addr(1, &addr, filter->addr_closure);
    }

    freeifaddrs(ifa);
    return 0;
}

int
kernel_dump(int operation, struct kernel_filter *filter)
{
    switch(operation) {
    case CHANGE_ROUTE: return kernel_routes(filter);
    case CHANGE_ADDR: return kernel_addresses(filter);
    default: break;
    }

    return -1;
}

int
kernel_callback(struct kernel_filter *filter)
{
    if(kernel_socket < 0) kernel_setup_socket(1);

    kdebugf("Reading kernel table modification.");
    socket_read(kernel_socket, filter);

    return 0;

}

/* Local Variables:      */
/* c-basic-offset: 4     */
/* indent-tabs-mode: nil */
/* End:                  */
