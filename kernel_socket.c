/*
Copyright (c) 2007 by Grégoire Henry
Copyright (c) 2008 by Juliusz Chroboczek

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
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include "babel.h"
#include "neighbour.h"
#include "kernel.h"
#include "util.h"

int export_table = -1, import_table = -1;

int
if_eui64(char *ifname, int ifindex, unsigned char *eui)
{
    errno = ENOSYS;
    return -1;
}


/* KAME said : "Following two macros are highly depending on KAME Release" */
#define	IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr[2] << 8 | (a).s6_addr[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)         \
    do {                                        \
        (a).s6_addr[2] = ((i) >> 8) & 0xff;     \
        (a).s6_addr[3] = (i) & 0xff;            \
    } while (0)

#define ROUNDUP(a)                                                      \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))


static int old_forwarding = -1;
static int old_accept_redirects = -1;

static int ifindex_lo = -1;
static int seq;

static int get_sysctl_int(char *name)
{
  int old;
  size_t len = sizeof (old);

  if (sysctlbyname(name, &old, &len, NULL, 0) < 0)
    return -1;

  return old;
}

static int set_sysctl_int(char *name, int new)
{
  int old;
  size_t len = sizeof (old);

  if (sysctlbyname(name, &old, &len, &new, sizeof (new)) < 0)
    return -1;

  return old;
}

int
mask2len(const struct in6_addr *addr)
{
    int i = 0, j;
    const u_char *p = (const u_char *)addr;

    for(j = 0; j < 16; j++, p++) {
        if(*p != 0xff)
            break;
        i += 8;
    }
    if(j < 16) {
        switch(*p) {
#define	MASKLEN(m, l)	case m: do { i += l; break; } while (0)
            MASKLEN(0xfe, 7); break;
            MASKLEN(0xfc, 6); break;
            MASKLEN(0xf8, 5); break;
            MASKLEN(0xf0, 4); break;
            MASKLEN(0xe0, 3); break;
            MASKLEN(0xc0, 2); break;
            MASKLEN(0x80, 1); break;
#undef	MASKLEN
        }
    }
    return i;
}

void
plen2mask(int n, struct in6_addr *dest)
{
    unsigned char *p;
    int i;

    static const int pl2m[9] = {
        0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
    };

    memset(dest, 0, sizeof(struct in6_addr));
    p = (u_char *)dest;
    for (i = 0; i < 16; i++, p++, n -= 8) {
        if (n >= 8) {
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
    int rc;
    if(setup) {
        seq = time(NULL);
        old_forwarding = get_sysctl_int("net.inet6.ip6.forwarding");
        if(old_forwarding < 0) {
            perror("Couldn't read forwarding knob.");
            return -1;
        }
        rc = set_sysctl_int("net.inet6.ip6.forwarding",1);
        if(rc < 0) {
            perror("Couldn't write forwarding knob.");
            return -1;
        }
        old_accept_redirects = get_sysctl_int("net.inet6.icmp6.rediraccept");
        if(old_accept_redirects < 0) {
            perror("Couldn't read accept_redirects knob.");
            return -1;
        }
        rc = set_sysctl_int("net.inet6.icmp6.rediraccept",0);
        if(rc < 0) {
            perror("Couldn't write accept_redirects knob.");
            return -1;
        }
        return 1;
    } else {
        if(old_forwarding >= 0) {
            rc = set_sysctl_int("net.inet6.ip6.forwarding",old_forwarding);
            if(rc < 0) {
                perror("Couldn't write accept_redirects knob.\n");
                return -1;
            }
        }
        if(old_accept_redirects >= 0) {
            rc = set_sysctl_int("net.inet6.icmp6.rediraccept",
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
kernel_setup_socket(int setup)
{
    int rc;
    int zero = 0;
    if(setup) {
        if(kernel_socket < 0) {
            kernel_socket = socket(PF_ROUTE, SOCK_RAW, AF_INET6);
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
    return -1;
}

int
kernel_route(int operation, const unsigned char *dest, unsigned short plen,
             const unsigned char *gate, int ifindex, unsigned int metric,
             const unsigned char *newgate, int newifindex,
             unsigned int newmetric)
{

    unsigned char msg[512];
    struct rt_msghdr *rtm;
    struct sockaddr_in6 *sin6;
    int rc, len;

    char local[1][1][16] = IN6ADDR_LOOPBACK_INIT;

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

    if(v4mapped(gate)) {
        /* Not implemented yet. */
        errno = ENOSYS;
        return -1;
    }

    if(operation == ROUTE_MODIFY && newmetric == metric && 
       memcmp(newgate, gate, 16) == 0 && newifindex == ifindex)
      return 0;

    if(operation == ROUTE_MODIFY) {
        metric = newmetric;
        gate = newgate;
        ifindex = newifindex;
    }

    kdebugf("kernel_route: %s %s/%d metric %d dev %d nexthop %s\n",
           operation == ROUTE_ADD ? "add" :
           operation == ROUTE_FLUSH ? "flush" : "change",
           format_address(dest), plen, metric, ifindex,
           format_address(gate));

    if(kernel_socket < 0) kernel_setup_socket(1);
    
    memset(&msg, 0, sizeof(msg));
    rtm = (struct rt_msghdr *)msg;
    rtm->rtm_version = RTM_VERSION;
    switch(operation) {
    case ROUTE_FLUSH:
      rtm->rtm_type = RTM_DELETE; break;
    case ROUTE_ADD:
      rtm->rtm_type = RTM_ADD; break;
    case ROUTE_MODIFY: 
      rtm->rtm_type = RTM_CHANGE; break;
    default: 
      return -1;
    };
    rtm->rtm_index = ifindex;
    rtm->rtm_flags = RTF_UP | RTF_PROTO2;
    if(plen == 128) rtm->rtm_flags |= RTF_HOST;
/*     if(memcmp(nexthop->id, dest, 16) == 0) { */
/*         rtm -> rtm_flags |= RTF_LLINFO; */
/*         rtm -> rtm_flags |= RTF_CLONING; */
/*     } else { */
        rtm->rtm_flags |= RTF_GATEWAY;
/*     } */
    if(metric == KERNEL_INFINITY) {
        rtm->rtm_flags |= RTF_BLACKHOLE;
        if(ifindex_lo < 0) {
            ifindex_lo = if_nametoindex("lo0");
            if(ifindex_lo <= 0)
                return -1;
        }
        rtm->rtm_index = ifindex_lo;      
    }
    rtm->rtm_seq = ++seq;
    rtm->rtm_addrs = RTA_DST | RTA_GATEWAY;
    if(!(operation == ROUTE_MODIFY && plen == 128)) {
        rtm->rtm_addrs |= RTA_NETMASK;
    }
    rtm->rtm_rmx.rmx_hopcount = metric;
    rtm->rtm_inits = RTV_HOPCOUNT;

    sin6 = (struct sockaddr_in6 *)&msg[sizeof(struct rt_msghdr)];
    /* Destination */
    sin6->sin6_len = sizeof(struct sockaddr_in6);
    sin6->sin6_family = AF_INET6;
    sin6->sin6_addr = *((struct in6_addr *)dest);
    sin6 = (struct sockaddr_in6 *)((char *)sin6 + ROUNDUP(sin6->sin6_len));
    /* Gateway */
    sin6->sin6_len = sizeof(struct sockaddr_in6);
    sin6->sin6_family = AF_INET6;
    if (metric == KERNEL_INFINITY) 
        sin6->sin6_addr = *((struct in6_addr *)*local);
    else
        sin6->sin6_addr = *((struct in6_addr *)gate);
    if(IN6_IS_ADDR_LINKLOCAL (&sin6->sin6_addr))
        SET_IN6_LINKLOCAL_IFINDEX (sin6->sin6_addr, ifindex);
    sin6 = (struct sockaddr_in6 *)((char *)sin6 + ROUNDUP(sin6->sin6_len));
    /* Netmask */
    if((rtm->rtm_addrs | RTA_NETMASK) != 0) {
        sin6->sin6_len = sizeof(struct sockaddr_in6);
        sin6->sin6_family = AF_INET6;
        plen2mask(plen, &sin6->sin6_addr);
        sin6 = (struct sockaddr_in6 *)((char *)sin6 + ROUNDUP(sin6->sin6_len));
    }
    len = (char *)sin6 - (char *)msg;
    rtm->rtm_msglen = len;

    rc = write(kernel_socket, msg, rtm->rtm_msglen);
    if (rc < rtm->rtm_msglen)
        return -1;

    return 1;
}

static void
print_kernel_route(int add, struct kernel_route *route)
{
    char ifname[IFNAMSIZ];
    char addr_prefix[INET6_ADDRSTRLEN];
    char addr_gw[INET6_ADDRSTRLEN];
    
    if(!inet_ntop(AF_INET6, route->prefix,
                  addr_prefix, sizeof(addr_prefix)) ||
       !inet_ntop(AF_INET6,route->gw, addr_gw, sizeof(addr_gw)) ||
       !if_indextoname(route->ifindex, ifname)) {
        fprintf(stderr,"Couldn't format kernel route for printing.");
        // return;
    }

    fprintf(stderr,
            "%s kernel route: dest: %s/%d gw: %s metric: %d if: %s(%d) \n",
            add == RTM_ADD ? "Add" :
            add == RTM_DELETE ? "Delete" : "Change",
            addr_prefix, route->plen, addr_gw, route->metric, ifname, 
            route->ifindex
            );
}

static int
parse_kernel_route(const struct rt_msghdr *rtm, struct kernel_route *route)
{

    void *rta = (void*)rtm + sizeof(struct rt_msghdr);
    struct sockaddr_in6 *sin6;
    char addr[INET6_ADDRSTRLEN];

    memset(route, 0, sizeof(*route));
    route->metric = rtm->rtm_rmx.rmx_hopcount;
    route->ifindex = rtm->rtm_index;

    if(!rtm->rtm_addrs && RTA_DST)
        return -1;
    sin6 = (struct sockaddr_in6 *)rta;
    if(IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) 
       || IN6_IS_ADDR_MC_LINKLOCAL(&sin6->sin6_addr))
        return -1;
    if((rtm->rtm_flags & RTF_PROTO2) != 0)
        return -1;
    memcpy(&route->prefix, &sin6->sin6_addr, 16);
    rta += ROUNDUP(sizeof(struct sockaddr_in6));
   
    if(!rtm->rtm_addrs && RTA_GATEWAY)
        return -1;

    sin6 = (struct sockaddr_in6 *)rta;
    if(IN6_IS_ADDR_LINKLOCAL (&sin6->sin6_addr)) {
        route->ifindex = IN6_LINKLOCAL_IFINDEX(sin6->sin6_addr);
        SET_IN6_LINKLOCAL_IFINDEX(sin6->sin6_addr, 0);
    }
    memcpy(&route->gw, &sin6->sin6_addr, 16);
    rta += ROUNDUP(sizeof(struct sockaddr_in6));

    if(!rtm->rtm_addrs && RTA_NETMASK) {
        route->plen = 0;
    } else {
        sin6 = (struct sockaddr_in6 *)rta;        
        route->plen = mask2len(&sin6->sin6_addr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof(addr));
        rta += ROUNDUP(sizeof(struct sockaddr_in6));
    }
    if (rtm->rtm_flags & RTF_HOST)
        route->plen = 128;

    if(ifindex_lo < 0) {
        ifindex_lo = if_nametoindex("lo0");
        if(ifindex_lo <= 0)
            return -1;
    }

    if(route->ifindex == ifindex_lo)
        return -1;

    return 0;

}

int
kernel_routes(struct kernel_route *routes, int maxroutes)
{
    int mib[6];
    char *buf, *p;
    size_t len;
    struct rt_msghdr *rtm;
    int rc, i;
    
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET6;	  /* Address family */
    mib[4] = NET_RT_DUMP; /* Dump the kernel routing table */
    mib[5] = 0;		  /* No flags */

    rc = sysctl(mib, 6, NULL, &len, NULL, 0);
    if (rc < 0) {
        perror("kernel_routes(len)");
        return -1;
    }

    buf = malloc(len);
    if(!buf) {
        perror("kernel_routes(malloc)");
        return -1;
    }

    rc = sysctl(mib, 6, buf, &len, NULL, 0);
    if (rc < 0) {
        perror("kernel_routes(dump)");
        goto fail;
    }

    i = 0;
    p = buf;
    while(p < buf + len && i < maxroutes) {
        rtm = (struct rt_msghdr*)p;
        rc = parse_kernel_route(rtm, &routes[i]);
        if(rc)
            goto cont;

        if(debug > 2)
            print_kernel_route(1,&routes[i]);

        i++;

    cont:
        p += rtm->rtm_msglen;
    }

    free(buf);
    return i;

 fail:
    free(buf);
    return -1;

}

static int
socket_read(int sock) 
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
        if(debug > 2)
            print_kernel_route(1,&route);
        return 1;

    }

    return 0;

}

int
kernel_addresses(char *ifname, int ifindex,
                 struct kernel_route *routes, int maxroutes)
{
    errno = ENOSYS;
    return -1;
}

int
kernel_callback(int (*fn)(int, void*), void *closure)
{
    int rc;

    if(kernel_socket < 0) kernel_setup_socket(1);

    kdebugf("Reading kernel table modification.");
    rc = socket_read(kernel_socket);
    if(rc)
        return fn(~0, closure);

    return 0;

}

/* Local Variables:      */
/* c-basic-offset: 4     */
/* indent-tabs-mode: nil */
/* End:                  */
