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

#include <sys/time.h>
#include <time.h>

#ifdef __APPLE__
#include "kernel_socket.c"
#else
#include "kernel_netlink.c"
#endif

/* Return an interface's link-local addresses */
int
kernel_ll_addresses(char *ifname, int ifindex,
                    unsigned char (*addresses)[16], int maxaddr)
{
    struct kernel_route routes[64];
    int rc, i, j;

    rc = kernel_addresses(ifname, ifindex, routes, 64);
    if(rc < 0)
        return -1;

    j = 0;
    for(i = 0; i < rc; i++) {
        unsigned char *prefix;
        if(j >= maxaddr)
            break;
        if(routes[i].ifindex != ifindex)
            continue;
        prefix = routes[i].prefix;
        if(prefix[0] == 0xFE && prefix[1] == 0x80 &&
           memcmp(prefix + 2, zeroes, 6) == 0) {
            memcpy(addresses[j], prefix, 16);
            j++;
        }
    }
    return j;
}

/* Determine an interface's hardware address, in modified EUI-64 format */
int
if_eui64(char *ifname, int ifindex, unsigned char *eui)
{
    int s, rc;
    struct ifreq req;
    unsigned char *mac;

    s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(s < 0) return -1;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
    rc = ioctl(s, SIOCGIFHWADDR, &req);
    if(rc < 0) {
        int saved_errno = errno;
        close(s);
        errno = saved_errno;
        return -1;
    }
    close(s);

    mac = (unsigned char *)req.ifr_hwaddr.sa_data;
    /* OpenVPN interfaces have a null MAC address.  Also check not group
       and global */
    if(memcmp(mac, zeroes, 6) == 0 || (mac[0] & 1) != 0 || (mac[0] & 2) != 0) {
        errno = ENOENT;
        return -1;
    }

    eui[0] = mac[0] ^ 2;
    eui[1] = mac[1];
    eui[2] = mac[2];
    eui[3] = 0xFF;
    eui[4] = 0xFE;
    eui[5] = mac[3];
    eui[6] = mac[4];
    eui[7] = mac[5];
    return 1;
}

/* Like gettimeofday, but should return monotonic time.  If POSIX clocks
   are not available, falls back to gettimeofday. */
int
gettime(struct timeval *tv)
{
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 && defined(CLOCK_MONOTONIC)
    static int have_posix_clocks = -1;

    if(have_posix_clocks < 0) {
        struct timespec ts;
        int rc;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0) {
            have_posix_clocks = 0;
        } else {
            have_posix_clocks = 1;
        }
    }

    if(have_posix_clocks) {
        struct timespec ts;
        int rc;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0)
            return rc;
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
        return rc;
    }
#endif

    return gettimeofday(tv, NULL);
}
