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
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "babel.h"
#include "util.h"

int
seqno_compare(unsigned short s1, unsigned short s2)
{
    if(s1 == s2)
        return 0;
    else if(((s2 - s1) & 0xFFFF) < 0x8000)
        return -1;
    else
        return 1;
}

int
seqno_minus(unsigned short s1, unsigned short s2)
{
    if(s1 == s2)
        return 0;
    else if(((s2 - s1) & 0xFFFF) < 0x8000)
        return -(int)((s2 - s1) & 0xFFFF);
    else
        return ((s1 - s2) & 0xFFFF);
}

unsigned short
seqno_plus(unsigned short s, int plus)
{
    return ((s + plus) & 0xFFFF);
}

void
timeval_minus(struct timeval *d,
              const struct timeval *s1, const struct timeval *s2)
{
    if(s1->tv_usec > s2->tv_usec) {
        d->tv_usec = s1->tv_usec - s2->tv_usec;
        d->tv_sec = s1->tv_sec - s2->tv_sec;
    } else {
        d->tv_usec = s1->tv_usec + 1000000 - s2->tv_usec;
        d->tv_sec = s1->tv_sec - s2->tv_sec - 1;
    }
}

int
timeval_minus_msec(const struct timeval *s1, const struct timeval *s2)
{
    return (s1->tv_sec - s2->tv_sec) * 1000 +
        (s1->tv_usec - s2->tv_usec) / 1000;
}

void
timeval_plus_msec(struct timeval *d, const struct timeval *s, int msecs)
{
    int usecs;
    d->tv_sec = s->tv_sec + msecs / 1000;
    usecs = s->tv_usec + (msecs % 1000) * 1000;
    if(usecs < 1000000) {
        d->tv_usec = usecs;
    } else {
        d->tv_usec = usecs - 1000000;
        d->tv_sec++;
    }
}

int
timeval_compare(const struct timeval *s1, const struct timeval *s2)
{
    if(s1->tv_sec < s2->tv_sec)
        return -1;
    else if(s1->tv_sec > s2->tv_sec)
        return 1;
    else if(s1->tv_usec < s2->tv_usec)
        return -1;
    else if(s1->tv_usec > s2->tv_usec)
        return 1;
    else
        return 0;
}

/* {0, 0} represents infinity */
void
timeval_min(struct timeval *d, const struct timeval *s)
{
    if(s->tv_sec == 0)
        return;

    if(d->tv_sec == 0 || timeval_compare(d, s) > 0) {
        *d = *s;
    }
}

void
timeval_min_sec(struct timeval *d, int secs)
{
    if(d->tv_sec == 0 || d->tv_sec > secs) {
        d->tv_sec = secs;
        d->tv_usec = random() % 1000000;
    }
}

void
do_debugf(int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if(debug >= level)
        vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
}

int
in_prefix(const unsigned char *address,
          const unsigned char *prefix, unsigned char plen)
{
    unsigned char m;

    if(plen > 128)
        plen = 128;

    if(memcmp(address, prefix, plen / 8) != 0)
        return 0;

    m = 0xFF << (8 - (plen % 8));

    return ((address[plen / 8] & m) == (prefix[plen / 8] & m));
}

const unsigned char *
mask_prefix(unsigned char *ret,
            const unsigned char *prefix, unsigned char plen)
{
    if(plen > 128)
        plen = 128;

    memset(ret, 0, 16);
    memcpy(ret, prefix, plen / 8);
    if(plen % 8 != 0)
        ret[plen / 8] = (prefix[plen / 8] & (0xFF << (8 - (plen % 8))));
    return (const unsigned char *)ret;
}

static unsigned char v4prefix[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

const char *
format_address(const unsigned char *address)
{
    static char buf[4][INET6_ADDRSTRLEN];
    static int i = 0;
    i = (i + 1) % 4;
    if(v4mapped(address))
       inet_ntop(AF_INET, address + 12, buf[i], INET6_ADDRSTRLEN);
    else
       inet_ntop(AF_INET6, address, buf[i], INET6_ADDRSTRLEN);
    return buf[i];
}

const char *
format_prefix(const unsigned char *prefix, unsigned char plen)
{
    static char buf[4][INET6_ADDRSTRLEN + 4];
    static int i = 0;
    int n;
    i = (i + 1) % 4;
    if(plen >= 96 && v4mapped(prefix)) {
        inet_ntop(AF_INET, prefix + 12, buf[i], INET6_ADDRSTRLEN);
        n = strlen(buf[i]);
        snprintf(buf[i] + n, INET6_ADDRSTRLEN + 4 - n, "/%d", plen - 96);
    } else {
        inet_ntop(AF_INET6, prefix, buf[i], INET6_ADDRSTRLEN);
        n = strlen(buf[i]);
        snprintf(buf[i] + n, INET6_ADDRSTRLEN + 4 - n, "/%d", plen);
    }
    return buf[i];
}

int
parse_address(const char *address, unsigned char *addr_r, int *af_r)
{
    struct in_addr ina;
    struct in6_addr ina6;
    int rc;

    rc = inet_pton(AF_INET, address, &ina);
    if(rc > 0) {
        memcpy(addr_r, v4prefix, 12);
        memcpy(addr_r + 12, &ina, 4);
        if(af_r) *af_r = AF_INET;
        return 0;
    }

    rc = inet_pton(AF_INET6, address, &ina6);
    if(rc > 0) {
        memcpy(addr_r, &ina6, 16);
        if(af_r) *af_r = AF_INET6;
        return 0;
    }

    return -1;
}

int
parse_net(const char *net, unsigned char *prefix_r, unsigned char *plen_r,
          int *af_r)
{
    char buf[INET6_ADDRSTRLEN];
    char *slash, *end;
    unsigned char prefix[16];
    long plen;
    int af;
    struct in_addr ina;
    struct in6_addr ina6;
    int rc;

    if(strcmp(net, "default") == 0) {
        memset(prefix, 0, 16);
        plen = 0;
    } else {
        slash = strchr(net, '/');
        if(slash == NULL) {
            rc = parse_address(net, prefix, &af);
            if(rc < 0)
                return rc;
            plen = 128;
        } else {
            if(slash - net >= INET6_ADDRSTRLEN)
                return -1;
            memcpy(buf, net, slash - net);
            buf[slash - net] = '\0';
            rc = inet_pton(AF_INET, buf, &ina);
            if(rc > 0) {
                memcpy(prefix, v4prefix, 12);
                memcpy(prefix + 12, &ina, 4);
                plen = strtol(slash + 1, &end, 0);
                if(*end != '\0' || plen < 0 || plen > 32)
                    return -1;
                plen += 96;
                af = AF_INET;
            } else {
                rc = inet_pton(AF_INET6, buf, &ina6);
                if(rc > 0) {
                    memcpy(prefix, &ina6, 16);
                    plen = strtol(slash + 1, &end, 0);
                    if(*end != '\0' || plen < 0 || plen > 128)
                        return -1;
                    af = AF_INET6;
                } else {
                    return -1;
                }
            }
        }
    }
    mask_prefix(prefix_r, prefix, plen);
    *plen_r = plen;
    if(af_r) *af_r = af;
    return 0;
}

int
wait_for_fd(int direction, int fd, int msecs)
{
    fd_set fds;
    int rc;
    struct timeval tv;

    tv.tv_sec = msecs / 1000;
    tv.tv_usec = (msecs % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    if(direction)
        rc = select(fd + 1, NULL, &fds, NULL, &tv);
    else
        rc = select(fd + 1, &fds, NULL, NULL, &tv);

    return rc;
}

int
martian_prefix(const unsigned char *prefix, int plen)
{
    return
        (plen >= 8 && prefix[0] == 0xFF) ||
        (plen >= 10 && prefix[0] == 0xFE && (prefix[1] & 0xC0) == 0x80) ||
        (plen >= 128 && memcmp(prefix, zeroes, 15) == 0 &&
         (prefix[15] == 0 || prefix[15] == 1)) ||
        (plen >= 96 && v4mapped(prefix) &&
         ((plen >= 104 && (prefix[12] == 127 || prefix[12] == 0)) ||
          (plen >= 100 &&
           ((prefix[12] & 0xF0) == 0xF0 || (prefix[12] & 0xF0) == 0xE0))));
}

int
v4mapped(const unsigned char *address)
{
    return in_prefix(address, v4prefix, 96);
}

void
v4tov6(unsigned char *dst, const unsigned char *src)
{
    memcpy(dst, v4prefix, 12);
    memcpy(dst + 12, src, 4);
}

char *
parse_ifflags(unsigned int flags)
{
    static char buf[512];
    buf[0] = '\0';
    if (flags & IFF_UP)
        strcat(buf, "UP ");
    if (flags & IFF_BROADCAST)
        strcat(buf, "BROADCAST ");
    if (flags & IFF_RUNNING)
        strcat(buf, "RUNNING ");
    if (flags & IFF_MULTICAST)
        strcat(buf, "MULTICAST ");
    return buf;
}

int
daemonise()
{
    int rc;

    fflush(stdout);
    fflush(stderr);

    rc = fork();
    if(rc < 0)
        return -1;

    if(rc > 0)
        exit(0);

    rc = setsid();
    if(rc < 0)
        return -1;

    return 1;
}
