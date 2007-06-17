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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "babel.h"

int
seqno_compare(unsigned char s1, unsigned char s2)
{
    if(s1 == s2)
        return 0;
    else if(((s2 - s1) & 0xFF) < 128)
        return -1;
    else
        return 1;
}

int
seqno_minus(unsigned char s1, unsigned char s2)
{
    if(s1 == s2)
        return 0;
    else if(((s2 - s1) & 0xFF) < 128)
        return -(int)((s2 - s1) & 0xFF);
    else
        return ((s1 - s2) & 0xFF);
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
do_debugf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if(debug >= 2)
        vfprintf(stderr, format, args);
    va_end(args);
    fflush(stderr);
}

const char *
format_address(const unsigned char *address)
{
    static char buf[4][INET6_ADDRSTRLEN];
    static int i = 0;
    i = (i + 1) % 4;
    return inet_ntop(AF_INET6, address, buf[i], INET6_ADDRSTRLEN);
}

int
parse_address(const char *address, unsigned char *addr_r)
{
    struct in6_addr ina6;
    int rc;
    rc = inet_pton(AF_INET6, address, &ina6);
    if(rc > 0) {
        memcpy(addr_r, &ina6, 16);
        return 0;
    }

    return -1;
}

int
parse_net(const char *net, unsigned char *prefix_r, unsigned short *plen_r)
{
    char buf[INET6_ADDRSTRLEN];
    char *slash, *end;
    unsigned char prefix[16];
    unsigned short plen;
    int rc;

    if(strcmp(net, "default") == 0) {
        memset(prefix, 0, 16);
        plen = 0;
    } else {
        slash = strchr(net, '/');
        if(slash == NULL) {
            rc = parse_address(net, prefix);
            if(rc < 0)
                return rc;
            plen = 128;
        } else {
            if(slash - net >= INET6_ADDRSTRLEN)
                return -1;
            memcpy(buf, net, slash - net);
            buf[slash - net] = '\0';
            rc = parse_address(buf, prefix);
            if(rc < 0)
                return rc;
            plen = strtol(slash + 1, &end, 0);
            if(*end != '\0')
            return -1;
        }
    }
    memcpy(prefix_r, prefix, 16);
    *plen_r = plen;
    return 0;
}

int
wait_for_fd(int direction, int fd, int msecs)
{
    fd_set fds;
    int rc;
    struct timeval tv;

    tv.tv_sec = msecs / 1000;
    tv.tv_usec = msecs * 1000;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    if(direction)
        rc = select(fd + 1, NULL, &fds, NULL, &tv);
    else
        rc = select(fd + 1, &fds, NULL, NULL, &tv);

    return rc;
}
