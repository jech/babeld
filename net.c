/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

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

#define _GNU_SOURCE
#define __APPLE_USE_RFC_3542
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>

#if defined(__UCLIBC__)
#include <linux/in6.h>
#endif

#include "babeld.h"
#include "util.h"
#include "net.h"

int
babel_socket(int port)
{
    struct sockaddr_in6 sin6;
    int s, rc;
    int saved_errno;
    int one = 1, zero = 0;
    const int ds = 0xc0;        /* CS6 - Network Control */

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                    &zero, sizeof(zero));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

#ifdef IPV6_TCLASS
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &ds, sizeof(ds));
#else
    rc = -1;
    errno = ENOSYS;
#endif
    if(rc < 0)
        perror("Couldn't set traffic class");

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

int
babel_recv(int s, void *buf, int buflen, struct sockaddr *sin, int slen,
           unsigned char *src_return)
{
    struct iovec iovec;
    struct msghdr msg;
    unsigned char cmsgbuf[128];
    struct cmsghdr *cmsg;
    int rc, found;
    unsigned char src[16] = {0};

    memset(&msg, 0, sizeof(msg));
    iovec.iov_base = buf;
    iovec.iov_len = buflen;
    msg.msg_name = sin;
    msg.msg_namelen = slen;
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    rc = recvmsg(s, &msg, 0);
    if(rc < 0)
        return rc;

    found = 0;
    memset(src, 0, 16);
    cmsg = CMSG_FIRSTHDR(&msg);
    while(cmsg != NULL) {
        if(cmsg->cmsg_level == IPPROTO_IPV6 &&
           cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *info =(struct in6_pktinfo*)CMSG_DATA(cmsg);
            memcpy(src, info->ipi6_addr.s6_addr, 16);
            found = 1;
            break;
        }
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    if(!found) {
        errno = EDESTADDRREQ;
        return -1;
    }
    if(src_return != NULL)
        memcpy(src_return, src, 16);
    return rc;
}

int
babel_send(int s,
           const void *buf1, int buflen1, const void *buf2, int buflen2,
           const struct sockaddr *sin, int slen, int dontfrag)
{
    struct iovec iovec[2];
    struct msghdr msg;
    int one = 1;
    unsigned char cmsgbuf[CMSG_SPACE(sizeof(one))];
    int rc, count = 0;

    iovec[0].iov_base = (void*)buf1;
    iovec[0].iov_len = buflen1;
    iovec[1].iov_base = (void*)buf2;
    iovec[1].iov_len = buflen2;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)sin;
    msg.msg_namelen = slen;
    msg.msg_iov = iovec;
    msg.msg_iovlen = 2;
    if(dontfrag) {
        struct cmsghdr *cmsg;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_DONTFRAG;;
        cmsg->cmsg_len = CMSG_LEN(sizeof(one));
        memcpy(CMSG_DATA(cmsg), &one, sizeof(one));
        msg.msg_controllen = cmsg->cmsg_len;
    }

    /* The Linux kernel can apparently keep returning EAGAIN indefinitely. */

 again:
    rc = sendmsg(s, &msg, 0);
    if(rc < 0) {
        if(errno == EINTR) {
            count++;
            if(count < 100)
                goto again;
        } else if(errno == EAGAIN) {
            int rc2;
            rc2 = wait_for_fd(1, s, 5);
            if(rc2 > 0) {
                count++;
                if(count < 100)
                    goto again;
            }
            errno = EAGAIN;
        }
    }
    return rc;
}

int
tcp_server_socket(int port, int local)
{
    struct sockaddr_in6 sin6;
    int s, rc, saved_errno;
    int one = 1;

    s = socket(PF_INET6, SOCK_STREAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    if(local) {
        rc = inet_pton(AF_INET6, "::1", &sin6.sin6_addr);
        if(rc < 0)
            goto fail;
    }
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    rc = listen(s, 2);
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

int
unix_server_socket(const char *path)
{
    struct sockaddr_un sun;
    int s, rc, saved_errno;

    if(strlen(path) >= sizeof(sun.sun_path))
        return -1;

    s = socket(PF_UNIX, SOCK_STREAM, 0);
    if(s < 0)
        return -1;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, rc | O_NONBLOCK);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, path, sizeof(sun.sun_path));
    rc = bind(s, (struct sockaddr *)&sun, sizeof(sun));
    if(rc < 0)
        goto fail;

    rc = listen(s, 2);
    if(rc < 0)
        goto fail_unlink;

    return s;

 fail_unlink:
    saved_errno = errno;
    unlink(path);
    errno = saved_errno;
 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}
