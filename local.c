/*
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "babeld.h"
#include "interface.h"
#include "source.h"
#include "neighbour.h"
#include "kernel.h"
#include "xroute.h"
#include "route.h"
#include "util.h"
#include "configuration.h"
#include "local.h"
#include "version.h"

int local_server_socket = -1;
struct local_socket local_sockets[MAX_LOCAL_SOCKETS];
int num_local_sockets = 0;
int local_server_port = -1;
char *local_server_path;
int local_server_write = 0;

static int
write_timeout(int fd, const void *buf, int len)
{
    int n = 0, rc = 0;
    const char *b = buf;

    while(n < len) {
        rc = write(fd, b + n, len - n);
        if(rc < 0) {
            if(errno == EAGAIN || errno == EINTR) {
                rc = wait_for_fd(1, fd, 100);
                if(rc > 0) {
                    rc = write(fd, b + n, len - n);
                }
            }
        }
        if(rc > 0)
            n += rc;
        else
            break;
    }

    if(n >= len)
        return 1;
    else {
        if(rc >= 0)
            errno = EAGAIN;
        return -1;
    }
}

const char *
local_kind(int kind)
{
    switch(kind) {
    case LOCAL_FLUSH: return "flush";
    case LOCAL_CHANGE: return "change";
    case LOCAL_ADD: return "add";
    default: return "???";
    }
}

static void
local_notify_interface_1(struct local_socket *s,
                         struct interface *ifp, int kind)
{
    char buf[512], v4[INET_ADDRSTRLEN];
    int rc;
    int up;

    up = if_up(ifp);
    if(up && ifp->ipv4)
        inet_ntop(AF_INET, ifp->ipv4, v4, INET_ADDRSTRLEN);
    else
        v4[0] = '\0';
    if(up)
        rc = snprintf(buf, 512,
                      "%s interface %s up true%s%s%s%s\n",
                      local_kind(kind), ifp->name,
                      ifp->numll > 0 ? " ipv6 " : "",
                      ifp->numll > 0 ? format_address(ifp->ll[0]) : "",
                      v4[0] ? " ipv4 " : "", v4);
    else
        rc = snprintf(buf, 512, "%s interface %s up false\n",
                      local_kind(kind), ifp->name);

    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(s->fd, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(s->fd, 1);
    return;
}

void
local_notify_interface(struct interface *ifp, int kind)
{
    int i;
    for(i = 0; i < num_local_sockets; i++) {
        if(local_sockets[i].monitor)
            local_notify_interface_1(&local_sockets[i], ifp, kind);
    }
}

static void
local_notify_neighbour_1(struct local_socket *s,
                         struct neighbour *neigh, int kind)
{
    char buf[512], rttbuf[64];
    int rc;

    rttbuf[0] = '\0';
    if(valid_rtt(neigh)) {
        rc = snprintf(rttbuf, 64, " rtt %s rttcost %u",
                      format_thousands(neigh->rtt), neighbour_rttcost(neigh));
        if(rc < 0 || rc >= 64)
            rttbuf[0] = '\0';
    }

    rc = snprintf(buf, 512,
                  "%s neighbour %lx address %s "
                  "if %s reach %04x ureach %04x "
                  "rxcost %u txcost %u%s cost %u\n",
                  local_kind(kind),
                  /* Neighbours never move around in memory , so we can use the
                     address as a unique identifier. */
                  (unsigned long int)neigh,
                  format_address(neigh->address),
                  neigh->ifp->name,
                  neigh->hello.reach,
                  neigh->uhello.reach,
                  neighbour_rxcost(neigh),
                  neighbour_txcost(neigh),
                  rttbuf,
                  neighbour_cost(neigh));

    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(s->fd, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(s->fd, 1);
    return;
}

void
local_notify_neighbour(struct neighbour *neigh, int kind)
{
    int i;
    for(i = 0; i < num_local_sockets; i++) {
        if(local_sockets[i].monitor)
            local_notify_neighbour_1(&local_sockets[i], neigh, kind);
    }
}

static void
local_notify_xroute_1(struct local_socket *s, struct xroute *xroute, int kind)
{
    char buf[512];
    int rc;
    const char *dst_prefix = format_prefix(xroute->prefix,
                                           xroute->plen);
    const char *src_prefix = format_prefix(xroute->src_prefix,
                                           xroute->src_plen);

    rc = snprintf(buf, 512, "%s xroute %s-%s prefix %s from %s metric %d\n",
                  local_kind(kind), dst_prefix, src_prefix,
                  dst_prefix, src_prefix, xroute->metric);

    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(s->fd, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(s->fd, 1);
    return;
}

void
local_notify_xroute(struct xroute *xroute, int kind)
{
    int i;
    for(i = 0; i < num_local_sockets; i++) {
        if(local_sockets[i].monitor)
            local_notify_xroute_1(&local_sockets[i], xroute, kind);
    }
}

static void
local_notify_route_1(struct local_socket *s, struct babel_route *route, int kind)
{
    char buf[512];
    int rc;
    const char *dst_prefix = format_prefix(route->src->prefix,
                                           route->src->plen);
    const char *src_prefix = format_prefix(route->src->src_prefix,
                                           route->src->src_plen);

    rc = snprintf(buf, 512,
                  "%s route %lx prefix %s from %s installed %s "
                  "id %s metric %d refmetric %d via %s if %s\n",
                  local_kind(kind),
                  (unsigned long)route,
                  dst_prefix, src_prefix,
                  route->installed ? "yes" : "no",
                  format_eui64(route->src->id),
                  route_metric(route), route->refmetric,
                  format_address(route->neigh->address),
                  route->neigh->ifp->name);

    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(s->fd, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(s->fd, 1);
    return;
}

void
local_notify_route(struct babel_route *route, int kind)
{
    int i;
    for(i = 0; i < num_local_sockets; i++) {
        if(local_sockets[i].monitor)
            local_notify_route_1(&local_sockets[i], route, kind);
    }
}

static void
local_notify_all_1(struct local_socket *s)
{
    struct interface *ifp;
    struct neighbour *neigh;
    struct xroute_stream *xroutes;
    struct route_stream *routes;

    FOR_ALL_INTERFACES(ifp) {
        local_notify_interface_1(s, ifp, LOCAL_ADD);
    }

    FOR_ALL_NEIGHBOURS(neigh) {
        local_notify_neighbour_1(s, neigh, LOCAL_ADD);
    }

    xroutes = xroute_stream();
    if(xroutes) {
        while(1) {
            struct xroute *xroute = xroute_stream_next(xroutes);
            if(xroute == NULL)
                break;
            local_notify_xroute_1(s, xroute, LOCAL_ADD);
        }
        xroute_stream_done(xroutes);
    }

    routes = route_stream(0);
    if(routes) {
        while(1) {
            struct babel_route *route = route_stream_next(routes);
            if(route == NULL)
                break;
            local_notify_route_1(s, route, LOCAL_ADD);
        }
        route_stream_done(routes);
    }
    return;
}

int
local_read(struct local_socket *s)
{
    int rc, n;
    char *eol;
    char reply[100] = "ok\n";
    const char *message = NULL;

    if(s->buf == NULL)
        s->buf = malloc(LOCAL_BUFSIZE);
    if(s->buf == NULL)
        return -1;

    if(s->n >= LOCAL_BUFSIZE) {
        errno = ENOSPC;
        goto fail;
    }

    rc = read(s->fd, s->buf + s->n, LOCAL_BUFSIZE - s->n);
    if(rc <= 0)
        return rc;
    s->n += rc;

    while(s->n > 0) {
        eol = memchr(s->buf, '\n', s->n);
        if(eol == NULL)
            break;
        n = eol + 1 - s->buf;

        rc = parse_config_from_string(s->buf, n, &message);
        switch(rc) {
        case CONFIG_ACTION_DONE:
            break;
        case CONFIG_ACTION_QUIT:
            shutdown(s->fd, 1);
            reply[0] = '\0';
            break;
        case CONFIG_ACTION_DUMP:
            local_notify_all_1(s);
            break;
        case CONFIG_ACTION_MONITOR:
            local_notify_all_1(s);
            s->monitor = 1;
            break;
        case CONFIG_ACTION_UNMONITOR:
            s->monitor = 0;
            break;
        case CONFIG_ACTION_NO:
            snprintf(reply, sizeof(reply), "no%s%s\n",
                     message ? " " : "", message ? message : "");
            break;
        default:
            snprintf(reply, sizeof(reply), "bad\n");
        }

        if(reply[0] != '\0') {
            rc = write_timeout(s->fd, reply, strlen(reply));
            if(rc < 0) {
                goto fail;
            }
        }
        if(s->n > n)
            memmove(s->buf, s->buf + n, s->n - n);
        s->n -= n;
    }

    if(s->n == 0) {
        free(s->buf);
        s->buf = NULL;
    }

    return 1;

 fail:
    shutdown(s->fd, 1);
    return -1;
}

int
local_header(struct local_socket *s)
{
    char buf[512], host[64];
    int rc;

    rc = gethostname(host, 64);
    if(rc < 0)
        strncpy(host, "alamakota", 64);

    rc = snprintf(buf, 512, "BABEL 1.0\nversion %s\nhost %s\nmy-id %s\nok\n",
                  BABELD_VERSION, host, format_eui64(myid));
    if(rc < 0 || rc >= 512)
        goto fail;
    rc = write_timeout(s->fd, buf, rc);
    if(rc < 0)
        goto fail;

    return 1;

 fail:
    shutdown(s->fd, 1);
    return -1;
}

struct local_socket *
local_socket_create(int fd)
{
    if(num_local_sockets >= MAX_LOCAL_SOCKETS)
        return NULL;

    memset(&local_sockets[num_local_sockets], 0, sizeof(struct local_socket));
    local_sockets[num_local_sockets].fd = fd;
    num_local_sockets++;

    return &local_sockets[num_local_sockets - 1];
}

void
local_socket_destroy(int i)
{
    if(i < 0 || i >= num_local_sockets) {
        fprintf(stderr, "Internal error: closing unknown local socket.\n");
        return;
    }

    free(local_sockets[i].buf);
    close(local_sockets[i].fd);
    local_sockets[i] = local_sockets[--num_local_sockets];
    VALGRIND_MAKE_MEM_UNDEFINED(local_sockets + num_local_sockets,
                                sizeof(struct local_socket));
}
