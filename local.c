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

#include "babeld.h"
#include "interface.h"
#include "source.h"
#include "neighbour.h"
#include "xroute.h"
#include "route.h"
#include "util.h"
#include "local.h"

#ifdef NO_LOCAL_INTERFACE

int dummy;

#else

int
local_read(int s)
{
    int rc;
    char buf[500];

    /* Ignore anything that comes in, except for EOF */
    rc = read(s, buf, 500);

    if(rc <= 0)
        return rc;

    return 1;
}

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

void
local_notify_self()
{
    char buf[512];
    int rc;
    
    if(local_socket < 0)
        return;

    rc = snprintf(buf, 512, "add self alamakota id %s\n",
                  format_eui64(myid));

    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(local_socket, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(local_socket, 1);
    return;
}

static const char *
local_kind(int kind)
{
    switch(kind) {
    case LOCAL_FLUSH: return "flush";
    case LOCAL_CHANGE: return "change";
    case LOCAL_ADD: return "add";
    default: return "???";
    }
}

void
local_notify_neighbour(struct neighbour *neigh, int kind)
{
    char buf[512];
    int rc;
    
    if(local_socket < 0)
        return;

    rc = snprintf(buf, 512,
                  "%s neighbour %lx address %s "
                  "if %s reach %04x rxcost %d txcost %d cost %d\n",
                  local_kind(kind),
                  /* Neighbours never move around in memory , so we can use the
                     address as a unique identifier. */
                  (unsigned long int)neigh,
                  format_address(neigh->address),
                  neigh->ifp->name,
                  neigh->reach,
                  neighbour_rxcost(neigh),
                  neighbour_txcost(neigh),
                  neighbour_cost(neigh));

    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(local_socket, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(local_socket, 1);
    return;
}

void
local_notify_xroute(struct xroute *xroute, int kind)
{
    char buf[512];
    int rc;

    if(local_socket < 0)
        return;

    rc = snprintf(buf, 512, "%s xroute %s prefix %s metric %d\n",
                  local_kind(kind),
                  format_prefix(xroute->prefix, xroute->plen),
                  format_prefix(xroute->prefix, xroute->plen),
                  xroute->metric);
    
    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(local_socket, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(local_socket, 1);
    return;
}

void
local_notify_route(struct babel_route *route, int kind)
{
    char buf[512];
    int rc;

    if(local_socket < 0)
        return;

    rc = snprintf(buf, 512,
                  "%s route %s-%lx prefix %s installed %s "
                  "id %s metric %d refmetric %d via %s if %s\n",
                  local_kind(kind),
                  format_prefix(route->src->prefix, route->src->plen),
                  (unsigned long)route->neigh,
                  format_prefix(route->src->prefix, route->src->plen),
                  route->installed ? "yes" : "no",
                  format_eui64(route->src->id),
                  route_metric(route), route->refmetric,
                  format_address(route->neigh->address),
                  route->neigh->ifp->name);
    
    if(rc < 0 || rc >= 512)
        goto fail;

    rc = write_timeout(local_socket, buf, rc);
    if(rc < 0)
        goto fail;
    return;

 fail:
    shutdown(local_socket, 1);
    return;
}

static void
local_notify_xroute_callback(struct xroute *xroute, void *closure)
{
    local_notify_xroute(xroute, LOCAL_ADD);
}

static void
local_notify_route_callback(struct babel_route *route, void *closure)
{
    local_notify_route(route, LOCAL_ADD);
}

void
local_notify_all()
{
    int rc;
    struct neighbour *neigh;
    const char *header = "BABEL 0.0\n";

    if(local_socket < 0)
        return;

    rc = write_timeout(local_socket, header, strlen(header));
    if(rc < 0)
        goto fail;

    local_notify_self();
    FOR_ALL_NEIGHBOURS(neigh) {
        local_notify_neighbour(neigh, LOCAL_ADD);
    }
    for_all_xroutes(local_notify_xroute_callback, NULL);
    for_all_routes(local_notify_route_callback, NULL);
    return;

 fail:
    shutdown(local_socket, 1);
    return;
}

#endif
