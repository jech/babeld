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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "babel.h"
#include "kernel.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "xroute.h"
#include "util.h"

struct xroute xroutes[MAXXROUTES];
int numxroutes = 0;

struct xroute *
find_exported_xroute(const unsigned char *prefix, unsigned char plen)
{
    int i;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].exported) {
            if(xroutes[i].plen == plen &&
               memcmp(xroutes[i].prefix, prefix, 16) == 0)
                return &xroutes[i];
        }
    }
    return NULL;
}

int
check_xroutes()
{
    int i, j, n, change;
    struct kernel_route routes[120];

    debugf("\nChecking kernel routes.\n");

    n = -1;
    for(i = 0; i < numxroutes; i++)
        if(xroutes[i].exported < 2)
            n = MAX(n, xroutes[i].plen);

    if(n < 0)
        return 0;

    n = kernel_routes(n, routes, 120);
    if(n < 0)
        return -1;

    change = 0;
    for(i = 0; i < numxroutes; i++) {
        int export;
        if(xroutes[i].exported == 2)
            continue;
        export = 0;
        for(j = 0; j < n; j++) {
            if(xroutes[i].plen == routes[j].plen &&
               memcmp(xroutes[i].prefix, routes[j].prefix, 16) == 0) {
                export = 1;
                break;
            }
        }
        if(xroutes[i].exported != export) {
            xroutes[i].exported = export;
            if(export) {
                struct route *route;
                route = find_installed_route(xroutes[i].prefix,
                                             xroutes[i].plen);
                if(route)
                    uninstall_route(route);
            } else {
                struct route *route;
                route = find_best_route(xroutes[i].prefix, xroutes[i].plen);
                if(route)
                    install_route(route);
            }
            send_update(NULL, 1, xroutes[i].prefix, xroutes[i].plen);
            change = 1;
        }
    }
    return change;
}
