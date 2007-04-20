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

struct xroute;

struct route {
    struct destination *dest;
    unsigned short metric;
    unsigned short refmetric;
    unsigned char seqno;
    struct neighbour *nexthop;
    int time;
    int origtime;
    int installed;
};

extern struct route routes[MAXROUTES];
extern int numroutes;
extern int kernel_metric;

struct route *find_route(const unsigned char *dest, struct neighbour *nexthop);
struct route *find_installed_route(struct destination *dest);
void flush_route(struct route *route);
void flush_neighbour_routes(struct neighbour *neigh);
unsigned int metric_to_kernel(int metric);
void install_route(struct route *route);
void uninstall_route(struct route *route);
int route_feasible(struct route *route);
int update_feasible(unsigned char seqno, unsigned short refmetric,
                    struct destination *dest);
struct route *find_best_route(struct destination *dest);
void update_neighbour_metric(struct neighbour *neigh);
void update_route_metric(struct route *route);
struct route *update_route(const unsigned char *d, int seqno, int refmetric,
                           struct neighbour *nexthop,
                           struct xroute *pxroutes, int numpxroutes);
void consider_route(struct route *route);
void tweak_route(struct route *route,
                 int newseqno, int newrefmetric, int newmetric);
void send_triggered_update(struct route *route, int oldmetric);
