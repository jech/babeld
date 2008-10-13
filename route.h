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

struct route {
    struct source *src;
    unsigned short metric;
    unsigned short refmetric;
    unsigned short seqno;
    struct neighbour *neigh;
    unsigned char nexthop[16];
    time_t time;
    unsigned short hold_time;    /* in seconds */
    short installed;
};

extern struct route *routes;
extern int numroutes, maxroutes;
extern unsigned kernel_metric;

struct route *find_route(const unsigned char *prefix, unsigned char plen,
                         struct neighbour *neigh, const unsigned char *nexthop);
struct route *find_installed_route(const unsigned char *prefix,
                                   unsigned char plen);
void flush_route(struct route *route);
void flush_neighbour_routes(struct neighbour *neigh);
void install_route(struct route *route);
void uninstall_route(struct route *route);
void switch_route(struct route *old, struct route *new);
void change_route_metric(struct route *route, unsigned newmetric);
int route_feasible(struct route *route);
int update_feasible(const unsigned char *id,
                    const unsigned char *p, unsigned char plen,
                    unsigned short seqno, unsigned short refmetric);
struct route *find_best_route(const unsigned char *prefix, unsigned char plen,
                              int feasible, struct neighbour *exclude);
struct route *install_best_route(const unsigned char prefix[16],
                                 unsigned char plen);
void update_neighbour_metric(struct neighbour *neigh);
void update_network_metric(struct network *net);
void update_route_metric(struct route *route);
struct route *update_route(const unsigned char *a,
                           const unsigned char *p, unsigned char plen,
                           unsigned short seqno, unsigned short refmetric,
                           unsigned short interval, struct neighbour *neigh,
                           const unsigned char *nexthop);
void retract_neighbour_routes(struct neighbour *neigh);
void send_unfeasible_request(struct neighbour *neigh, int force,
                             unsigned short seqno, unsigned short metric,
                             const unsigned char *a,
                             const unsigned char *prefix, unsigned char plen);
void consider_route(struct route *route);
void send_triggered_update(struct route *route,
                           struct source *oldsrc, unsigned oldmetric);
void route_changed(struct route *route,
                   struct source *oldsrc, unsigned short oldmetric);
void route_lost(struct source *src, unsigned oldmetric);
void expire_routes(void);
