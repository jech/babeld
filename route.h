/*
Copyright (c) 2007-2011 by Juliusz Chroboczek

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

struct babel_route {
    struct source *src;
    unsigned short refmetric;
    unsigned short cost;
    unsigned short add_metric;
    unsigned short seqno;
    struct neighbour *neigh;
    unsigned char nexthop[16];
    time_t time;
    unsigned short hold_time;    /* in seconds */
    unsigned short smoothed_metric; /* for route selection */
    time_t smoothed_metric_time;
    short installed;
    struct babel_route *next;
};

struct route_stream;

extern struct babel_route **routes;
extern int kernel_metric, allow_duplicates, reflect_kernel_metric;
extern int route_slots;
extern int smoothing_half_life;
extern int two_to_the_one_over_hl; /* 2^(1/hl) * 0x10000 */

static inline int
route_metric(const struct babel_route *route)
{
    int m = (int)route->refmetric + route->cost + route->add_metric;
    return MIN(m, INFINITY);
}

int route_compare(const unsigned char *prefix, unsigned char plen,
                  const unsigned char *src_prefix, unsigned char src_plen,
                  struct babel_route *route);
int
find_route_slot(const unsigned char *prefix, unsigned char plen,
                const unsigned char *src_prefix, unsigned char src_plen,
                int *new_return);
struct babel_route *find_route(const unsigned char *prefix, unsigned char plen,
                        const unsigned char *src_prefix, unsigned char src_plen,
                        struct neighbour *neigh);
struct babel_route *find_installed_route(const unsigned char *prefix,
                        unsigned char plen, const unsigned char *src_prefix,
                        unsigned char src_plen);
int installed_routes_estimate(void);
struct babel_route * insert_route(struct babel_route *route);
void flush_route(struct babel_route *route);
void flush_all_routes(void);
void flush_neighbour_routes(struct neighbour *neigh);
void flush_interface_routes(struct interface *ifp, int v4only);
struct route_stream *route_stream(int which);
struct babel_route *route_stream_next(struct route_stream *stream);
void route_stream_done(struct route_stream *stream);
int metric_to_kernel(int metric);
void install_route(struct babel_route *route);
void uninstall_route(struct babel_route *route);
void change_route_metric(struct babel_route *route,
                         unsigned refmetric,
                         unsigned cost,
                         unsigned add);
int route_feasible(struct babel_route *route);
int route_interferes(struct babel_route *route, struct interface *ifp);
int update_feasible(struct source *src,
                    unsigned short seqno, unsigned short refmetric);
void change_smoothing_half_life(int half_life);
int route_smoothed_metric(struct babel_route *route);
struct babel_route *find_best_route(const unsigned char *prefix,
                                    unsigned char plen,
                                    const unsigned char *src_prefix,
                                    unsigned char src_plen,
                                    int feasible, struct neighbour *exclude);
struct babel_route *install_best_route(const unsigned char prefix[16],
                                 unsigned char plen);
void update_neighbour_metric(struct neighbour *neigh, int changed);
void update_interface_metric(struct interface *ifp);
void update_route_metric(struct babel_route *route);
struct babel_route *update_route(const unsigned char *id,
                                 const unsigned char *prefix, unsigned char plen,
                                 const unsigned char *src_prefix,
                                 unsigned char src_plen,
                                 unsigned short seqno, unsigned short refmetric,
                                 unsigned short interval,
                                 struct neighbour *neigh,
                                 const unsigned char *nexthop);
void retract_neighbour_routes(struct neighbour *neigh);
void send_unfeasible_request(struct neighbour *neigh, int force,
                             unsigned short seqno, unsigned short metric,
                             struct source *src);
void consider_route(struct babel_route *route);
void send_triggered_update(struct babel_route *route,
                           struct source *oldsrc, unsigned oldmetric);
void route_changed(struct babel_route *route,
                   struct source *oldsrc, unsigned short oldmetric);
void route_lost(struct source *src, unsigned oldmetric);
void expire_routes(void);
