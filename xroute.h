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

struct route;

struct xroute {
    unsigned char prefix[16];
    unsigned short plen;
    struct destination *gateway;
    struct neighbour *nexthop;
    int cost;
    int metric;
    int time;
    int installed;
};

extern struct xroute xroutes[MAXXROUTES];
extern int numxroutes;

extern struct xroute myxroutes[MAXMYXROUTES];
extern int nummyxroutes;

extern int xroute_gc_delay;
extern int xroute_hold_delay;

void install_xroute(struct xroute *xroute);
void uninstall_xroute(struct xroute *xroute);
void consider_xroute(struct xroute *xroute);
void flush_xroute(struct xroute *xroute);
void flush_neighbour_xroutes(struct neighbour *neigh);
void retract_xroutes(struct destination *gateway, struct neighbour *nexthop,
                     const struct xroute *except, int numexcept);
struct xroute * update_xroute(const unsigned char *prefix, unsigned short plen,
                              struct destination *gateway,
                              struct neighbour *nexthop, int cost);
void update_xroute_metric(struct xroute *xroute, int cost);
int check_myxroutes(void);
