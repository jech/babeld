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

#include <netinet/in.h>
#include "babeld.h"

#define KERNEL_INFINITY 0xFFFF

struct kernel_route {
    unsigned char prefix[16];
    int plen;
    int metric;
    unsigned int ifindex;
    int proto;
    unsigned char gw[16];
};

#define ROUTE_FLUSH 0
#define ROUTE_ADD 1
#define ROUTE_MODIFY 2

#define CHANGE_LINK  (1 << 0)
#define CHANGE_ROUTE (1 << 1)
#define CHANGE_ADDR  (1 << 2)

extern int export_table, import_table;

int kernel_setup(int setup);
int kernel_setup_socket(int setup);
int kernel_setup_interface(int setup, const char *ifname, int ifindex);
int kernel_interface_operational(const char *ifname, int ifindex);
int kernel_interface_ipv4(const char *ifname, int ifindex,
                          unsigned char *addr_r);
int kernel_interface_mtu(const char *ifname, int ifindex);
int kernel_interface_wireless(const char *ifname, int ifindex);
int kernel_interface_channel(const char *ifname, int ifindex);
int kernel_route(int operation, const unsigned char *dest, unsigned short plen,
                 const unsigned char *gate, int ifindex, unsigned int metric,
                 const unsigned char *newgate, int newifindex,
                 unsigned int newmetric);
int kernel_routes(struct kernel_route *routes, int maxroutes);
int kernel_callback(int (*fn)(int, void*), void *closure);
int kernel_addresses(char *ifname, int ifindex, int ll,
                     struct kernel_route *routes, int maxroutes);
int if_eui64(char *ifname, int ifindex, unsigned char *eui);
int gettime(struct timeval *tv);
int read_random_bytes(void *buf, size_t len);
