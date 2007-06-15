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

#define KERNEL_INFINITY 0xFFFF

struct kernel_route {
    unsigned char prefix[16];
    int plen;
    int metric;
    int ifindex;
    unsigned char gw[16];
};

#define ROUTE_FLUSH 0
#define ROUTE_ADD 1

int kernel_setup(int setup);
int kernel_setup_interface(int setup, const char *ifname, int ifindex);
int kernel_interface_mtu(const char *ifname, int ifindex);
int kernel_interface_wireless(const char *ifname, int ifindex);
int kernel_route(int operation, const unsigned char *dest, unsigned short plen,
                 const unsigned char *gate, int ifindex, unsigned int metric);
int kernel_routes(int maxplen, struct kernel_route *routes, int maxroutes);
int kernel_callback(void);
