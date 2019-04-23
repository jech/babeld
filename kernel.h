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
    unsigned char src_prefix[16];
    int src_plen;
    int metric;
    unsigned int ifindex;
    int proto;
    unsigned char gw[16];
};

struct kernel_addr {
    struct in6_addr addr;
    unsigned int ifindex;
};

struct kernel_link {
    char *ifname;
};

struct kernel_rule {
    unsigned int priority;
    unsigned int table;
    unsigned char src[16];
    unsigned char src_plen;
};

struct kernel_filter {
    /* return -1 to interrupt search. */
    int (*addr)(struct kernel_addr *, void *);
    void *addr_closure;
    int (*route)(struct kernel_route *, void *);
    void *route_closure;
    int (*link)(struct kernel_link *, void *);
    void *link_closure;
    int (*rule)(struct kernel_rule *, void *);
    void *rule_closure;
};

#define ROUTE_FLUSH 0
#define ROUTE_ADD 1
#define ROUTE_MODIFY 2

#define CHANGE_LINK  (1 << 0)
#define CHANGE_ROUTE (1 << 1)
#define CHANGE_ADDR  (1 << 2)
#define CHANGE_RULE  (1 << 3)

#ifndef MAX_IMPORT_TABLES
#define MAX_IMPORT_TABLES 10
#endif

extern int export_table, import_tables[MAX_IMPORT_TABLES], import_table_count;

int add_import_table(int table);

int kernel_setup(int setup);
int kernel_setup_socket(int setup);
int kernel_setup_interface(int setup, const char *ifname, int ifindex);
int kernel_interface_operational(const char *ifname, int ifindex);
int kernel_interface_ipv4(const char *ifname, int ifindex,
                          unsigned char *addr_r);
int kernel_interface_mtu(const char *ifname, int ifindex);
int kernel_interface_wireless(const char *ifname, int ifindex);
int kernel_interface_channel(const char *ifname, int ifindex);
int kernel_disambiguate(int v4);
int kernel_route(int operation, int table,
                 const unsigned char *dest, unsigned short plen,
                 const unsigned char *src, unsigned short src_plen,
                 const unsigned char *pref_src,
                 const unsigned char *gate, int ifindex, unsigned int metric,
                 const unsigned char *newgate, int newifindex,
                 unsigned int newmetric, int newtable);
int kernel_dump(int operation, struct kernel_filter *filter);
int kernel_callback(struct kernel_filter *filter);
int if_eui64(char *ifname, int ifindex, unsigned char *eui);
int gettime(struct timeval *tv);
int read_random_bytes(void *buf, int len);
int kernel_older_than(const char *sysname, int version, int sub_version);
int kernel_has_ipv6_subtrees(void);
int add_rule(int prio, const unsigned char *src_prefix, int src_plen,
             int table);
int flush_rule(int prio, int family);
int change_rule(int new_prio, int old_prio, const unsigned char *src, int plen,
                int table);
