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

struct buffered_update {
    unsigned char id[8];
    unsigned char prefix[16];
    unsigned char plen;
    unsigned char pad[3];
};

struct network_conf {
    char *ifname;
    struct network_conf *next;
};

#define NET_UP (1 << 0)
#define NET_WIRED (1<<1)
#define NET_SPLIT_HORIZON (1 << 2)

struct network {
    struct network *next;
    struct network_conf *conf;
    unsigned int ifindex;
    unsigned short flags;
    unsigned short cost;
    struct timeval hello_timeout;
    struct timeval self_update_timeout;
    struct timeval update_timeout;
    struct timeval flush_timeout;
    struct timeval update_flush_timeout;
    char ifname[IF_NAMESIZE];
    unsigned char *ipv4;
    int numll;
    unsigned char (*ll)[16];
    int buffered;
    int bufsize;
    char have_buffered_hello;
    char have_buffered_id;
    char have_buffered_nh;
    char have_buffered_prefix;
    unsigned char buffered_id[16];
    unsigned char buffered_nh[4];
    unsigned char buffered_prefix[16];
    unsigned char *sendbuf;
    struct buffered_update *buffered_updates;
    int num_buffered_updates;
    int update_bufsize;
    time_t bucket_time;
    unsigned int bucket;
    time_t activity_time;
    unsigned short hello_seqno;
    unsigned short hello_interval;
    unsigned short self_update_interval;
};

extern struct network *networks;
extern int numnets;

#define FOR_ALL_NETS(_net) for(_net = networks; _net; _net = _net->next)

static inline int
net_up(struct network *net)
{
    return !!(net->flags & NET_UP);
}

struct network *add_network(char *ifname, struct network_conf *conf);
int network_idle(struct network *net);
int update_hello_interval(struct network *net);
unsigned jitter(struct network *net, int urgent);
unsigned update_jitter(struct network *net, int urgent);
void delay_jitter(struct timeval *timeout, int msecs);
int network_up(struct network *net, int up);
int network_ll_address(struct network *net, const unsigned char *address);
void check_networks(void);
