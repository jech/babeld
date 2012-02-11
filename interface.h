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

struct interface_conf {
    char *ifname;
    unsigned hello_interval;
    unsigned update_interval;
    unsigned short cost;
    char wired;
    char split_horizon;
    char lq;
    char faraway;
    int channel;
    struct interface_conf *next;
};

#define CONFIG_DEFAULT 0
#define CONFIG_NO 1
#define CONFIG_YES 2

#define IF_UP (1 << 0)
#define IF_WIRED (1<<1)
#define IF_SPLIT_HORIZON (1 << 2)
#define IF_LQ (1 << 3)
#define IF_FARAWAY (1 << 4)

/* Only INTERFERING can appear on the wire. */
#define IF_CHANNEL_UNKNOWN 0
#define IF_CHANNEL_INTERFERING 255
#define IF_CHANNEL_NONINTERFERING -2

struct interface {
    struct interface *next;
    struct interface_conf *conf;
    unsigned int ifindex;
    unsigned short flags;
    unsigned short cost;
    int channel;
    struct timeval hello_timeout;
    struct timeval update_timeout;
    struct timeval flush_timeout;
    struct timeval update_flush_timeout;
    char name[IF_NAMESIZE];
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
    time_t last_update_time;
    unsigned short hello_seqno;
    unsigned hello_interval;
    unsigned update_interval;
};

#define IF_CONF(_ifp, _field) \
    ((_ifp)->conf ? (_ifp)->conf->_field : 0)

extern struct interface *interfaces;

#define FOR_ALL_INTERFACES(_ifp) for(_ifp = interfaces; _ifp; _ifp = _ifp->next)

static inline int
if_up(struct interface *ifp)
{
    return !!(ifp->flags & IF_UP);
}

struct interface *add_interface(char *ifname, struct interface_conf *if_conf);
unsigned jitter(struct interface *ifp, int urgent);
unsigned update_jitter(struct interface *ifp, int urgent);
void set_timeout(struct timeval *timeout, int msecs);
int interface_up(struct interface *ifp, int up);
int interface_ll_address(struct interface *ifp, const unsigned char *address);
void check_interfaces(void);
