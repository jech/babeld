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

struct network {
    int up;
    unsigned int ifindex;
    int wired;
    unsigned short cost;
    struct timeval hello_time;
    struct timeval hello_timeout;
    struct timeval self_update_time;
    struct timeval self_update_timeout;
    struct timeval update_time;
    struct timeval update_timeout;
    char ifname[IF_NAMESIZE];
    unsigned char *ipv4;
    int buffered;
    struct timeval flush_timeout;
    int bufsize;
    unsigned char *sendbuf;
    time_t bucket_time;
    unsigned int bucket;
    time_t activity_time;
    unsigned short hello_seqno;
    unsigned int hello_interval;
    unsigned int self_update_interval;
};

extern struct network nets[MAXNETS];
extern int numnets;

#define FOR_ALL_NETS(_net) for(_net = nets; _net < nets + numnets; _net++)

struct network *add_network(char *ifname);
int network_idle(struct network *net);
int update_hello_interval(struct network *net);
unsigned int jitter(struct network *net, int urgent);
unsigned int update_jitter(struct network *net, int urgent);
void delay_jitter(struct timeval *time, struct timeval *timeout, int msecs);
int network_up(struct network *net, int up);
void check_networks(void);
