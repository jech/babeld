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

#define MAXROUTES 512
#define MAXSRCS 1024
#define MAXNEIGHBOURS 128
#define MAXNETS 8
#define MAXXROUTES 64

#define INFINITY ((unsigned short)(~0))

#ifndef RTPROT_BABEL
#define RTPROT_BABEL 42
#endif

#undef MAX
#undef MIN

#define MAX(x,y) ((x)<=(y)?(y):(x))
#define MIN(x,y) ((x)<=(y)?(x):(y))

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define ATTRIBUTE(x) __attribute__(x)
#else
#define ATTRIBUTE(x) /**/
#endif

#ifndef IF_NAMESIZE
#include <net/if.h>
#endif

#ifdef HAVE_VALGRIND
#include <valgrind/memcheck.h>
#else
#ifndef VALGRIND_MAKE_MEM_UNDEFINED
#define VALGRIND_MAKE_MEM_UNDEFINED(a, b) do {} while(0)
#endif
#ifndef VALGRIND_CHECK_MEM_IS_DEFINED
#define VALGRIND_CHECK_MEM_IS_DEFINED(a, b) do {} while(0)
#endif
#endif

struct network {
    unsigned int ifindex;
    int wired;
    unsigned short cost;
    int hello_time;
    int self_update_time;
    int update_time;
    int ihu_time;
    char ifname[IF_NAMESIZE];
    int buffered;
    struct timeval flush_time;
    int bufsize;
    unsigned char *sendbuf;
    int bucket_time;
    unsigned int bucket;
    int activity_time;
    unsigned short hello_seqno;
    unsigned int hello_interval;
    unsigned int self_update_interval;
    unsigned int ihu_interval;
};

extern struct timeval now;
extern int debug;
extern int reboot_time;

extern unsigned char myid[16];

extern struct network nets[MAXNETS];
extern int numnets;

extern const unsigned char zeroes[16], ones[16];

extern int protocol_port;
extern unsigned char protocol_group[16];
extern int protocol_socket;
extern int kernel_socket;
extern int max_request_hopcount;

int network_idle(struct network *net);
int update_hello_interval(struct network *net);
