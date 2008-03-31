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

#define REQUEST_TIMEOUT 125000

struct request {
    unsigned char prefix[16];
    unsigned char plen;
    unsigned short seqno;
    unsigned short router_hash;
    struct network *network;
    struct timeval time;
    int resend;
    struct request *next;
};

extern struct timeval resend_time;

struct request *find_request(const unsigned char *prefix, unsigned char plen,
                             struct request **previous_return);
int record_request(const unsigned char *prefix, unsigned char plen,
                   unsigned short seqno, unsigned short router_hash,
                   struct network *net, int resend);
int unsatisfied_request(const unsigned char *prefix, unsigned char plen,
                        unsigned short seqno, unsigned short router_hash);
int satisfy_request(const unsigned char *prefix, unsigned char plen,
                    unsigned short seqno, unsigned short router_hash,
                    struct network *net);

void expire_requests(void);
void recompute_resend_time(void);
void do_resend(void);
