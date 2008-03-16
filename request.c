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

#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "babel.h"
#include "util.h"
#include "neighbour.h"
#include "request.h"
#include "message.h"
#include "network.h"
#include "filter.h"

struct timeval request_resend_time = {0, 0};
struct request *recorded_requests = NULL;

static int
request_match(struct request *request,
              const unsigned char *prefix, unsigned char plen)
{
    return request->plen == plen && memcmp(request->prefix, prefix, 16) == 0;
}

struct request *
find_request(const unsigned char *prefix, unsigned char plen,
             struct request **previous_return)
{
    struct request *request, *previous;

    previous = NULL;
    request = recorded_requests;
    while(request) {
        if(request_match(request, prefix, plen)) {
            if(previous_return)
                *previous_return = previous;
            return request;
        }
        previous = request;
        request = request->next;
    }

    return NULL;
}

int
record_request(const unsigned char *prefix, unsigned char plen,
               unsigned short seqno, unsigned short router_hash,
               struct network *network, int resend)
{
    struct request *request;
    unsigned int ifindex = network ? network->ifindex : 0;

    if(input_filter(NULL, prefix, plen, NULL, ifindex) >= INFINITY ||
       output_filter(NULL, prefix, plen, ifindex) >= INFINITY)
        return 0;

    request = find_request(prefix, plen, NULL);
    if(request) {
        if(request->resend && resend)
            request->resend = MIN(request->resend, resend);
        else if(resend)
            request->resend = resend;
        request->time = now;
        if(request->router_hash == router_hash &&
           seqno_compare(request->seqno, seqno) > 0) {
            return 0;
        }
        request->router_hash = router_hash;
        request->seqno = seqno;
        if(request->network != network)
            request->network = NULL;
    } else {
        request = malloc(sizeof(struct request));
        if(request == NULL)
            return -1;
        memcpy(request->prefix, prefix, 16);
        request->plen = plen;
        request->seqno = seqno;
        request->router_hash = router_hash;
        request->network = network;
        request->time = now;
        request->resend = resend;
        request->next = recorded_requests;
        recorded_requests = request;
    }

    if(request->resend) {
        struct timeval timeout;
        timeval_plus_msec(&timeout, &request->time, request->resend);
        timeval_min(&request_resend_time, &timeout);
    }
    return 1;
}

int
unsatisfied_request(const unsigned char *prefix, unsigned char plen,
                    unsigned short seqno, unsigned short router_hash)
{
    struct request *request;

    request = find_request(prefix, plen, NULL);
    if(request == NULL)
        return 0;

    if(request->router_hash != router_hash ||
       seqno_compare(request->seqno, seqno) <= 0)
        return 1;

    return 0;
}

int
satisfy_request(const unsigned char *prefix, unsigned char plen,
                unsigned short seqno, unsigned short router_hash,
                struct network *network)
{
    struct request *request, *previous;

    request = find_request(prefix, plen, &previous);
    if(request == NULL)
        return 0;

    if(network != NULL && request->network != network)
        return 0;

    if(request->router_hash != router_hash ||
       seqno_compare(request->seqno, seqno) <= 0) {
        if(previous == NULL)
            recorded_requests = request->next;
        else
            previous->next = request->next;
        free(request);
        recompute_request_resend_time();
        return 1;
    }

    return 0;
}

void
expire_requests()
{
    struct request *request, *previous;
    int recompute = 0;

    previous = NULL;
    request = recorded_requests;
    while(request) {
        if(timeval_minus_msec(&now, &request->time) >= REQUEST_TIMEOUT) {
            if(previous == NULL) {
                recorded_requests = request->next;
                free(request);
                request = recorded_requests;
            } else {
                previous->next = request->next;
                free(request);
                request = previous->next;
            }
            recompute = 1;
        } else {
            request = request->next;
        }
    }
    if(recompute)
        recompute_request_resend_time();
}

void
recompute_request_resend_time()
{
    struct request *request;
    struct timeval resend = {0, 0};

    request = recorded_requests;
    while(request) {
        if(request->resend) {
            struct timeval timeout;
            timeval_plus_msec(&timeout, &request->time, request->resend);
            timeval_min(&request_resend_time, &timeout);
        }
        request = request->next;
    }

    request_resend_time = resend;
}

void
resend_requests()
{
    struct request *request;

    request = recorded_requests;
    while(request) {
        if(request->resend) {
            struct timeval timeout;
            timeval_plus_msec(&timeout, &request->time, request->resend);
            if(timeval_compare(&now, &timeout) >= 0) {
                send_request(NULL, request->prefix, request->plen, 127,
                             request->seqno, request->router_hash);
                request->resend *= 2;
            }
        }
        request = request->next;
    }
    recompute_request_resend_time();
}
