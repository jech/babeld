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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "babeld.h"
#include "util.h"
#include "source.h"
#include "network.h"
#include "route.h"

struct source *srcs = NULL;

struct source*
find_source(const unsigned char *id, const unsigned char *p, unsigned char plen,
            int create, unsigned short seqno)
{
    struct source *src;

    for(src = srcs; src; src = src->next) {
        /* This should really be a hash table.  For now, check the
           last byte first. */
        if(src->id[7] != id[7])
            continue;
        if(memcmp(src->id, id, 8) != 0)
            continue;
        if(source_match(src, p, plen))
           return src;
    }

    if(!create)
        return NULL;

    src = malloc(sizeof(struct source));
    if(src == NULL) {
        perror("malloc(source)");
        return NULL;
    }

    memcpy(src->id, id, 8);
    memcpy(src->prefix, p, 16);
    src->plen = plen;
    src->seqno = seqno;
    src->metric = INFINITY;
    src->time = now.tv_sec;
    src->next = srcs;
    srcs = src;
    return src;
}

int
flush_source(struct source *src)
{
    int i;

    /* This is absolutely horrible -- it makes expire_sources quadratic.
       But it's not called very often. */

    for(i = 0; i < numroutes; i++) {
        if(routes[i].src == src)
            return 0;
    }

    if(srcs == src) {
        srcs = src->next;
    } else {
        struct source *previous = srcs;
        while(previous->next != src)
            previous = previous->next;
        previous->next = src->next;
    }

    free(src);
    return 1;
}

int
source_match(struct source *src,
             const unsigned char *p, unsigned char plen)
{
    if(src->plen != plen)
        return 0;
    if(src->prefix[15] != p[15])
        return 0;
    if(memcmp(src->prefix, p, 16) != 0)
        return 0;
    return 1;
}

void
update_source(struct source *src,
              unsigned short seqno, unsigned short metric)
{
    if(metric >= INFINITY)
        return;

    if(src->time < now.tv_sec - SOURCE_GC_TIME ||
       seqno_compare(src->seqno, seqno) < 0 ||
       (src->seqno == seqno && src->metric > metric)) {
        src->seqno = seqno;
        src->metric = metric;
    }
    src->time = now.tv_sec;
}

void
expire_sources()
{
    struct source *src;

    src = srcs;
    while(src) {
        if(src->time > now.tv_sec)
            /* clock stepped */
            src->time = now.tv_sec;
        if(src->time < now.tv_sec - SOURCE_GC_TIME) {
            struct source *old = src;
            src = src->next;
            flush_source(old);
            continue;
        }
        src = src->next;
    }
}
