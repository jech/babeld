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

#include "babel.h"
#include "util.h"
#include "source.h"

struct source srcs[MAXSRCS];
int numsrcs = 0;

struct source *
find_source(const unsigned char *a, const unsigned char *p, unsigned char plen,
            int create, unsigned short seqno)
{
    struct source *src;
    int i;

    for(i = 0; i < numsrcs; i++) {
        if(!srcs[i].valid)
            continue;
        /* This should really be a hash table.  For now, check the
           last byte first. */
        if(srcs[i].address[15] != a[15])
            continue;
        if(memcmp(srcs[i].address, a, 16) != 0)
            continue;
        if(source_match(&srcs[i], p, plen))
           return &srcs[i];
    }

    if(!create)
        return NULL;

    src = NULL;

    for(i = 0; i < numsrcs; i++) {
        if(srcs[i].valid == 0) {
            src = &srcs[i];
            break;
        }
    }

    if(!src) {
        if(numsrcs >= MAXSRCS) {
            fprintf(stderr, "Too many sources.\n");
            return NULL;
        }
        src = &srcs[numsrcs++];
    }

    src->valid = 1;
    memcpy(src->address, a, 16);
    memcpy(src->prefix, p, 16);
    src->plen = plen;
    src->seqno = seqno;
    src->metric = INFINITY;
    src->time = now.tv_sec;
    return src;
}

/* It is the caller's responsibility to check that no routes point at
   this source. */
void
flush_source(struct source *src)
{
    memset(src, 0, sizeof(*src));
    VALGRIND_MAKE_MEM_UNDEFINED(src, sizeof(*src));
    src->valid = 0;
}

struct source *
find_recent_source(const unsigned char *p, unsigned char plen)
{
    int i;
    struct source *src = NULL;

    for(i = 0; i < numsrcs; i++) {
        if(!srcs[i].valid)
            continue;
        if(!source_match(&srcs[i], p, plen))
            continue;
        if(!src || src->time < srcs[i].time)
            src = &srcs[i];
    }
    return src;
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
