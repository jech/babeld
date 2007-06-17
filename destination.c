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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "babel.h"
#include "util.h"
#include "destination.h"

struct destination dests[MAXDESTS];
int numdests = 0;

struct destination *
find_destination(const unsigned char *d, int create, unsigned char seqno)
{
    int i;
    for(i = 0; i < numdests; i++) {
        if(memcmp(dests[i].address, d, 16) == 0)
            return &dests[i];
    }

    if(!create)
        return NULL;

    if(i >= numdests) {
        if(numdests >= MAXDESTS) {
            fprintf(stderr, "Too many destinations.\n");
            return NULL;
        }
        memcpy(dests[numdests].address, d, 16);
        numdests++;
    }
    dests[i].seqno = seqno;
    dests[i].metric = INFINITY;
    return &dests[i];
}

void
update_destination(struct destination *dest,
                   unsigned char seqno, unsigned short metric)
{
    if(seqno_compare(dest->seqno, seqno) < 0 ||
       (dest->seqno == seqno && dest->metric > metric)) {
        dest->seqno = seqno;
        dest->metric = metric;
    }
    dest->time = now.tv_sec;
}

