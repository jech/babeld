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
#include <assert.h>

#include "babeld.h"
#include "util.h"
#include "source.h"
#include "interface.h"
#include "route.h"

static struct source **sources = NULL;
static int source_slots = 0, max_source_slots = 0;

static int
source_compare(const unsigned char *id,
               const unsigned char *prefix, unsigned char plen,
               const unsigned char *src_prefix, unsigned char src_plen,
               const struct source *src)
{
    int rc;

    rc = memcmp(id, src->id, 8);
    if(rc != 0)
        return rc;

    if(plen < src->plen)
        return -1;
    if(plen > src->plen)
        return 1;

    rc = memcmp(prefix, src->prefix, 16);
    if(rc != 0)
        return rc;

    rc = memcmp(src_prefix, src->src_prefix, 16);
    if(rc != 0)
        return rc;

    return 0;
}

static int
find_source_slot(const unsigned char *id,
                 const unsigned char *prefix, unsigned char plen,
                 const unsigned char *src_prefix, unsigned char src_plen,
                 int *new_return)
{
    int p, m, g, c;

    if(source_slots < 1) {
        if(new_return)
            *new_return = 0;
        return -1;
    }

    p = 0; g = source_slots - 1;

    do {
        m = (p + g) / 2;
        c = source_compare(id, prefix, plen, src_prefix, src_plen, sources[m]);
        if(c == 0)
            return m;
        else if(c < 0)
            g = m - 1;
        else
            p = m + 1;
    } while(p <= g);

    if(new_return)
        *new_return = p;

    return -1;
}

static int
resize_source_table(int new_slots)
{
    struct source **new_sources;
    assert(new_slots >= source_slots);

    if(new_slots == 0) {
        new_sources = NULL;
        free(sources);
    } else {
        new_sources = realloc(sources, new_slots * sizeof(struct source*));
        if(new_sources == NULL)
            return -1;
    }

    max_source_slots = new_slots;
    sources = new_sources;
    return 1;
}

struct source*
find_source(const unsigned char *id,
            const unsigned char *prefix, unsigned char plen,
            const unsigned char *src_prefix, unsigned char src_plen,
            int create, unsigned short seqno)
{
    int n = -1;
    int i = find_source_slot(id, prefix, plen, src_prefix, src_plen, &n);
    struct source *src;

    if(i >= 0)
        return sources[i];

    if(!create)
        return NULL;

    src = calloc(1, sizeof(struct source));
    if(src == NULL) {
        perror("malloc(source)");
        return NULL;
    }

    memcpy(src->id, id, 8);
    memcpy(src->prefix, prefix, 16);
    src->plen = plen;
    memcpy(src->src_prefix, src_prefix, 16);
    src->src_plen = src_plen;
    src->seqno = seqno;
    src->metric = INFINITY;
    src->time = now.tv_sec;

    if(source_slots >= max_source_slots)
        resize_source_table(max_source_slots < 1 ? 8 : 2 * max_source_slots);
    if(source_slots >= max_source_slots) {
        free(src);
        return NULL;
    }
    if(n < source_slots)
        memmove(sources + n + 1, sources + n,
                (source_slots - n) * sizeof(struct source*));
    source_slots++;
    sources[n] = src;

    return src;
}

struct source *
retain_source(struct source *src)
{
    assert(src->route_count < 0xffff);
    src->route_count++;
    return src;
}

void
release_source(struct source *src)
{
    assert(src->route_count > 0);
    src->route_count--;
}

void
update_source(struct source *src,
              unsigned short seqno, unsigned short metric)
{
    if(metric >= INFINITY)
        return;

    /* If a source is expired, pretend that it doesn't exist and update
       it unconditionally.  This makes ensures that old data will
       eventually be overridden, and prevents us from getting stuck if
       a router loses its sequence number. */
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
    int i = 0, j = 0;
    while(i < source_slots) {
        struct source *src = sources[i];

        if(src->time > now.tv_sec)
            /* clock stepped */
            src->time = now.tv_sec;

        if(src->route_count == 0 && src->time < now.tv_sec - SOURCE_GC_TIME) {
            free(src);
            sources[i] = NULL;
            i++;
        } else {
            if(j < i) {
                sources[j] = sources[i];
                sources[i] = NULL;
            }
            i++;
            j++;
        }
    }
    source_slots = j;
}

void
check_sources_released(void)
{
    int i;

    for(i = 0; i < source_slots; i++) {
        struct source *src = sources[i];

        if(src->route_count != 0)
            fprintf(stderr, "Warning: source %s %s has refcount %d.\n",
                    format_eui64(src->id),
                    format_prefix(src->prefix, src->plen),
                    (int)src->route_count);
    }
}
