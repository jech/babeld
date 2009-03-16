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
#include <string.h>
#include <stdio.h>

#include "babel.h"
#include "util.h"
#include "config.h"

struct filter *input_filters = NULL;
struct filter *output_filters = NULL;
struct filter *redistribute_filters = NULL;

/* get_next_char callback */
typedef int (*gnc_t)(void*);

static int
skip_whitespace(int c, gnc_t gnc, void *closure)
{
    while(c == ' ' || c == '\t')
        c = gnc(closure);
    return c;
}

static int
skip_to_eol(int c, gnc_t gnc, void *closure)
{
    while(c != '\n' && c >= 0)
        c = gnc(closure);
    if(c == '\n')
        c = gnc(closure);
    return c;
}

static int
getword(int c, char **token_r, gnc_t gnc, void *closure)
{
    char buf[256];
    int i = 0;

    c = skip_whitespace(c, gnc, closure);
    if(c < 0)
        return c;
    if(c == '"' || c == '\n')
        return -2;
    do {
        if(i >= 255) return -2;
        buf[i++] = c;
        c = gnc(closure);
    } while(c != ' ' && c != '\t' && c != '\n' && c >= 0);
    buf[i] = '\0';
    *token_r = strdup(buf);
    return c;
}

static int
getstring(int c, char **token_r, gnc_t gnc, void *closure)
{
    char buf[256];
    int i = 0;

    c = skip_whitespace(c, gnc, closure);
    if(c < 0)
        return c;
    if(c == '\n')
        return -2;

    /* Unquoted strings have the same syntax as words. */
    if(c != '"')
        return getword(c, token_r, gnc, closure);

    c = gnc(closure);

    while(1) {
        if(i >= 255 || c == '\n') return -2;
        if(c == '"') {
            c = gnc(closure);
            break;
        }
        if(c == '\\')
            c = gnc(closure);
        buf[i++] = c;
        c = gnc(closure);
    }

    buf[i] = '\0';
    *token_r = strdup(buf);
    return c;
}

static int
getint(int c, int *int_r, gnc_t gnc, void *closure)
{
    char *t, *end;
    int i;
    c = getword(c, &t, gnc, closure);
    if(c < -1)
        return c;
    i = strtol(t, &end, 0);
    if(*end != '\0') {
        free(t);
        return -2;
    }
    free(t);
    *int_r = i;
    return c;
}

static int
getip(int c, unsigned char **ip_r, int *af_r, gnc_t gnc, void *closure)
{
    char *t;
    unsigned char *ip;
    unsigned char addr[16];
    int af, rc;

    c = getword(c, &t, gnc, closure);
    if(c < -1)
        return c;
    rc = parse_address(t, addr, &af);
    if(rc < 0) {
        free(t);
        return -2;
    }
    free(t);

    ip = malloc(16);
    if(ip == NULL) {
        return -2;
    }
    memcpy(ip, addr, 16);
    *ip_r = ip;
    if(af_r)
        *af_r = af;
    return c;
}

static int
getid(int c, unsigned char **id_r, gnc_t gnc, void *closure)
{
    char *t;
    unsigned char *idp;
    unsigned char id[8];
    int rc;

    c = getword(c, &t, gnc, closure);
    if(c < -1)
        return c;
    rc = parse_eui64(t, id);
    if(rc < 0) {
        free(t);
        return -2;
    }
    free(t);

    idp = malloc(8);
    if(idp == NULL) {
        return -2;
    }
    memcpy(idp, id, 8);
    *id_r = idp;
    return c;
}

static int
getnet(int c, unsigned char **p_r, unsigned char *plen_r, int *af_r,
          gnc_t gnc, void *closure)
{
    char *t;
    unsigned char *ip;
    unsigned char addr[16];
    unsigned char plen;
    int af, rc;

    c = getword(c, &t, gnc, closure);
    if(c < -1)
        return c;
    rc = parse_net(t, addr, &plen, &af);
    if(rc < 0) {
        free(t);
        return -2;
    }
    free(t);
    ip = malloc(16);
    if(ip == NULL)
        return -2;
    memcpy(ip, addr, 16);
    *p_r = ip;
    *plen_r = plen;
    if(af_r) *af_r = af;
    return c;
}

static struct filter *
parse_filter(gnc_t gnc, void *closure)
{
    int c;
    char *token;
    struct filter *filter;

    filter = calloc(1, sizeof(struct filter));
    if(filter == NULL)
        goto error;
    filter->plen_le = 128;

    c = gnc(closure);
    if(c < -1)
        goto error;

    while(c >= 0 && c != '\n') {
        c = skip_whitespace(c, gnc, closure);
        if(c == '#') {
            c = skip_to_eol(c, gnc, closure);
            break;
        }
        c = getword(c, &token, gnc, closure);
        if(c < -1)
            goto error;

        if(strcmp(token, "ip") == 0) {
            c = getnet(c, &filter->prefix, &filter->plen, &filter->af,
                       gnc, closure);
            if(c < -1)
                goto error;
        } else if(strcmp(token, "eq") == 0) {
            int p;
            c = getint(c, &p, gnc, closure);
            if(c < -1)
                goto error;
            filter->plen_ge = MAX(filter->plen_ge, p);
            filter->plen_le = MIN(filter->plen_le, p);
        } else if(strcmp(token, "le") == 0) {
            int p;
            c = getint(c, &p, gnc, closure);
            if(c < -1)
                goto error;
            filter->plen_le = MIN(filter->plen_le, p);
        } else if(strcmp(token, "ge") == 0) {
            int p;
            c = getint(c, &p, gnc, closure);
            if(c < -1)
                goto error;
            filter->plen_ge = MAX(filter->plen_ge, p);
        } else if(strcmp(token, "neigh") == 0) {
            unsigned char *neigh;
            c = getip(c, &neigh, NULL, gnc, closure);
            if(c < -1)
                goto error;
            filter->neigh = neigh;
        } else if(strcmp(token, "id") == 0) {
            unsigned char *id;
            c = getid(c, &id, gnc, closure);
            if(c < -1)
                goto error;
            filter->id = id;
        } else if(strcmp(token, "proto") == 0) {
            int proto;
            c = getint(c, &proto, gnc, closure);
            if(c < -1)
                goto error;
            filter->proto = proto;
        } else if(strcmp(token, "local") == 0) {
            filter->proto = RTPROT_BABEL_LOCAL;
        } else if(strcmp(token, "if") == 0) {
            char *interface;
            c = getstring(c, &interface, gnc, closure);
            if(c < -1)
                goto error;
            filter->ifname = interface;
            filter->ifindex = if_nametoindex(interface);
        } else if(strcmp(token, "allow") == 0) {
            filter->result = 0;
        } else if(strcmp(token, "deny") == 0) {
            filter->result = INFINITY;
        } else if(strcmp(token, "metric") == 0) {
            int metric;
            c = getint(c, &metric, gnc, closure);
            if(c < -1) goto error;
            if(metric <= 0 || metric > INFINITY)
                goto error;
            filter->result = metric;
        } else {
            goto error;
        }
        free(token);
    }
    if(filter->af == 0) {
        if(filter->plen_le < 128 || filter->plen_ge > 0)
            filter->af = AF_INET6;
    } else if(filter->af == AF_INET) {
        filter->plen_le += 96;
        filter->plen_ge += 96;
    }
    return filter;
 error:
    free(filter);
    return NULL;
}

static void
add_filter(struct filter *filter, struct filter **filters)
{
    struct filter *f;
    if(*filters == NULL) {
        filter->next = NULL;
        *filters = filter;
    } else {
        f = *filters;
        while(f->next)
            f = f->next;
        filter->next = NULL;
        f->next = filter;
    }
}

static int
parse_config(gnc_t gnc, void *closure)
{
    int kind;
    int c;
    char *token;
    struct filter *filter;
    c = gnc(closure);
    if(c < 2)
        return -1;

    while(c >= 0) {
        c = skip_whitespace(c, gnc, closure);
        if(c == '#') {
            c = skip_to_eol(c, gnc, closure);
            continue;
        }
        if(c == '\n') {
            c = gnc(closure);
            continue;
        }
        if(c < 0)
            break;
        c = getword(c, &token, gnc, closure);
        if(c < -1)
            return -1;

        if(strcmp(token, "in") == 0) {
            kind = 1;
        } else if(strcmp(token, "out") == 0) {
            kind = 2;
        } else if(strcmp(token, "redistribute") == 0) {
            kind = 3;
        } else {
            return -1;
        }
        free(token);

        filter = parse_filter(gnc, closure);
        if(filter == NULL)
            return -1;

        if(kind == 1)
            add_filter(filter, &input_filters);
        else if(kind == 2)
            add_filter(filter, &output_filters);
        else if(kind == 3)
            add_filter(filter, &redistribute_filters);
        else
            return -1;
    }
    return 1;
}

int
parse_config_from_file(char *filename)
{
    FILE *f;
    int rc;

    f = fopen(filename, "r");
    if(f == NULL)
        return -1;
    rc = parse_config((gnc_t)fgetc, f);
    fclose(f);
    return rc;
}

struct string_state {
    char *string;
    int n;
};

static int
gnc_string(struct string_state *s)
{
    if(s->string[s->n] == '\0')
        return -1;
    else
        return s->string[s->n++];
}

int
parse_config_from_string(char *string)
{
    struct string_state s = { string, 0 };
    return parse_config((gnc_t)gnc_string, &s);
}

static void
renumber_filter(struct filter *filter)
{
    while(filter) {
        if(filter->ifname)
            filter->ifindex = if_nametoindex(filter->ifname);
        filter = filter->next;
    }
}

void
renumber_filters()
{
    renumber_filter(input_filters);
    renumber_filter(output_filters);
    renumber_filter(redistribute_filters);
}

static int
filter_match(struct filter *f, const unsigned char *id,
             const unsigned char *prefix, unsigned short plen,
             const unsigned char *neigh, unsigned int ifindex, int proto)
{
    if(f->af) {
        if(plen >= 96 && v4mapped(prefix)) {
            if(f->af == AF_INET6) return 0;
        } else {
            if(f->af == AF_INET) return 0;
        }
    }
    if(f->id) {
        if(!id || memcmp(f->id, id, 8) != 0)
            return 0;
    }
    if(f->prefix) {
        if(!prefix || plen < f->plen || !in_prefix(prefix, f->prefix, f->plen))
            return 0;
    }
    if(f->plen_ge > 0 || f->plen_le < 128) {
        if(!prefix)
            return 0;
        if(plen > f->plen_le)
            return 0;
        if(plen < f->plen_ge)
            return 0;
    }
    if(f->neigh) {
        if(!neigh || memcmp(f->neigh, neigh, 16) != 0)
            return 0;
    }
    if(f->ifname) {
        if(!f->ifindex)         /* no such interface */
            return 0;
        if(!ifindex || f->ifindex != ifindex)
            return 0;
    }
    if(f->proto) {
        if(!proto || f->proto != proto)
            return 0;
    } else if(proto == RTPROT_BABEL_LOCAL) {
        return 0;
    }
    return 1;
}

static int
do_filter(struct filter *f, const unsigned char *id,
          const unsigned char *prefix, unsigned short plen,
          const unsigned char *neigh, unsigned int ifindex, int proto)
{
    while(f) {
        if(filter_match(f, id, prefix, plen, neigh, ifindex, proto))
            return f->result;
        f = f->next;
    }
    return -1;
}

int
input_filter(const unsigned char *id,
             const unsigned char *prefix, unsigned short plen,
             const unsigned char *neigh, unsigned int ifindex)
{
    int res;
    res = do_filter(input_filters, id, prefix, plen, neigh, ifindex, 0);
    if(res < 0)
        res = 0;
    return res;
}

int
output_filter(const unsigned char *id, const unsigned char *prefix,
              unsigned short plen, unsigned int ifindex)
{
    int res;
    res = do_filter(output_filters, id, prefix, plen, NULL, ifindex, 0);
    if(res < 0)
        res = 0;
    return res;
}

int
redistribute_filter(const unsigned char *prefix, unsigned short plen,
                    unsigned int ifindex, int proto)
{
    int res;
    res = do_filter(redistribute_filters, NULL, prefix, plen, NULL,
                    ifindex, proto);
    if(res < 0)
        res = INFINITY;
    return res;
}

int
finalise_filters()
{
    struct filter *filter = calloc(1, sizeof(struct filter));
    if(filter == NULL)
        return -1;

    filter->proto = RTPROT_BABEL_LOCAL;
    filter->plen_le = 128;
    add_filter(filter, &redistribute_filters);

    return 1;
}
