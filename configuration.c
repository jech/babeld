/*
Copyright (c) 2007-2010 by Juliusz Chroboczek

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
#include <sys/time.h>
#include <assert.h>

#ifdef __linux
/* Defining it rather than including <linux/rtnetlink.h> because this
 * implies <asm/types.h> on Linux 2.4 */
#define RTPROT_BOOT 3 /* Route installed during boot */
#endif

#include "babeld.h"
#include "util.h"
#include "interface.h"
#include "route.h"
#include "kernel.h"
#include "configuration.h"
#include "rule.h"

struct filter *input_filters = NULL;
struct filter *output_filters = NULL;
struct filter *redistribute_filters = NULL;
struct filter *install_filters = NULL;
struct interface_conf *default_interface_conf = NULL;
struct interface_conf *interface_confs = NULL;

/* This file implements a recursive descent parser with one character
   lookahead.  The looked-ahead character is returned from most
   functions.

   Throughout this file, -1 signals that the look-ahead is EOF,
   while -2 signals an error. */

/* get_next_char callback */
typedef int (*gnc_t)(void*);

static int
skip_whitespace(int c, gnc_t gnc, void *closure)
{
    while(c == ' ' || c == '\t' || c == '\r')
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
    if(c < 0 || c == '"' || c == '\n' || c == '#' || c < 0)
        return -2;
    do {
        if(i >= 255) return -2;
        buf[i++] = c;
        c = gnc(closure);
    } while(c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != '#' && c >= 0);
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
    if(c < 0 || c == '\n' || c == '#')
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

        if(c < 0)
            return -2;

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
getthousands(int c, int *int_r, gnc_t gnc, void *closure)
{
    char *t;
    int i;
    c = getword(c, &t, gnc, closure);
    if(c < -1)
        return c;
    i = parse_thousands(t);
    if(i < 0) {
        free(t);
        return -2;
    }
    free(t);
    *int_r = i;
    return c;
}

static int
getbool(int c, int *int_r, gnc_t gnc, void *closure)
{
    char *t;
    int i;
    c = getword(c, &t, gnc, closure);
    if(c < -1)
        return c;
    if(strcmp(t, "true") == 0 || strcmp(t, "yes") == 0)
        i = CONFIG_YES;
    else if(strcmp(t, "false") == 0 || strcmp(t, "no") == 0)
        i = CONFIG_NO;
    else if(strcmp(t, "default") == 0 || strcmp(t, "auto") == 0)
        i = CONFIG_DEFAULT;
    else {
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

static int
parse_filter(int c, gnc_t gnc, void *closure, struct filter **filter_return)
{
    char *token;
    struct filter *filter;

    filter = calloc(1, sizeof(struct filter));
    if(filter == NULL)
        goto error;
    filter->plen_le = 128;
    filter->src_plen_le = 128;

    while(1) {
        c = skip_whitespace(c, gnc, closure);
        if(c < 0 || c == '\n' || c == '#') {
            c = skip_to_eol(c, gnc, closure);
            break;
        }
        c = getword(c, &token, gnc, closure);
        if(c < -1)
            goto error;

        if(strcmp(token, "ip") == 0) {
            int af;
            c = getnet(c, &filter->prefix, &filter->plen, &af,
                       gnc, closure);
            if(c < -1)
                goto error;
            if(filter->af == AF_UNSPEC)
                filter->af = af;
            else if(filter->af != af)
                goto error;
        } else if(strcmp(token, "src-ip") == 0) {
            int af;
            c = getnet(c, &filter->src_prefix, &filter->src_plen, &af,
                       gnc, closure);
            if(c < -1)
                goto error;
            if(filter->af == AF_UNSPEC)
                filter->af = af;
            else if(filter->af != af)
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
        } else if(strcmp(token, "src-eq") == 0) {
            int p;
            c = getint(c, &p, gnc, closure);
            if(c < -1)
                goto error;
            filter->src_plen_ge = MAX(filter->src_plen_ge, p);
            filter->src_plen_le = MIN(filter->src_plen_le, p);
        } else if(strcmp(token, "src-le") == 0) {
            int p;
            c = getint(c, &p, gnc, closure);
            if(c < -1)
                goto error;
            filter->src_plen_le = MIN(filter->src_plen_le, p);
        } else if(strcmp(token, "src-ge") == 0) {
            int p;
            c = getint(c, &p, gnc, closure);
            if(c < -1)
                goto error;
            filter->src_plen_ge = MAX(filter->src_plen_ge, p);
        } else if(strcmp(token, "neigh") == 0) {
            unsigned char *neigh = NULL;
            c = getip(c, &neigh, NULL, gnc, closure);
            if(c < -1)
                goto error;
            filter->neigh = neigh;
        } else if(strcmp(token, "id") == 0) {
            unsigned char *id = NULL;
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
            filter->action.add_metric = 0;
        } else if(strcmp(token, "deny") == 0) {
            filter->action.add_metric = INFINITY;
        } else if(strcmp(token, "metric") == 0) {
            int metric;
            c = getint(c, &metric, gnc, closure);
            if(c < -1) goto error;
            if(metric <= 0 || metric > INFINITY)
                goto error;
            filter->action.add_metric = metric;
        } else if(strcmp(token, "src-prefix") == 0) {
            int af;
            c = getnet(c, &filter->action.src_prefix, &filter->action.src_plen,
                       &af, gnc, closure);
            if(c < -1)
                goto error;
            if(filter->af == AF_UNSPEC)
                filter->af = af;
            else if(filter->af != af)
                goto error;
            if(af == AF_INET && filter->action.src_plen == 96)
                memset(&filter->action.src_prefix, 0, 16);
        } else if(strcmp(token, "table") == 0) {
            int table;
            c = getint(c, &table, gnc, closure);
            if(c < -1) goto error;
            if(table <= 0 || table > INFINITY)
                goto error;
            filter->action.table = table;
        } else {
            goto error;
        }
        free(token);
    }
    if(filter->af == 0) {
        if(filter->plen_le < 128 || filter->plen_ge > 0 ||
           filter->src_plen_le < 128 || filter->src_plen_ge > 0)
            filter->af = AF_INET6;
    } else if(filter->af == AF_INET) {
        filter->plen_le += 96;
        filter->plen_ge += 96;
    }
    *filter_return = filter;
    return c;

 error:
    free(filter);
    return -2;
}

static int
parse_anonymous_ifconf(int c, gnc_t gnc, void *closure,
                       struct interface_conf *if_conf,
                       struct interface_conf **if_conf_return)
{

    char *token;

    if(if_conf == NULL) {
        if_conf = calloc(1, sizeof(struct interface_conf));
        if(if_conf == NULL)
            goto error;
    }

    while(1) {
        c = skip_whitespace(c, gnc, closure);
        if(c < 0 || c == '\n' || c == '#') {
            c = skip_to_eol(c, gnc, closure);
            break;
        }
        c = getword(c, &token, gnc, closure);
        if(c < -1)
            goto error;

        if(strcmp(token, "rxcost") == 0) {
            int cost;
            c = getint(c, &cost, gnc, closure);
            if(c < -1 || cost <= 0 || cost > 0xFFFF)
                goto error;
            if_conf->cost = cost;
        } else if(strcmp(token, "hello-interval") == 0) {
            int interval;
            c = getthousands(c, &interval, gnc, closure);
            if(c < -1 || interval <= 0 || interval > 10 * 0xFFFF)
                goto error;
            if_conf->hello_interval = interval;
        } else if(strcmp(token, "update-interval") == 0) {
            int interval;
            c = getthousands(c, &interval, gnc, closure);
            if(c < -1 || interval <= 0 || interval > 10 * 0xFFFF)
                goto error;
            if_conf->update_interval = interval;
        } else if(strcmp(token, "wired") == 0) {
            int v;
            c = getbool(c, &v, gnc, closure);
            if(c < -1)
                goto error;
            if_conf->wired = v;
        } else if(strcmp(token, "faraway") == 0) {
            int v;
            c = getbool(c, &v, gnc, closure);
            if(c < -1)
                goto error;
            if_conf->faraway = v;
        } else if(strcmp(token, "link-quality") == 0) {
            int v;
            c = getbool(c, &v, gnc, closure);
            if(c < -1)
                goto error;
            if_conf->lq = v;
        } else if(strcmp(token, "split-horizon") == 0) {
            int v;
            c = getbool(c, &v, gnc, closure);
            if(c < -1)
                goto error;
            if_conf->split_horizon = v;
        } else if(strcmp(token, "channel") == 0) {
            char *t, *end;

            c = getword(c, &t, gnc, closure);
            if(c < -1)
                goto error;

            if(strcmp(t, "noninterfering") == 0)
                if_conf->channel = IF_CHANNEL_NONINTERFERING;
            else if(strcmp(t, "interfering") == 0)
                if_conf->channel = IF_CHANNEL_INTERFERING;
            else {
                if_conf->channel = strtol(t, &end, 0);
                if(*end != '\0')
                    goto error;
            }

            free(t);

            if((if_conf->channel < 1 || if_conf->channel > 255) &&
               if_conf->channel != IF_CHANNEL_NONINTERFERING)
                goto error;
        } else if(strcmp(token, "enable-timestamps") == 0) {
            int v;
            c = getbool(c, &v, gnc, closure);
            if(c < -1)
                goto error;
            if_conf->enable_timestamps = v;
        } else if(strcmp(token, "rtt-decay") == 0) {
            int decay;
            c = getint(c, &decay, gnc, closure);
            if(c < -1 || decay <= 0 || decay > 256)
                goto error;
            if_conf->rtt_decay = decay;
        } else if(strcmp(token, "rtt-min") == 0) {
            int rtt;
            c = getthousands(c, &rtt, gnc, closure);
            if(c < -1 || rtt <= 0)
                goto error;
            if_conf->rtt_min = rtt;
        } else if(strcmp(token, "rtt-max") == 0) {
            int rtt;
            c = getthousands(c, &rtt, gnc, closure);
            if(c < -1 || rtt <= 0)
                goto error;
            if_conf->rtt_max = rtt;
        } else if(strcmp(token, "max-rtt-penalty") == 0) {
            int cost;
            c = getint(c, &cost, gnc, closure);
            if(c < -1 || cost <= 0 || cost > 0xFFFF)
                goto error;
            if_conf->max_rtt_penalty = cost;
        } else {
            goto error;
        }
        free(token);
    }

    *if_conf_return = if_conf;
    return c;

 error:
    free(if_conf);
    return -2;
}

static int
parse_ifconf(int c, gnc_t gnc, void *closure,
             struct interface_conf **if_conf_return)
{
    char *token;
    struct interface_conf *if_conf;

    if_conf = calloc(1, sizeof(struct interface_conf));
    if(if_conf == NULL)
        goto error;

    c = skip_whitespace(c, gnc, closure);
    if(c < -1 || c == '\n' || c == '#')
        goto error;

    c = getstring(c, &token, gnc, closure);
    if(c < -1 || token == NULL)
        goto error;

    if_conf->ifname = token;

    return parse_anonymous_ifconf(c, gnc, closure, if_conf, if_conf_return);

 error:
    free(if_conf);
    return -2;
}

static void
add_filter(struct filter *filter, struct filter **filters)
{
    if(*filters == NULL) {
        filter->next = NULL;
        *filters = filter;
    } else {
        struct filter *f;
        f = *filters;
        while(f->next)
            f = f->next;
        filter->next = NULL;
        f->next = filter;
    }
}

static void
merge_ifconf(struct interface_conf *dest,
             const struct interface_conf *src1,
             const struct interface_conf *src2)
{

#define MERGE(field)                            \
    do {                                        \
        if(src1->field)                         \
            dest->field = src1->field;          \
        else                                    \
            dest->field = src2->field;          \
    } while(0)

    MERGE(hello_interval);
    MERGE(update_interval);
    MERGE(cost);
    MERGE(wired);
    MERGE(split_horizon);
    MERGE(lq);
    MERGE(faraway);
    MERGE(channel);
    MERGE(enable_timestamps);
    MERGE(rtt_decay);
    MERGE(rtt_min);
    MERGE(rtt_max);
    MERGE(max_rtt_penalty);

#undef MERGE
}

static void
add_ifconf(struct interface_conf *if_conf, struct interface_conf **if_confs)
{
    if(*if_confs == NULL) {
        if_conf->next = NULL;
        *if_confs = if_conf;
    } else {
        struct interface_conf *prev, *next;
        next = *if_confs;
        prev = NULL;
        while(next) {
            if(strcmp(next->ifname, if_conf->ifname) == 0) {
                merge_ifconf(next, if_conf, next);
                free(if_conf);
                return;
            }
            prev = next;
            next = next->next;
        }
        if_conf->next = NULL;
        prev->next = if_conf;
    }
}

static int
parse_option(int c, gnc_t gnc, void *closure, char *token)
{
    if(strcmp(token, "protocol-port") == 0 ||
       strcmp(token, "kernel-priority") == 0 ||
       strcmp(token, "allow-duplicates") == 0 ||
#ifndef NO_LOCAL_INTERFACE
       strcmp(token, "local-port") == 0 ||
#endif
       strcmp(token, "export-table") == 0 ||
       strcmp(token, "import-table") == 0) {
        int v;
        c = getint(c, &v, gnc, closure);
        if(c < -1 || v <= 0 || v >= 0xFFFF)
            goto error;

        if(strcmp(token, "protocol-port") == 0)
            protocol_port = v;
        else if(strcmp(token, "kernel-priority") == 0)
            kernel_metric = v;
        else if(strcmp(token, "allow_duplicates") == 0)
            allow_duplicates = v;
#ifndef NO_LOCAL_INTERFACE
        else if(strcmp(token, "local-port") == 0)
            local_server_port = v;
#endif
        else if(strcmp(token, "export-table") == 0)
            export_table = v;
        else if(strcmp(token, "import-table") == 0)
            add_import_table(v);
        else
            abort();
    } else if(strcmp(token, "keep-unfeasible") == 0 ||
              strcmp(token, "link-detect") == 0 ||
              strcmp(token, "random-id") == 0 ||
              strcmp(token, "daemonise") == 0 ||
              strcmp(token, "skip-kernel-setup") == 0 ||
              strcmp(token, "ipv6-subtrees") == 0 ||
              strcmp(token, "reflect-kernel-metric") == 0) {
        int b;
        c = getbool(c, &b, gnc, closure);
        if(c < -1)
            goto error;
        b = (b == CONFIG_YES);
        if(strcmp(token, "keep-unfeasible") == 0)
            keep_unfeasible = b;
        else if(strcmp(token, "link-detect") == 0)
            link_detect = b;
        else if(strcmp(token, "random-id") == 0)
            random_id = b;
        else if(strcmp(token, "daemonise") == 0)
            do_daemonise = b;
        else if(strcmp(token, "skip-kernel-setup") == 0)
            skip_kernel_setup = b;
        else if(strcmp(token, "ipv6-subtrees") == 0)
            has_ipv6_subtrees = b;
        else if(strcmp(token, "reflect-kernel-metric") == 0)
            reflect_kernel_metric = b;
        else
            abort();
    } else if(strcmp(token, "protocol-group") == 0) {
        unsigned char *group = NULL;
        c = getip(c, &group, NULL, gnc, closure);
        if(c < -1)
            goto error;
        memcpy(protocol_group, group, 16);
        free(group);
    } else if(strcmp(token, "state-file") == 0 ||
              strcmp(token, "log-file") == 0 ||
              strcmp(token, "pid-file") == 0) {
        char *file;
        c = getstring(c, &file, gnc, closure);
        if(c < -1)
            goto error;
        if(strcmp(token, "state-file") == 0)
            state_file = file;
        else if(strcmp(token, "log-file") == 0)
            logfile = file;
        else if(strcmp(token, "pid-file") == 0)
            pidfile = file;
        else
            abort();
    } else if(strcmp(token, "debug") == 0) {
        int d;
        c = getint(c, &d, gnc, closure);
        if(c < -1 || d < 0)
            goto error;
        debug = d;
    } else if(strcmp(token, "diversity") == 0) {
        int d;
        c = skip_whitespace(c, gnc, closure);
        if(c >= '0' && c <= '9') {
            c = getint(c, &d, gnc, closure);
            if(c < -1)
                goto error;
        } else {
            int b;
            c = getbool(c, &b, gnc, closure);
            if(c < -1)
                goto error;
            d = (b == CONFIG_YES) ? 3 : 0;
        }
        diversity_kind = d;
    } else if(strcmp(token, "diversity-factor") == 0) {
        int f;
        c = getint(c, &f, gnc, closure);
        if(c < -1 || f < 0 || f > 256)
            goto error;
        diversity_factor = f;
    } else if(strcmp(token, "smoothing-half-life") == 0) {
        int h;
        c = getint(c, &h, gnc, closure);
        if(c < -1 || h < 0)
            goto error;
        change_smoothing_half_life(h);
    } else if(strcmp(token, "first-table-number") == 0) {
        int n;
        c = getint(c, &n, gnc, closure);
        if(c < -1 || n <= 0 || n + SRC_TABLE_NUM >= 254)
            goto error;
        src_table_idx = n;
    } else if(strcmp(token, "first-rule-priority") == 0) {
        int n;
        c = getint(c, &n, gnc, closure);
        if(c < -1 || n <= 0 || n + SRC_TABLE_NUM >= 32765)
            goto error;
        src_table_prio = n;
    } else if(strcmp(token, "router-id") == 0) {
        unsigned char *id = NULL;
        c = getid(c, &id, gnc, closure);
        if(c < -1 || id == NULL)
            goto error;
        memcpy(myid, id, 8);
        free(id);
        have_id = 1;
    } else {
        goto error;
    }

    c = skip_whitespace(c, gnc, closure);
    if(c < 0 || c == '\n' || c == '#') {
        c = skip_to_eol(c, gnc, closure);
        return c;
    }

    /* Fall through */
 error:
    return -2;

}

static int
parse_config_line(int c, gnc_t gnc, void *closure)
{
    char *token;

    c = skip_whitespace(c, gnc, closure);
    if(c == '\n' || c == '#')
        return skip_to_eol(c, gnc, closure);

    c = getword(c, &token, gnc, closure);
    if(c < -1)
        return c;

    if(strcmp(token, "in") == 0) {
        struct filter *filter;
        c = parse_filter(c, gnc, closure, &filter);
        if(c < -1)
            return -1;
        add_filter(filter, &input_filters);
    } else if(strcmp(token, "out") == 0) {
        struct filter *filter;
        c = parse_filter(c, gnc, closure, &filter);
        if(c < -1)
            return -1;
        add_filter(filter, &output_filters);
    } else if(strcmp(token, "redistribute") == 0) {
        struct filter *filter;
        c = parse_filter(c, gnc, closure, &filter);
        if(c < -1)
            return -1;
        add_filter(filter, &redistribute_filters);
    } else if(strcmp(token, "install") == 0) {
        struct filter *filter;
        c = parse_filter(c, gnc, closure, &filter);
        if(c < -1)
            return -1;
    } else if(strcmp(token, "interface") == 0) {
        struct interface_conf *if_conf;
        c = parse_ifconf(c, gnc, closure, &if_conf);
        if(c < -1)
            return -1;
        add_ifconf(if_conf, &interface_confs);
    } else if(strcmp(token, "default") == 0) {
        struct interface_conf *if_conf;
        c = parse_anonymous_ifconf(c, gnc, closure, NULL, &if_conf);
        if(c < -1)
            return -1;
        if(default_interface_conf == NULL)
            default_interface_conf = if_conf;
        else {
            merge_ifconf(default_interface_conf,
                         if_conf, default_interface_conf);
            free(if_conf);
        }
    } else {
        c = parse_option(c, gnc, closure, token);
        if(c < -1)
            return -1;
    }
    free(token);
    return c;
}

struct file_state {
    FILE *f;
    int line;
};

static int
gnc_file(struct file_state *s)
{
    int c;
    c = fgetc(s->f);
    if(c == '\n')
        s->line++;
    return c;
}

int
parse_config_from_file(const char *filename, int *line_return)
{
    struct file_state s = { NULL, 1 };
    int c;

    s.f = fopen(filename, "r");
    if(s.f == NULL) {
        *line_return = 0;
        return -1;
    }

    c = gnc_file(&s);
    if(c < 0)
        return 0;

    while(1) {
        c = parse_config_line(c, (gnc_t)gnc_file, &s);
        if(c < -1) {
            *line_return = s.line;
            return -1;
        }
        if(c == -1)
            break;
    }
    fclose(s.f);

    return 1;
}

struct buf_state {
    char *buf;
    int i, n;
};

static int
gnc_buf(struct buf_state *s)
{
    if(s->i < s->n)
        return s->buf[s->i++];
    else
        return -1;
}

int
parse_config_from_string(char *string, int n)
{
    int c;
    struct buf_state s = { string, 0, n };

    c = gnc_buf(&s);
    if(c < 0)
        return -1;

    c = parse_config_line(c, (gnc_t)gnc_buf, &s);
    if(c == -1)
        return 1;
    else
        return -1;
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
    renumber_filter(install_filters);
}

static int
filter_match(struct filter *f, const unsigned char *id,
             const unsigned char *prefix, unsigned short plen,
             const unsigned char *src_prefix, unsigned short src_plen,
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
    if(f->src_prefix) {
        if(!src_prefix || src_plen < f->src_plen ||
           !in_prefix(src_prefix, f->src_prefix, f->src_plen))
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
    if(f->src_plen_ge > 0 || f->src_plen_le < 128) {
        if(!src_prefix)
            return 0;
        if(src_plen > f->src_plen_le)
            return 0;
        if(src_plen < f->src_plen_ge)
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
#ifdef __linux
    } else if(proto == RTPROT_BOOT) {
        return 0;
#endif
    }

    return 1;
}

static int
do_filter(struct filter *f, const unsigned char *id,
          const unsigned char *prefix, unsigned short plen,
          const unsigned char *src_prefix, unsigned short src_plen,
          const unsigned char *neigh, unsigned int ifindex, int proto,
          struct filter_result *result)
{
    if(result)
        memset(result, 0, sizeof(struct filter_result));

    while(f) {
        if(filter_match(f, id, prefix, plen, src_prefix, src_plen,
                        neigh, ifindex, proto)) {
            if(result)
                memcpy(result, &f->action, sizeof(struct filter_result));
            return f->action.add_metric;
        }
        f = f->next;
    }

    return -1;
}

int
input_filter(const unsigned char *id,
             const unsigned char *prefix, unsigned short plen,
             const unsigned char *src_prefix, unsigned short src_plen,
             const unsigned char *neigh, unsigned int ifindex)
{
    int res;
    res = do_filter(input_filters, id, prefix, plen,
                    src_prefix, src_plen, neigh, ifindex, 0, NULL);
    if(res < 0)
        res = 0;
    return res;
}

int
output_filter(const unsigned char *id,
              const unsigned char *prefix, unsigned short plen,
              const unsigned char *src_prefix, unsigned short src_plen,
              unsigned int ifindex)
{
    int res;
    res = do_filter(output_filters, id, prefix, plen,
                    src_prefix, src_plen, NULL, ifindex, 0, NULL);
    if(res < 0)
        res = 0;
    return res;
}

int
redistribute_filter(const unsigned char *prefix, unsigned short plen,
                    const unsigned char *src_prefix, unsigned short src_plen,
                    unsigned int ifindex, int proto,
                    struct filter_result *result)
{
    int res;
    res = do_filter(redistribute_filters, NULL, prefix, plen,
                    src_prefix, src_plen, NULL, ifindex, proto, result);
    if(res < 0)
        res = INFINITY;
    return res;
}

int
install_filter(const unsigned char *prefix, unsigned short plen,
               const unsigned char *src_prefix, unsigned short src_plen,
               struct filter_result *result)
{
    int res;
    res = do_filter(install_filters, NULL, prefix, plen,
                    src_prefix, src_plen, NULL, 0, 0, result);
    if(res < 0)
        res = INFINITY;
    return res;
}

int
finalise_config()
{
    struct filter *filter = calloc(1, sizeof(struct filter));
    if(filter == NULL)
        return -1;

    filter->proto = RTPROT_BABEL_LOCAL;
    filter->plen_le = 128;
    filter->src_plen_le = 128;
    add_filter(filter, &redistribute_filters);

    while(interface_confs) {
        struct interface_conf *if_conf;
        void *vrc;
        if_conf = interface_confs;
        interface_confs = interface_confs->next;
        if_conf->next = NULL;
        if(default_interface_conf)
            merge_ifconf(if_conf, if_conf, default_interface_conf);
        vrc = add_interface(if_conf->ifname, if_conf);
        if(vrc == NULL) {
            fprintf(stderr, "Couldn't add interface %s.\n", if_conf->ifname);
            return -1;
        }
    }

    return 1;
}
