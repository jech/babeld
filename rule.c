/*
Copyright (c) 2015 by Matthieu Boutier and Juliusz Chroboczek.

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "babeld.h"
#include "util.h"
#include "kernel.h"
#include "configuration.h"
#include "rule.h"

int src_table_idx = 10;
int src_table_prio = 100;

/* The table used for non-specific routes is "export_table", therefore, we can
   take the convention of plen == 0 <=> empty table. */
struct rule {
    unsigned char src[16];
    unsigned char plen;
    unsigned char table;
};

/* rules contains informations about the rules we installed. It is an array
   indexed by: <table priority> - src_table_prio.
   (First entries are the most specific, since they have priority.) */
static struct rule rules[SRC_TABLE_NUM];
/* used tables is indexed by: <table number> - src_table_idx
   used_tables[i] == 1 <=> the table number (i + src_table_idx) is used */
static char used_tables[SRC_TABLE_NUM] = {0};

static int
get_free_table(void)
{
    int i;
    for(i = 0; i < SRC_TABLE_NUM; i++)
        if(!used_tables[i]) {
            used_tables[i] = 1;
            return i + src_table_idx;
        }
    return -1;
}

static void
release_table(int i)
{
    used_tables[i - src_table_idx] = 0;
}

static int
find_hole_around(int i)
{
    int j;
    for(j = i; j < SRC_TABLE_NUM; j++)
        if(rules[j].plen == 0)
            return j;
    for(j = i - 1; j >= 0; j--)
        if(rules[j].plen == 0)
            return j;
    return -1;
}

static int
shift_rule(int from, int to)
{
    int dec = (from < to) ? 1 /* right */ : -1 /* left */;
    int rc;
    while(to != from) {
        to -= dec;
        rc = change_rule(to + dec + src_table_prio, to + src_table_prio,
                         rules[to].src, rules[to].plen, rules[to].table);
        if(rc < 0) {
            perror("change_table_priority");
            return -1;
        }
        rules[to+dec] = rules[to];
        rules[to].plen = 0;
    }
    return 0;
}

/* Return a new table at index [idx] of rules.  If cell at that index is not
   free, we need to shift cells (and rules).  If it's full, return NULL. */
static struct rule *
insert_table(const unsigned char *src, unsigned short src_plen, int idx)
{
    int table;
    int rc;
    int hole;

    if(idx < 0 || idx >= SRC_TABLE_NUM) {
        fprintf(stderr, "Incorrect table number %d\n", idx);
        return NULL;
    }

    table = get_free_table();
    if(table < 0) {
        kdebugf("All allowed routing tables are used!\n");
        return NULL;
    }

    hole = find_hole_around(idx);
    if(hole < 0) {
        fprintf(stderr, "Have free table but not free rule.\n");
        goto fail;
    }
    rc = shift_rule(idx, hole);
    if(rc < 0)
        goto fail;

    rc = add_rule(idx + src_table_prio, src, src_plen, table);
    if(rc < 0) {
        perror("add rule");
        goto fail;
    }
    memcpy(rules[idx].src, src, 16);
    rules[idx].plen = src_plen;
    rules[idx].table = table;

    return &rules[idx];
 fail:
    release_table(table);
    return NULL;
}

/* Sorting rules in a well ordered fashion will increase code complexity and
   decrease performances, because more rule shifts will be required, so more
   system calls invoked. */
static int
find_table_slot(const unsigned char *src, unsigned short src_plen, int *found)
{
    struct rule *kr = NULL;
    int i;
    *found = 0;

    for(i = 0; i < SRC_TABLE_NUM; i++) {
        kr = &rules[i];
        if(kr->plen == 0)
            return i;
        switch(prefix_cmp(src, src_plen, kr->src, kr->plen)) {
        case PST_LESS_SPECIFIC:
        case PST_DISJOINT:
            continue;
        case PST_MORE_SPECIFIC:
            return i;
        case PST_EQUALS:
            *found = 1;
            return i;
        }
    }

    return -1;
}

int
find_table(const unsigned char *dest, unsigned short plen,
           const unsigned char *src, unsigned short src_plen)
{
    struct filter_result filter_result = {0};
    struct rule *kr = NULL;
    int i, found;

    install_filter(dest, plen, src, src_plen, &filter_result);
    if(filter_result.table) {
        return filter_result.table;
    } else if(src_plen == 0) {
        return export_table;
    } else if(kernel_disambiguate(v4mapped(dest))) {
        return export_table;
    }

    i = find_table_slot(src, src_plen, &found);
    if(found)
        return rules[i].table;
    if(i < 0)
        return -1;
    kr = insert_table(src, src_plen, i);
    return kr == NULL ? -1 : kr->table;
}

void
release_tables(void)
{
    int i;
    for(i = 0; i < SRC_TABLE_NUM; i++) {
        if(rules[i].plen != 0) {
            flush_rule(i + src_table_prio,
                       v4mapped(rules[i].src) ? AF_INET : AF_INET6);
            rules[i].plen = 0;
        }
        used_tables[i] = 0;
    }
}

static int
filter_rule(struct kernel_rule *rule, void *data)
{
    int i;
    char (*rule_exists)[2][SRC_TABLE_NUM] = data;
    int is_v4 = v4mapped(rule->src);
    int r = is_v4 ? 0 : 1;

    if(martian_prefix(rule->src, rule->src_plen))
        return 0;

    i = rule->priority - src_table_prio;

    if(i < 0 || SRC_TABLE_NUM <= i)
        return 0;

    if(prefix_cmp(rule->src, rule->src_plen,
                  rules[i].src, rules[i].plen) == PST_EQUALS &&
       rule->table == rules[i].table &&
       (*rule_exists)[r][i] == 0)
        (*rule_exists)[r][i] = 1;
    else
        (*rule_exists)[r][i] = -1;

    return 1;
}

/* This functions should be executed wrt the code just bellow: [rule_exists]
   contains is a boolean array telling whether the rules we should have
   installed in the kernel are installed or not.  If they aren't, then reinstall
   them (this can append when rules are modified by third parties). */

static void
install_missing_rules(char rule_exists[SRC_TABLE_NUM], int v4)
{
    int i, rc;
    for(i = 0; i < SRC_TABLE_NUM; i++) {
        int priority = i + src_table_prio;
        if(rule_exists[i] == 1)
            continue;

        if(rule_exists[i] != 0) {
            int rc;
            do {
                rc = flush_rule(priority, v4 ? AF_INET : AF_INET6);
            } while(rc >= 0);
            if(errno != ENOENT && errno != EEXIST)
                fprintf(stderr,
                        "Cannot remove rule %d: from %s table %d (%s)\n",
                        priority,
                        format_prefix(rules[i].src, rules[i].plen),
                        rules[i].table, strerror(errno));
        }

        /* Be wise, our priority are both for v4 and v6 (does not overlap). */
        if(!!v4mapped(rules[i].src) == !!v4 && rules[i].plen != 0) {
            rc = add_rule(priority, rules[i].src,
                          rules[i].plen, rules[i].table);
            if(rc < 0)
                fprintf(stderr,
                        "Cannot install rule %d: from %s table %d (%s)\n",
                        priority,
                        format_prefix(rules[i].src, rules[i].plen),
                        rules[i].table, strerror(errno));
        }
    }
}

int
check_rules(void)
{
    int rc;
    char rule_exists[2][SRC_TABLE_NUM]; /* v4, v6 */
    struct kernel_filter filter = {0};
    filter.rule = filter_rule;
    filter.rule_closure = (void*) rule_exists;
    memset(rule_exists, 0, sizeof(rule_exists));

    rc = kernel_dump(CHANGE_RULE, &filter);
    if(rc < 0)
        return -1;
    install_missing_rules(rule_exists[0], 1);
    install_missing_rules(rule_exists[1], 0);

    return 0;
}
