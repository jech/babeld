/*
Copyright (c) 2018 by Clara Dô and Weronika Kolodziejak
Copyright (c) 2019-2020 by Antonin Décimo

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
#include <assert.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "rfc6234/sha.h"
#include "BLAKE2/ref/blake2.h"

#include "babeld.h"
#include "mac.h"
#include "interface.h"
#include "neighbour.h"
#include "util.h"
#include "configuration.h"
#include "message.h"
#include "local.h"

#define MAX_DIGEST_LEN MAX((int)SHA256HashSize, (int)BLAKE2S_OUTBYTES)

struct keysuperset allkeysets = {0};
struct keyset allkeys = {0};

struct mac {
    unsigned int len;
    unsigned char digest[MAX_DIGEST_LEN];
};

static struct mac *macs = NULL;
static unsigned int macslen = 0;

int
init_keysuperset(struct keysuperset *kss)
{
    kss->cap = 1;
    kss->len = 0;
    kss->keysets = calloc(kss->cap, sizeof(struct keyset*));
    if(kss->keysets == NULL) {
        perror("calloc(keysets)");
        if(kss != &allkeysets)
            free(kss);
        return -1;
    }
    return 0;
}

static struct keyset *
init_keyset(struct keyset *ks, const char *name)
{
    int alloc = ks == NULL;

    if(alloc) {
        ks = calloc(1, sizeof(struct keyset));
        if(ks == NULL) {
            perror("calloc(keyset)");
            return NULL;
        }
    }

    if(name != NULL) {
        strncpy(ks->name, name, MAX_KEY_NAME_LEN - 1);
        ks->name[MAX_KEY_NAME_LEN - 1] = '\0';
    }

    ks->cap = 4;
    ks->refcount = -1;
    ks->keys = calloc(ks->cap, sizeof(struct key*));
    if(ks->keys == NULL) {
        perror("calloc(keys)");
        if(alloc)
            free(ks);
        return NULL;
    }
    return ks;
}

int
init_mac(void)
{
    struct keyset *ks;
    int rc;

    rc = init_keysuperset(&allkeysets);
    if(rc)
        goto fail1;
    ks = init_keyset(&allkeys, NULL);
    if(ks == NULL)
        goto fail2;
    return 0;

 fail2:
    free(allkeysets.keysets);
    memset(&allkeys, 0, sizeof(struct keyset));
 fail1:
    memset(&allkeysets, 0, sizeof(struct keysuperset));
    return -1;

}

static void
retain_key(struct key *key)
{
    if(key->refcount == -1)
        key->refcount = 0;
    ++key->refcount;
}

static void
retain_keyset(struct keyset *ks)
{
    if(ks->refcount == -1)
        ks->refcount = 0;
    ++ks->refcount;
}

static void
pop_keyset(struct keysuperset *kss, const unsigned int i)
{
    kss->keysets[i] = kss->keysets[--kss->len];
}

static void
pop_key(struct keyset *ks, const unsigned int i)
{
    ks->keys[i] = ks->keys[--ks->len];
}

static void
release_key(struct key *key)
{
    unsigned int i;

    --key->refcount;
    if(key->refcount > 0)
        return;

    for(i = 0; allkeys.keys[i] != key; i++);
    local_notify_key(key, LOCAL_FLUSH);
    pop_key(&allkeys, i);
    memzero(key->value, key->len);
    free(key);
}

static void
release_keyset(struct keyset *ks)
{
    unsigned int i;

    --ks->refcount;
    if(ks->refcount > 0)
        return;

    for(i = 0; i < ks->len; i++)
        release_key(ks->keys[i]);
    for(i = 0; allkeysets.keysets[i] != ks; i++);
    local_notify_keyset(ks, LOCAL_FLUSH);
    pop_keyset(&allkeysets, i);
    free(ks->keys);
    free(ks);
}

void
release_keysuperset(struct keysuperset *kss)
{
    unsigned int i;
    for(i = 0; i < kss->len; i++)
        release_keyset(kss->keysets[i]);
    free(kss->keysets);
    kss->keysets = NULL;
}

void
release_mac(void)
{
    unsigned int i;
    release_keysuperset(&allkeysets);
    for(i = 0; i < allkeys.len; i++)
        release_key(*allkeys.keys + i);
    free(allkeys.keys);
    free(macs);

    memset(&allkeysets, 0, sizeof(struct keysuperset));
    memset(&allkeys, 0, sizeof(struct keyset));
    macs = NULL;
    macslen = 0;
}

static struct keyset *
find_keyset(const struct keysuperset *kss, const char *name, unsigned int *pos)
{
    unsigned int i;
    for(i = 0; i < kss->len; i++) {
        if(strcmp(name, kss->keysets[i]->name) == 0) {
            if(pos != NULL)
                *pos = i;
            return kss->keysets[i];
        }
    }
    return NULL;
}

static int
contains_keyset(const struct keysuperset *kss, const struct keyset *ks)
{
    unsigned int i;
    for(i = 0; i < kss->len; i++)
        if(kss->keysets[i] == ks)
            return 1;
    return 0;
}

static struct key *
find_key(const struct keyset *ks, const char *name, unsigned int *pos)
{
    unsigned int i;
    for(i = 0; i < ks->len; i++) {
        if(strcmp(name, ks->keys[i]->name) == 0) {
            if(pos != NULL)
                *pos = i;
            return ks->keys[i];
        }
    }
    return NULL;
}

static int
contains_key(const struct keyset *ks, const struct key *key)
{
    unsigned int i;
    for(i = 0; i < ks->len; i++)
        if(ks->keys[i] == key)
            return 1;
    return 0;
}

static int
push_keyset(struct keysuperset *kss, struct keyset *ks)
{
    if(kss->len == kss->cap) {
        unsigned int cap = 2 * kss->cap;
        struct keyset **keysets;
        if(cap == 0)
            return -1;
        keysets = realloc(kss->keysets, cap * sizeof(struct keyset*));
        if(keysets == NULL) {
            perror("realloc(kss->keysets)");
            return -1;
        }
        kss->keysets = keysets;
        kss->cap = cap;
    }
    kss->keysets[kss->len++] = ks;
    return 0;
}

static int
push_key(struct keyset *ks, struct key *key)
{
    if(ks->len == ks->cap) {
        unsigned int cap = 2 * ks->cap;
        struct key **keys;
        if(cap == 0)
            return -1;
        keys = realloc(ks->keys, cap * sizeof(struct key*));
        if(keys == NULL) {
            perror("realloc(ks->keys)");
            return -1;
        }
        ks->keys = keys;
        ks->cap = cap;
    }
    ks->keys[ks->len++] = key;
    return 0;
}

int
add_key(struct key *key)
{
    const struct key *key2;
    int rc;

    key2 = find_key(&allkeys, key->name, NULL);
    if(key2 != NULL) {
        fprintf(stderr, "add_key: key %s already exists.\n", key->name);
        return -1;
    }
    key->refcount = -1;

    if(macslen < allkeys.len + 1) {
        struct mac *buf;
        buf = realloc(macs, (allkeys.len + 1) * sizeof(struct mac));
        if(buf == NULL) {
            perror("realloc(macs)");
            return -1;
        }
        /* memset(buf + macslen, 0, (allkeys.len + 1 - macslen) * sizeof(struct mac)); */
        macs = buf;
        macslen = allkeys.len + 1;
    }

    rc = push_key(&allkeys, key);
    if(rc)
        return rc;
    local_notify_key(key, LOCAL_ADD);
    return 0;
}

int
add_keyset(const char *name)
{
    struct keyset *ks;
    int rc;

    ks = find_keyset(&allkeysets, name, NULL);
    if(ks != NULL) {
        fprintf(stderr, "add_keyset: keyset %s already exists.\n", name);
        return -1;
    }
    ks = init_keyset(NULL, name);
    if(ks == NULL)
        return -1;

    rc = push_keyset(&allkeysets, ks);
    if(rc) {
        free(ks->keys);
        free(ks);
        return -1;
    }

    local_notify_keyset(ks, LOCAL_ADD);
    return 0;
}

int
add_key_to_keyset(const char *keyset_name, const char *key_name)
{
    struct keyset *ks;
    struct key *key;
    int rc;
    ks = find_keyset(&allkeysets, keyset_name, NULL);
    if(ks == NULL) {
        fprintf(stderr, "add_key_to_keyset: could not find keyset %s.\n",
                keyset_name);
        return -1;
    }
    key = find_key(&allkeys, key_name, NULL);
    if(key == NULL) {
        fprintf(stderr, "add_key_to_keyset: could not find key %s.\n",
                key_name);
        return -1;
    }
    if(contains_key(ks, key)) {
        fprintf(stderr, "add_key_to_keyset: key %s already in keyset %s.\n",
                key_name, keyset_name);
        return -1;
    }

    rc = push_key(ks, key);
    if(rc)
        return -1;
    if(key->use & KEY_USE_SIGN)
        ++ks->signing;
    retain_key(key);
    local_notify_keyset(ks, LOCAL_CHANGE);
    return 0;
}

int
rm_key_from_keyset(const char *keyset_name, const char *key_name)
{
    unsigned int i;
    struct keyset *ks;
    struct key *key;
    ks = find_keyset(&allkeysets, keyset_name, NULL);
    if(ks == NULL) {
        fprintf(stderr, "rm_key_from_keyset: could not find keyset %s.\n",
                keyset_name);
        return -1;
    }
    key = find_key(ks, key_name, &i);
    if(key == NULL) {
        fprintf(stderr, "rm_key_from_keyset: could not find key %s in keyset %s.\n",
                key_name, keyset_name);
        return -1;
    }

    pop_key(ks, i);
    if(key->use & KEY_USE_SIGN)
        --ks->signing;
    release_key(key);
    local_notify_keyset(ks, LOCAL_CHANGE);
    return 0;
}

int
merge_keysupersets(struct keysuperset *dst, const struct keysuperset *src)
{
    unsigned int i;
    int rc;
    for(i = 0; i < src->len; i++) {
        struct keyset *ks = src->keysets[i];
        if(contains_keyset(dst, ks))
            continue;
        rc = push_keyset(dst, ks);
        if(rc)
            return -1;
        retain_keyset(ks);
    }
    return 0;
}

int
add_keyset_to_keysuperset(struct keysuperset *kss, const char *keyset_name)
{
    struct keyset *ks;
    int rc;
    if(find_keyset(kss, keyset_name, NULL) != NULL) {
        fprintf(stderr, "add_keyset_to_keysuperset: keyset %s already in keysuperset.\n",
                keyset_name);
        return -1;
    }
    ks = find_keyset(&allkeysets, keyset_name, NULL);
    if(ks == NULL) {
        fprintf(stderr, "add_keyset_to_keysuperset: could not find keyset %s.\n",
                keyset_name);
        return -1;
    }

    rc = push_keyset(kss, ks);
    if(rc)
        return -1;
    retain_keyset(ks);
    local_notify_keysuperset(kss, LOCAL_CHANGE);
    return 0;
}

int
rm_keyset_from_keysuperset(struct keysuperset *kss, const char *keyset_name)
{
    unsigned int i;
    struct keyset *ks;
    ks = find_keyset(kss, keyset_name, &i);
    if(ks == NULL) {
        fprintf(stderr, "rm_keyset_to_interface: "
                "could not find keyset %s.\n", keyset_name);
        return -1;
    }

    pop_keyset(kss, i);
    release_keyset(ks);
    local_notify_keysuperset(kss, LOCAL_CHANGE);
    return 0;
}

static int
compute_mac(const unsigned char *src, const unsigned char *dst,
            const unsigned char *packet_header,
            const unsigned char *body, int bodylen, const struct key *key,
            unsigned char *mac_return)
{
    unsigned char port[2];
    int rc;

    DO_HTONS(port, (unsigned short)protocol_port);
    switch(key->algorithm) {
    case MAC_ALGORITHM_HMAC_SHA256: {
        /* Reference hmac-sha functions weigth up babeld by 32Kb-36Kb,
         * so we roll our own! */
        unsigned char pad[SHA256_Message_Block_Size], ihash[SHA256HashSize];
        SHA256Context c;
        int i;

        for(i = 0; i < key->len; i++)
            pad[i] = key->value[i] ^ 0x36;
        for(; i < (int)sizeof(pad); i++)
            pad[i] = 0x36;

        rc = SHA256Reset(&c);
        if(rc < 0)
            return -1;

        rc = SHA256Input(&c, pad, sizeof(pad));
        if(rc < 0)
            return -1;
        rc = SHA256Input(&c, src, 16);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&c, port, 2);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&c, dst, 16);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&c, port, 2);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&c, packet_header, 4);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&c, body, bodylen);
        if(rc != 0)
            return -1;
        rc = SHA256Result(&c, ihash);
        if(rc != 0)
            return -1;

        for(i = 0; i < key->len; i++)
            pad[i] = key->value[i] ^ 0x5c;
        for(; i < (int)sizeof(pad); i++)
            pad[i] = 0x5c;

        rc = SHA256Reset(&c);
        if(rc != 0)
            return -1;

        rc = SHA256Input(&c, pad, sizeof(pad));
        if(rc != 0)
            return -1;
        rc = SHA256Input(&c, ihash, sizeof(ihash));
        if(rc != 0)
            return -1;
        rc = SHA256Result(&c, mac_return);
        if(rc < 0)
            return -1;

        return SHA256HashSize;
    }
    case MAC_ALGORITHM_BLAKE2S: {
        blake2s_state s;
        rc = blake2s_init_key(&s, BLAKE2S_OUTBYTES, key->value, key->len);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, src, 16);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, port, 2);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, dst, 16);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, port, 2);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, packet_header, 4);
        if(rc < 0)
            return -1;
        rc = blake2s_update(&s, body, bodylen);
        if(rc < 0)
            return -1;
        rc = blake2s_final(&s, mac_return, BLAKE2S_OUTBYTES);
        if(rc < 0)
            return -1;

        return BLAKE2S_OUTBYTES;
    }
    default:
        return -1;
    }
}

int
max_mac_space(const struct interface *ifp)
{
    unsigned int numkeys = 0, i;
    for(i = 0; i < ifp->kss.len; i++)
        numkeys += ifp->kss.keysets[i]->signing;
    return numkeys * (2 + MAX_DIGEST_LEN);
}

int
sign_packet(struct buffered *buf, const struct interface *ifp,
            const unsigned char *packet_header)
{
    int maclen, bufi;
    unsigned int i, j;
    unsigned char *dst = buf->sin6.sin6_addr.s6_addr;
    unsigned char *src;

    if(ifp->numll < 1) {
        fprintf(stderr, "sign_packet: no link-local address.\n");
        return -1;
    }
    src = ifp->ll[0];

    if(buf->size - buf->len < max_mac_space(ifp)) {
        fprintf(stderr, "sign_packet: buffer overflow.\n");
        return -1;
    }

    bufi = buf->len;
    for(i = 0; i < ifp->kss.len; i++) {
        struct keyset *ks = ifp->kss.keysets[i];
        for(j = 0; j < ks->len; j++) {
            struct key *key = ks->keys[j];
            if(!(key->use & KEY_USE_SIGN))
               continue;

            maclen = compute_mac(src, dst, packet_header, buf->buf, buf->len,
                                 key, buf->buf + bufi + 2);
            if(maclen < 0) {
                fprintf(stderr, "sign_packet: couldn't compute mac.\n");
                return -1;
            }
            buf->buf[bufi++] = MESSAGE_MAC;
            buf->buf[bufi++] = maclen;
            bufi += maclen;
        }
    }
    return bufi;
}

static int
compare_mac_keysuperset(const unsigned char *src, const unsigned char *dst,
                        const unsigned char *packet, unsigned int bodylen,
                        const unsigned char *mac, unsigned int maclen,
                        const struct keysuperset *kss,
                        int *memoized)
{
    unsigned int i, j;
    int k = 0;

    for(i = 0; i < kss->len; i++) {
        struct keyset *ks = kss->keysets[i];
        for(j = 0; j < ks->len; j++) {
            struct key *key = ks->keys[j];
            struct mac *mmac;
            if(!(key->use & KEY_USE_VERIFY))
                continue;

            mmac = macs + k;
            if(k > *memoized) {
                mmac->len = compute_mac(src, dst, packet, packet + 4, bodylen,
                                        key, mmac->digest);
                *memoized = k;
            }
            if(mmac->len == maclen && memcmp(mmac->digest, mac, maclen) == 0)
                return 1;
            k++;
        }
    }
    return 0;
}

static int
compare_macs(const unsigned char *src, const unsigned char *dst,
             const unsigned char *packet, int bodylen,
             const unsigned char *mac, int maclen,
             const struct keysuperset *kss, int drop)
{
    static int memoized;
    if(drop)
        memoized = -1;

    return compare_mac_keysuperset(src, dst, packet, bodylen, mac, maclen,
                                   kss, &memoized);
}

int
verify_packet(const unsigned char *packet, unsigned int packetlen, int bodylen,
              const unsigned char *src, const unsigned char *dst,
              const struct interface *ifp)
{
    unsigned int i = bodylen + 4;
    int rc = -1;

    debugf("verify_packet %s -> %s\n",
           format_address(src), format_address(dst));
    while(i < packetlen) {
        unsigned int maclen;
        if(i + 2 > packetlen) {
            fprintf(stderr, "Received truncated message.\n");
            break;
        }
        maclen = packet[i + 1];
        if(packet[i] == MESSAGE_MAC) {
            int ok;
            if(i + maclen + 2 > packetlen) {
                fprintf(stderr, "Received truncated message.\n");
                return -1;
            }
            ok = compare_macs(src, dst, packet, bodylen, packet + i + 2, maclen,
                              &ifp->kss, rc);
            if(ok)
                return 1;
            rc = 0;
        }
        i += maclen + 2;
    }
    return rc;
}
