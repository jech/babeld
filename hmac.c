/*
Copyright (c) 2018 by Clara Dô and Weronika Kolodziejak

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
#include <netinet/in.h>

#include "rfc6234/sha.h"
#include "BLAKE2/ref/blake2.h"

#include "babeld.h"
#include "interface.h"
#include "neighbour.h"
#include "util.h"
#include "hmac.h"
#include "configuration.h"
#include "message.h"

struct key **keys = NULL;
int numkeys = 0, maxkeys = 0;

struct key *
find_key(const char *id)
{
    int i;
    for(i = 0; i < numkeys; i++) {
        if(strcmp(keys[i]->id, id) == 0)
            return retain_key(keys[i]);
    }
    return NULL;
}

struct key *
retain_key(struct key *key)
{
    assert(key->ref_count < 0xffff);
    key->ref_count++;
    return key;
}

void
release_key(struct key *key)
{
    assert(key->ref_count > 0);
    key->ref_count--;
}

struct key *
add_key(char *id, int type, int len, unsigned char *value)
{
    struct key *key;

    assert(value != NULL && type != 0);

    key = find_key(id);
    if(key) {
        key->type = type;
        key->len = len;
        key->value = value;
        return key;
    }

    if(type == AUTH_TYPE_NONE)
        return NULL;
    if(numkeys >= maxkeys) {
        struct key **new_keys;
        int n = maxkeys < 1 ? 8 : 2 * maxkeys;
        new_keys = realloc(keys, n * sizeof(struct key*));
        if(new_keys == NULL)
            return NULL;
        maxkeys = n;
        keys = new_keys;
    }

    key = calloc(1, sizeof(struct key));
    if(key == NULL)
        return NULL;
    key->id = id;
    key->type = type;
    key->len = len;
    key->value = value;

    keys[numkeys++] = key;
    return key;
}

static int
compute_hmac(const unsigned char *src, const unsigned char *dst,
	     const unsigned char *packet_header,
             const unsigned char *body, int bodylen, struct key *key,
             unsigned char *hmac_return)
{
    unsigned char port[2];
    int rc;

    DO_HTONS(port, (unsigned short)protocol_port);
    switch(key->type) {
    case AUTH_TYPE_SHA256: {
        SHA256Context inner, outer;
        unsigned char ipad[64], ihash[32], opad[64];
        if(key->len != 32)
            return -1;
        for(int i = 0; i < 32; i++)
            ipad[i] = key->value[i] ^ 0x36;
        for(int i = 32; i < 64; i++)
            ipad[i] = 0x36;
        rc = SHA256Reset(&inner);
        if(rc < 0)
            return -1;
        rc = SHA256Input(&inner, ipad, 64);
        if(rc < 0)
            return -1;

        rc = SHA256Input(&inner, src, 16);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, port, 2);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, dst, 16);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, port, 2);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, packet_header, 4);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&inner, body, bodylen);
        if(rc != 0)
            return -1;

        rc = SHA256Result(&inner, ihash);
        if(rc != 0)
            return -1;

        for(int i = 0; i < 32; i++)
            opad[i] = ihash[i] ^ 0x5c;
        for(int i = 32; i < 64; i++)
            opad[i] = 0x5c;

        rc = SHA256Reset(&outer);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&outer, opad, 64);
        if(rc != 0)
            return -1;
        rc = SHA256Input(&outer, ihash, 32);
        if(rc != 0)
            return -1;
        rc = SHA256Result(&outer, hmac_return);
        if(rc < 0)
            return -1;
	return 32;
    }
    case AUTH_TYPE_BLAKE2S: {
        blake2s_state s;
        if(key->len != 16)
            return -1;
        rc = blake2s_init_key(&s, 16, key->value, key->len);
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
        rc = blake2s_final(&s, hmac_return, 16);
        if(rc < 0)
            return -1;

	return 16;
    }
    default:
        return -1;
    }
}

int
add_hmac(struct buffered *buf, struct interface *ifp,
         unsigned char *packet_header)
{
    int hmaclen;
    int i = buf->len;
    unsigned char *dst = buf->sin6.sin6_addr.s6_addr;
    unsigned char *src;

    if(ifp->numll < 1) {
        fprintf(stderr, "add_hmac: no link-local address.\n");
        return -1;
    }
    src = ifp->ll[0];

    if(buf->len + 2 + DIGEST_LEN > buf->size) {
        fprintf(stderr, "Buffer overflow in add_hmac.\n");
        return -1;
    }

    hmaclen = compute_hmac(src, dst, packet_header,
                           buf->buf, buf->len, ifp->key,
                           buf->buf + i + 2);
    if(hmaclen < 0)
        return -1;
    buf->buf[i++] = MESSAGE_HMAC;
    buf->buf[i++] = hmaclen;
    i += hmaclen;
    return i;
}


static int
compare_hmac(const unsigned char *src, const unsigned char *dst,
	     const unsigned char *packet, int bodylen,
	     const unsigned char *hmac, int hmaclen)
{
    unsigned char true_hmac[DIGEST_LEN];
    int true_hmaclen;
    int i;
    for(i = 0; i < numkeys; i++) {
	true_hmaclen = compute_hmac(src, dst, packet,
				    packet + 4, bodylen, keys[i],
                                    true_hmac);
	if(true_hmaclen != hmaclen) {
            debugf("Bad hmac length (%d != %d).\n", true_hmaclen, hmaclen);
	    return -1;
	}
	if(memcmp(true_hmac, hmac, hmaclen) == 0)
            return 1;
    }
    return 0;
}

int
check_hmac(const unsigned char *packet, int packetlen, int bodylen,
	   const unsigned char *src, const unsigned char *dst)
{
    int i = bodylen + 4;
    int len;

    debugf("check_hmac %s -> %s\n",
	   format_address(src), format_address(dst));
    while(i < packetlen) {
	if(i + 1 > packetlen) {
            fprintf(stderr, "Received truncated message.\n");
            break;
        }
        len = packet[i+1];
        if(packet[i] == MESSAGE_HMAC) {
	    if(i + len > packetlen) {
	        fprintf(stderr, "Received truncated message.\n");
		return -1;
	    }
	    if(compare_hmac(src, dst, packet, bodylen,
			    packet + i + 2 , len) == 1) {
		return 1;
	    }
	}
	i += len + 2;
    }
    return 0;
}
