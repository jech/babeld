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

#include "rfc6234/sha.h"
#include "BLAKE2/ref/blake2.h"

#define MAC_ALGORITHM_HMAC_SHA256 1
#define MAC_ALGORITHM_BLAKE2S 2

#define KEY_USE_SIGN (1 << 0)
#define KEY_USE_VERIFY (1 << 1)

#define MAX_KEY_LEN MAX((int)SHA256HashSize, (int)BLAKE2S_KEYBYTES)
#define MAX_KEY_NAME_LEN 16U

struct key {
    char name[MAX_KEY_NAME_LEN];
    unsigned char value[MAX_KEY_LEN];
    int len;
    short refcount;
    unsigned char algorithm;
    unsigned char use;
};

struct keyset {
    char name[MAX_KEY_NAME_LEN];
    short refcount;
    unsigned int len, cap;
    unsigned int signing;
    struct key **keys;
};

struct keysuperset {
    unsigned int len, cap;
    struct keyset **keysets;
};

struct interface;
struct buffered;

extern struct keysuperset allkeysets;
extern struct keyset allkeys;

int init_mac(void);
void release_mac(void);

int init_keysuperset(struct keysuperset *kss);
void release_keysuperset(struct keysuperset *kss);

int add_key(struct key *key);

int add_key_to_keyset(const char *keyset_name, const char *key_name);
int rm_key_from_keyset(const char *keyset_name, const char *key_name);

int add_keyset_to_keysuperset(struct keysuperset *kss, const char *keyset_name);
int rm_keyset_from_keysuperset(struct keysuperset *kss, const char *keyset_name);

int merge_keysupersets(struct keysuperset *dst, const struct keysuperset *src);
int max_mac_space(const struct interface *ifp);

int sign_packet(struct buffered *buf, const struct interface *ifp,
                const unsigned char *packet_header);
int verify_packet(const unsigned char *packet, unsigned int packetlen, int bodylen,
                  const unsigned char *src, const unsigned char *dst,
                  const struct interface *ifp);
