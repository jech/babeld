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

#define MAC_ALGORITHM_HMAC_SHA256 1
#define MAC_ALGORITHM_BLAKE2S 2

#define MAX_DIGEST_LEN ((int)SHA256HashSize > (int)BLAKE2S_OUTBYTES ?   \
                        (int)SHA256HashSize : (int)BLAKE2S_OUTBYTES)
#define MAX_MAC_SPACE (2 + MAX_DIGEST_LEN)

#define MAX_KEY_LEN ((int)SHA256_Message_Block_Size > (int)BLAKE2S_KEYBYTES ? \
                     (int)SHA256_Message_Block_Size : (int)BLAKE2S_KEYBYTES)
#define MAX_KEY_NAME_LEN 16U

struct key {
    char name[MAX_KEY_NAME_LEN];
    unsigned char value[MAX_KEY_LEN];
    int len;
    unsigned short ref_count;
    unsigned char algorithm;
};

struct key *find_key(const char *name);
struct key *retain_key(struct key *key);
void release_key(struct key *key);
struct key *add_key(char *name, int algorithm, int len, unsigned char *value);
int sign_packet(struct buffered *buf, const struct interface *ifp,
                const unsigned char *packet_header);
int verify_packet(const unsigned char *packet, int packetlen, int bodylen,
                  const unsigned char *src, const unsigned char *dst,
                  const struct interface *ifp);
