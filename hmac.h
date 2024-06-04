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

#define MAX_DIGEST_LEN 32

struct key *find_key(const char *id);
struct key *retain_key(struct key *key);
void release_key(struct key *key);
struct key *add_key(char *id, int type, int len, unsigned char *value);
int compute_hmac(const unsigned char *src, const unsigned char *dst,
                 const unsigned char *packet_header,
                 const unsigned char *body, int bodylen, struct key *key,
                 unsigned char *hmac_return);
int add_hmac(struct buffered *buf, struct interface *ifp,
             unsigned char *packet_header);
int check_hmac(const unsigned char *packet, int packetlen, int bodylen,
               const unsigned char *src, const unsigned char *dst,
               struct interface *ifp);
