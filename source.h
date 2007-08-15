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

struct destination {
    unsigned char address[16];
    unsigned char seqno;
    unsigned short metric;
    int time;
    int requested_seqno;
    struct network *requested_net;
};

struct destination *find_destination(const unsigned char *d,
                                     int create, unsigned char seqno);
void update_destination(struct destination *dest,
                        unsigned char seqno, unsigned short metric);
void notice_request(struct destination *dest, unsigned char seqno,
                    struct network *net);
int request_requested(struct destination *dest, unsigned char seqno,
                      struct network *net);
void satisfy_request(struct destination *dest, unsigned char seqno,
                     struct network *net);
