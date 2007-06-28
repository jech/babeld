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

extern unsigned char seqno;
extern int seqno_time;
extern int seqno_interval;

extern unsigned int jitter;
extern unsigned int update_jitter;
extern int add_cost;
extern int parasitic;
extern int silent_time;
extern int broadcast_txcost;
extern int split_horizon;

extern struct timeval update_flush_time;
extern const unsigned char packet_header[4];

void parse_packet(const unsigned char *from, struct network *net,
                  const unsigned char *packet, int len);
void flushbuf(struct network *net);
void send_hello(struct network *net);
void send_request(struct network *net, struct destination *dest,
                  int hopcount, int seqno);
void send_unicast_request(struct neighbour *neigh, struct destination *dest,
                          int hopcount, int seqno);
void send_update(struct destination *dest, struct network *net);
void send_self_update(struct network *net, int force_seqno);
void send_self_retract(struct network *net);
void send_neighbour_update(struct neighbour *neigh, struct network *net);
void send_txcost(struct neighbour *neigh, struct network *net);
void schedule_flush_now(struct network *net);
void flushupdates(void);










