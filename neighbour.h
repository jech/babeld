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

struct neighbour {
    /* This is -1 when unknown, and -2 for an invalid neighbour,
       so don't make it unsigned */
    int hello_seqno;
    unsigned char id[16];
    unsigned char address[16];
    unsigned short reach;
    unsigned short txcost;
    struct timeval hello_time;
    struct timeval ihu_time;
    unsigned short hello_interval; /* in centiseconds */
    unsigned short ihu_interval;   /* in centiseconds */
    struct network *network;
};

extern struct neighbour neighs[MAXNEIGHBOURS];
extern int numneighs;

void flush_neighbour(struct neighbour *neigh);
struct neighbour *find_neighbour(const unsigned char *address,
                                 struct network *net);
struct neighbour *
add_neighbour(const unsigned char *id, const unsigned char *address,
              struct network *net);
int update_neighbour(struct neighbour *neigh, int hello, int hello_interval);
int check_neighbours(void);
int neighbour_rxcost(struct neighbour *neigh);
int neighbour_cost(struct neighbour *neigh);
