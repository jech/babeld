/*
Copyright (c) 2008 by Juliusz Chroboczek

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

struct neighbour;
struct babel_route;
struct xroute;

#define LOCAL_FLUSH 0
#define LOCAL_ADD 1
#define LOCAL_CHANGE 2

#ifndef NO_LOCAL_INTERFACE

int local_read(int s);
void local_notify_self(void);
void local_notify_neighbour(struct neighbour *neigh, int kind);
void local_notify_xroute(struct xroute *xroute, int kind);
void local_notify_route(struct babel_route *route, int kind);
void local_notify_all(void);

#else

#define local_notify_self() do {} while(0)
#define local_notify_neighbour(n, k) do {} while(0)
#define local_notify_xroute(x, k) do {} while(0)
#define local_notify_route(r, k) do {} while(0)
#define local_dump() do {} while 0
#endif
