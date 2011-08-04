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

struct filter {
    int af;
    char *ifname;
    unsigned int ifindex;
    unsigned char *id;
    unsigned char *prefix;
    unsigned char plen;
    unsigned char plen_ge, plen_le;
    unsigned char *neigh;
    int proto;                  /* May be negative */
    unsigned int result;
    struct filter *next;
};

int parse_config_from_file(char *filename);
int parse_config_from_string(char *string);
void renumber_filters(void);

int input_filter(const unsigned char *id,
                 const unsigned char *prefix, unsigned short plen,
                 const unsigned char *neigh, unsigned int ifindex);
int output_filter(const unsigned char *id, const unsigned char *prefix,
                  unsigned short plen, unsigned int ifindex);
int redistribute_filter(const unsigned char *prefix, unsigned short plen,
                        unsigned int ifindex, int proto);
int finalise_config(void);
