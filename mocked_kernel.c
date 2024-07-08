/*
Copyright 2007-2010 by Grégoire Henry, Julien Cristau and Juliusz Chroboczek

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

#include "kernel.h"

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

int export_table = -1, import_table_count = 0, import_tables[MAX_IMPORT_TABLES];

int
if_eui64(char *ifname, int ifindex, unsigned char *eui)
{
    return 0;
}

int
kernel_setup(int setup)
{
    return 0;
}

int
kernel_setup_socket(int setup)
{
    return 0;
}

int
kernel_setup_interface(int setup, const char *ifname, int ifindex)
{
    return 0;
}

int
kernel_interface_operational(const char *ifname, int ifindex)
{
    return 0;
}

int
kernel_interface_ipv4(const char *ifname, int ifindex, unsigned char *addr_r)
{
    return 0;
}

int
kernel_interface_mtu(const char *ifname, int ifindex)
{
    return 0;
}

int
kernel_interface_wireless(const char *ifname, int ifindex)
{
    return 0;
}

int
kernel_safe_v4viav6(void)
{
    return 0;
}

int
kernel_route(int operation, int table,
             const unsigned char *dest, unsigned short plen,
             const unsigned char *src, unsigned short src_plen,
             const unsigned char *pref_src,
             const unsigned char *gate, int ifindex, unsigned int metric,
             const unsigned char *newgate, int newifindex,
             unsigned int newmetric, int newtable)
{
    return 0;
}

int
kernel_dump(int operation, struct kernel_filter *filter)
{
    return 0;
}

int
kernel_callback(struct kernel_filter *filter)
{
    return 0;
}
