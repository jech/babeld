/**
 * test_packing.c
 */

#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "babeld.h"
#include "util.h"
#include "net.h"
#include "kernel.h"
#include "interface.h"
#include "source.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"
#include "resend.h"
#include "configuration.h"
#include "local.h"
#include "rule.h"
#include "version.h"

#include "arch_detect.h"

int main()
{
#ifdef __GNUC__
    printf("Compiled with gcc %d.%d.%d for the %s "
        "architecture in %s mode\n",
        __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__,
        arch, __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
        "little endian" : "big endian");
#endif
    P(filter_result);
    P(filter);
    P(buffered_update);
    P(interface_conf);
    P(interface);
    P(kernel_route);
    P(kernel_rule);
    P(kernel_filter);
    P(local_socket);
    P(neighbour);
    P(resend);
    P(babel_route);
    P(source);
    P(xroute);
    return 0;
}
