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

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <assert.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "babel.h"
#include "util.h"
#include "net.h"
#include "kernel.h"
#include "network.h"
#include "source.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"
#include "request.h"
#include "filter.h"

struct timeval now;

unsigned char myid[16];
int debug = 0;

int reboot_time;

int idle_time = 320;
int link_detect = 0;
int all_wireless = 0;
int wireless_hello_interval = -1;
int wired_hello_interval = -1;
int idle_hello_interval = -1;
int update_interval = -1;

unsigned char *receive_buffer = NULL;
int receive_buffer_size = 0;

const unsigned char zeroes[16] = {0};
const unsigned char ones[16] =
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

char *state_file = "/var/lib/babel-state";

int protocol_port;
unsigned char protocol_group[16];
int protocol_socket = -1;
int kernel_socket = -1;
static int kernel_routes_changed = 0;

static volatile sig_atomic_t exiting = 0, dumping = 0, changed = 0;

static int kernel_routes_callback(void *closure);
static void init_signals(void);
static void dump_tables(FILE *out);

int
main(int argc, char **argv)
{
    struct sockaddr_in6 sin6;
    int i, rc, fd;
    struct timeval check_neighbours_time;
    int expiry_time, kernel_dump_time;
    char *config_file = NULL;
    void *vrc;
    unsigned int seed;
    char **arg;

    parse_address("ff02::cca6:c0f9:e182:5373", protocol_group, NULL);
    protocol_port = 8475;

#define SHIFT() do { arg++; } while(0)
#define SHIFTE() do { arg++; if(*arg == NULL) goto syntax; } while(0)

    arg = argv;

    SHIFTE();

    while((*arg)[0] == '-') {
        if(strcmp(*arg, "--") == 0) {
            SHIFTE();
            break;
        } else if(strcmp(*arg, "-m") == 0) {
            SHIFTE();
            rc = parse_address(*arg, protocol_group, NULL);
            if(rc < 0)
                goto syntax;
            if(protocol_group[0] != 0xff) {
                fprintf(stderr,
                        "%s is not a multicast address\n", *arg);
                goto syntax;
            }
            if(protocol_group[1] != 2) {
                fprintf(stderr,
                        "Warning: %s is not a link-local multicast address\n",
                        *arg);
            }
        } else if(strcmp(*arg, "-p") == 0) {
            SHIFTE();
            protocol_port = atoi(*arg);
        } else if(strcmp(*arg, "-X") == 0) {
            if(numxroutes >= MAXXROUTES) {
                fprintf(stderr, "Too many exported routes.\n");
                exit(1);
            }
            SHIFTE();
            rc = parse_net(*arg,
                           xroutes[numxroutes].prefix,
                           &xroutes[numxroutes].plen, NULL);
            if(rc < 0)
                goto syntax;
            SHIFTE();
            if(strcmp(*arg, "infinity") == 0)
                xroutes[numxroutes].metric = INFINITY;
            else {
                int metric = atoi(*arg);
                if(metric < 0 || metric > INFINITY)
                    goto syntax;
                xroutes[numxroutes].metric = metric;
            }
            xroutes[numxroutes].forced = 1;
            xroutes[numxroutes].ifindex = 0;
            numxroutes++;
        } else if(strcmp(*arg, "-h") == 0) {
            SHIFTE();
            wireless_hello_interval = atoi(*arg);
        } else if(strcmp(*arg, "-H") == 0) {
            SHIFTE();
            wired_hello_interval = atoi(*arg);
        } else if(strcmp(*arg, "-i") == 0) {
            SHIFTE();
            idle_hello_interval = atoi(*arg);
        } else if(strcmp(*arg, "-u") == 0) {
            SHIFTE();
            update_interval = atoi(*arg);
        } else if(strcmp(*arg, "-k") == 0) {
            SHIFTE();
            kernel_metric = atoi(*arg);
            if(kernel_metric < 0 || kernel_metric > 0xFFFF)
                goto syntax;
        } else if(strcmp(*arg, "-P") == 0) {
            parasitic = 1;
        } else if(strcmp(*arg, "-s") == 0) {
            split_horizon = 0;
        } else if(strcmp(*arg, "-S") == 0) {
            SHIFTE();
            state_file = *arg;
        } else if(strcmp(*arg, "-d") == 0) {
            SHIFTE();
            debug = atoi(*arg);
        } else if(strcmp(*arg, "-l") == 0) {
            link_detect = 1;
        } else if(strcmp(*arg, "-w") == 0) {
            all_wireless = 1;
        } else if(strcmp(*arg, "-t") == 0) {
            SHIFTE();
            export_table = atoi(*arg);
            if(export_table < 0 || export_table > 0xFFFF)
                goto syntax;
        } else if(strcmp(*arg, "-T") == 0) {
            SHIFTE();
            import_table = atoi(*arg);
            if(import_table < 0 || import_table > 0xFFFF)
                goto syntax;
        } else if(strcmp(*arg, "-c") == 0) {
            SHIFTE();
            config_file = *arg;
        } else if(strcmp(*arg, "-C") == 0) {
            int rc;
            SHIFTE();
            rc = parse_config_from_string(*arg);
            if(rc < 0) {
                fprintf(stderr,
                        "Couldn't parse configuration from command line.\n");
                exit(1);
            }
        } else {
            goto syntax;
        }
        SHIFTE();
    }


    if(!config_file) {
        if(access("/etc/babel.conf", R_OK) >= 0)
            config_file = "/etc/babel.conf";
    }
    if(config_file) {
        rc = parse_config_from_file(config_file);
        if(rc < 0) {
            fprintf(stderr,
                    "Couldn't parse configuration from file %s.\n",
                    config_file);
            exit(1);
        }
    }

    if(wireless_hello_interval <= 0)
        wireless_hello_interval = 6;

    if(wired_hello_interval <= 0)
        wired_hello_interval = 30;

    if(update_interval <= 0)
        update_interval =
            MIN(MAX(wireless_hello_interval * 5, wired_hello_interval),
                70);

    if(seqno_interval <= 0)
        seqno_interval = MAX(wireless_hello_interval - 1, 2);

    rc = parse_address(*arg, myid, NULL);
    if(rc < 0)
        goto syntax;
    SHIFTE();

    gettimeofday(&now, NULL);

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open(random)");
        memcpy(&seed, myid + 12, 4);
    } else {
        rc = read(fd, &seed, sizeof(unsigned int));
        if(rc < sizeof(unsigned int)) {
            perror("read(random)");
            exit(1);
        }
        close(fd);
    }
    seed ^= (now.tv_sec ^ now.tv_usec);
    srandom(seed);

    reboot_time = now.tv_sec;
    myseqno = (random() & 0xFFFF);

    fd = open(state_file, O_RDONLY);
    if(fd < 0 && errno != ENOENT)
        perror("open(babel-state)");
    rc = unlink(state_file);
    if(rc < 0)
        perror("unlink(babel-state)");
    if(fd >= 0 && rc < 0) {
        /* If we couldn't unlink it, it's probably stale. */
        close(fd);
        fd = -1;
    }
    if(fd >= 0) {
        char buf[100];
        char buf2[100];
        int s;
        long t;
        rc = read(fd, buf, 99);
        if(rc < 0) {
            perror("read(babel-state)");
        } else {
            buf[rc] = '\0';
            rc = sscanf(buf, "%99s %d %ld\n", buf2, &s, &t);
            if(rc == 3 && s >= 0 && s <= 0xFFFF) {
                unsigned char sid[16];
                rc = parse_address(buf2, sid, NULL);
                if(rc < 0) {
                    fprintf(stderr, "Couldn't parse babel-state.\n");
                } else {
                    debugf("Got %s %d %ld from babel-state.\n",
                           format_address(sid), s, t);
                    if(memcmp(sid, myid, 16) == 0)
                        myseqno = seqno_plus(s, 1);
                    else
                        fprintf(stderr, "ID mismatch in babel-state.\n");
                    if(t >= 1176800000L && t <= now.tv_sec)
                        reboot_time = t;
                }
            } else {
                fprintf(stderr, "Couldn't parse babel-state.\n");
            }
        }
        close(fd);
    }

    if(reboot_time + silent_time > now.tv_sec)
        fprintf(stderr, "Respecting %ld second silent time.\n",
                (long int)(reboot_time + silent_time - now.tv_sec));

    rc = kernel_setup(1);
    if(rc < 0) {
        fprintf(stderr, "kernel_setup failed.\n");
        exit(1);
    }

    rc = kernel_setup_socket(1);
    if(rc < 0) {
        fprintf(stderr, "kernel_setup_socket failed.\n");
        exit(1);
    }

    protocol_socket = babel_socket(protocol_port);
    if(protocol_socket < 0) {
        perror("Couldn't create link local socket");
        goto fail;
    }

    while(*arg) {
        debugf("Adding network %s.\n", *arg);
        vrc = add_network(*arg);
        if(vrc == NULL)
            goto fail;
        SHIFT();
    }

    init_signals();
    check_networks();
    if(receive_buffer == NULL) {
        fprintf(stderr, "Warning: couldn't find any operational interfaces.\n");
        resize_receive_buffer(1500);
        if(receive_buffer == NULL)
            goto fail;
    }
    check_xroutes();
    kernel_routes_changed = 0;
    kernel_dump_time = now.tv_sec + 20 + random() % 20;
    timeval_plus_msec(&check_neighbours_time, &now, 5000 + random() % 5000);
    expiry_time = now.tv_sec + 20 + random() % 20;

    /* Make some noise so that others notice us */
    for(i = 0; i < numnets; i++) {
        if(!nets[i].up)
            continue;
        gettimeofday(&now, NULL);
        send_hello(&nets[i]);
        send_self_update(&nets[i], 0);
        send_request(&nets[i], NULL, 0, 0, 0, 0);
        flushbuf(&nets[i]);
        usleep(50000 + random() % 100000);
    }

    debugf("Entering main loop.\n");

    while(1) {
        struct timeval tv;
        fd_set readfds;

        gettimeofday(&now, NULL);

        tv = check_neighbours_time;
        timeval_min_sec(&tv, expiry_time);
        if(request_resend_time)
            timeval_min_sec(&tv, request_resend_time);
        for(i = 0; i < numnets; i++) {
            if(!nets[i].up)
                continue;
            timeval_min(&tv, &nets[i].flush_time);
            timeval_min_sec(&tv,
                            nets[i].hello_time + nets[i].hello_interval);
            if(!network_idle(&nets[i])) {
                timeval_min_sec(&tv, nets[i].self_update_time +
                                nets[i].self_update_interval);
                timeval_min_sec(&tv, nets[i].update_time + update_interval);
            }
        }
        timeval_min(&tv, &update_flush_time);
        FD_ZERO(&readfds);
        if(timeval_compare(&tv, &now) > 0) {
            timeval_minus(&tv, &tv, &now);
            FD_SET(protocol_socket, &readfds);
            if(kernel_socket < 0) kernel_setup_socket(1);
            if(kernel_socket >= 0)
                FD_SET(kernel_socket, &readfds);
            rc = select(MAX(protocol_socket, kernel_socket) + 1,
                        &readfds, NULL, NULL, &tv);
            if(rc < 0) {
                if(errno == EINTR) {
                    rc = 0;
                    FD_ZERO(&readfds);
                } else {
                    perror("select");
                    sleep(1);
                    continue;
                }
            }
        }

        gettimeofday(&now, NULL);

        if(exiting)
            break;

        if(kernel_socket >= 0 && FD_ISSET(kernel_socket, &readfds))
            kernel_callback(kernel_routes_callback, NULL);

        if(FD_ISSET(protocol_socket, &readfds)) {
            rc = babel_recv(protocol_socket,
                            receive_buffer, receive_buffer_size,
                            (struct sockaddr*)&sin6, sizeof(sin6));
            if(rc < 0) {
                if(errno != EAGAIN && errno != EINTR) {
                    perror("recv");
                    sleep(1);
                }
            } else {
                for(i = 0; i < numnets; i++) {
                    if(!nets[i].up)
                        continue;
                    if(nets[i].ifindex == sin6.sin6_scope_id) {
                        parse_packet((unsigned char*)&sin6.sin6_addr, &nets[i],
                                     receive_buffer, rc);
                        VALGRIND_MAKE_MEM_UNDEFINED(receive_buffer,
                                                    receive_buffer_size);
                        break;
                    }
                }
            }
        }

        if(changed) {
            kernel_dump_time = now.tv_sec;
            check_neighbours_time = now;
            expiry_time = now.tv_sec;
            changed = 0;
        }

        if(kernel_routes_changed || now.tv_sec >= kernel_dump_time) {
            rc = check_xroutes();
            if(rc > 0)
                send_self_update(NULL, 1);
            else if(rc < 0)
                fprintf(stderr, "Warning: couldn't check exported routes.\n");
            kernel_routes_changed = 0;
            if(kernel_socket >= 0)
                kernel_dump_time = now.tv_sec + 200 + random() % 200;
            else
                kernel_dump_time = now.tv_sec + 20 + random() % 20;
        }

        if(timeval_compare(&check_neighbours_time, &now) < 0) {
            int msecs;
            msecs = check_neighbours();
            msecs = MAX(msecs, 500);
            timeval_plus_msec(&check_neighbours_time, &now,
                              msecs / 2 + random() % msecs);
        }

        if(now.tv_sec >= expiry_time) {
            check_networks();
            expire_routes();
            expire_requests();
            expiry_time = now.tv_sec + 20 + random() % 20;
        }

        for(i = 0; i < numnets; i++) {
            if(!nets[i].up)
                continue;
            if(now.tv_sec >= nets[i].hello_time + nets[i].hello_interval)
                send_hello(&nets[i]);
            if(now.tv_sec >= nets[i].ihu_time + nets[i].ihu_interval)
                send_ihu(NULL, &nets[i]);
            if(!network_idle(&nets[i])) {
                if(now.tv_sec >= nets[i].update_time + update_interval)
                    send_update(&nets[i], 0, NULL, 0);
                if(now.tv_sec >=
                   nets[i].self_update_time + nets[i].self_update_interval) {
                    send_self_update(&nets[i], 0);
                }
            }
        }

        if(now.tv_sec >= request_resend_time)
            resend_requests();

        if(update_flush_time.tv_sec != 0) {
            if(now.tv_sec >= update_flush_time.tv_sec)
                flushupdates();
        }

        for(i = 0; i < numnets; i++) {
            if(!nets[i].up)
                continue;
            if(nets[i].flush_time.tv_sec != 0) {
                if(timeval_compare(&now, &nets[i].flush_time) >= 0)
                    flushbuf(&nets[i]);
            }
        }

        if(debug || dumping) {
            dump_tables(stdout);
            dumping = 0;
        }
    }

    debugf("Exiting...\n");
    for(i = 0; i < numroutes; i++) {
        /* Uninstall and retract all routes. */
        if(routes[i].installed) {
            uninstall_route(&routes[i]);
            send_update(NULL, 1, routes[i].src->prefix, routes[i].src->plen);
        }
    }
    for(i = 0; i < numnets; i++) {
        if(!nets[i].up)
            continue;
        /* Retract exported routes. */
        send_self_retract(&nets[i]);
        /* Make sure that we expire quickly from our neighbours'
           association caches. */
        send_hello_noupdate(&nets[i], 15 * numnets);
        flushupdates();
        flushbuf(&nets[i]);
        usleep(50000 + random() % 100000);
    }
    for(i = 0; i < numnets; i++) {
        if(!nets[i].up)
            continue;
        /* Make sure they got it. */
        send_self_retract(&nets[i]);
        send_hello_noupdate(&nets[i], 1);
        flushupdates();
        flushbuf(&nets[i]);
        usleep(50000 + random() % 100000);
        network_up(&nets[i], 0);
    }
    kernel_setup_socket(0);
    kernel_setup(0);

    fd = open(state_file, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0) {
        perror("creat(babel-state)");
        unlink(state_file);
    } else {
        char buf[100];
        rc = snprintf(buf, 100, "%s %d %ld\n",
                      format_address(myid), (int)myseqno, (long)now.tv_sec);
        if(rc < 0 || rc >= 100) {
            fprintf(stderr, "write(babel-state): overflow.\n");
            unlink(state_file);
        } else {
            rc = write(fd, buf, rc);
            if(rc < 0) {
                perror("write(babel-state)");
                unlink(state_file);
            }
            fsync(fd);
        }
        close(fd);
    }
    debugf("Done.\n");
    return 0;

 syntax:
    fprintf(stderr,
            "Syntax: %s "
            "[-m multicast_address] [-p port] [-S state-file]\n"
            "                "
            "[-h hello] [-H wired_hello] [-i idle_hello] [-u update]\n"
            "                "
            "[-k metric] [-s] [-P] [-l] [-w] [-d level]\n"
            "                "
            "[-t table] [-T table] [-X net cost] [-c file] [-C statement]\n"
            "                "
            "id interface...\n",
            argv[0]);
    exit(1);

 fail:
    for(i = 0; i < numnets; i++) {
        if(!nets[i].up)
            continue;
        network_up(&nets[i], 0);
    }
    kernel_setup_socket(0);
    kernel_setup(0);
    exit(1);
}

void
resize_receive_buffer(int size)
{
    char *new;

    if(size <= receive_buffer_size)
        return;

    if(receive_buffer == NULL) {
        receive_buffer = malloc(size);
        if(receive_buffer == NULL)
            return;
        receive_buffer_size = size;
    }

    new = realloc(receive_buffer, size);
    if(new == NULL) {
        perror("malloc(receive_buffer)");
        return;
    }
    receive_buffer_size = size;
}

static void
sigexit(int signo)
{
    exiting = 1;
}

static void
sigdump(int signo)
{
    dumping = 1;
}

static void
sigchanged(int signo)
{
    changed = 1;
}

static void
init_signals(void)
{
    struct sigaction sa;
    sigset_t ss;

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGHUP, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigchanged;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);

#ifdef SIGINFO
    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINFO, &sa, NULL);
#endif
}

static void
dump_tables(FILE *out)
{
    int i;

    fprintf(out, "\n");

    fprintf(out, "My id %s seqno %d\n", format_address(myid), myseqno);

    for(i = 0; i < numneighs; i++) {
        if(neighs[i].id[0] == 0xFF)
            continue;
        fprintf(out, "Neighbour %s ", format_address(neighs[i].id));
        fprintf(out, "at %s dev %s reach %04x rxcost %d txcost %d%s.\n",
                format_address(neighs[i].address),
                neighs[i].network->ifname,
                neighs[i].reach,
                neighbour_rxcost(&neighs[i]),
                neighs[i].txcost,
                neighs[i].network->up ? "" : " (down)");
    }
    for(i = 0; i < numxroutes; i++) {
        fprintf(out, "%s metric %d (%s)\n",
                format_prefix(xroutes[i].prefix, xroutes[i].plen),
                xroutes[i].metric,
                xroutes[i].forced ? "forced" : "exported");
    }
    for(i = 0; i < numroutes; i++) {
        int id =
            routes[i].src->plen != 128 ||
            memcmp(routes[i].src->prefix, routes[i].src->address, 16) != 0;
        const unsigned char *nexthop =
            memcmp(routes[i].nexthop, routes[i].neigh->address, 16) == 0 ?
            NULL : routes[i].nexthop;
        fprintf(out, "%s metric %d refmetric %d %s%s seqno %d age %d "
                "via %s neigh %s%s%s%s\n",
                format_prefix(routes[i].src->prefix, routes[i].src->plen),
                routes[i].metric, routes[i].refmetric,
                id ? "id " : "",
                id ? format_address(routes[i].src->address) : "",
                (int)routes[i].seqno,
                (int)(now.tv_sec - routes[i].time),
                routes[i].neigh->network->ifname,
                format_address(routes[i].neigh->address),
                nexthop ? " nexthop " : "",
                nexthop ? format_address(nexthop) : "",
                routes[i].installed ? " (installed)" :
                route_feasible(&routes[i]) ? " (feasible)" : "");
    }
    fflush(out);
}

static int
kernel_routes_callback(void *closure)
{
    kernel_routes_changed = 1;
    return 1;
}
