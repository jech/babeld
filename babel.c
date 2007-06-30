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
#include "destination.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"

struct timeval now;

unsigned char myid[16];
int debug = 0;

static int maxmtu;

int reboot_time;

int idle_time = 320;

int wireless_hello_interval = -1;
int wired_hello_interval = -1;
int idle_hello_interval = -1;
int update_interval = -1;

int max_request_hopcount = 65;

struct network nets[MAXNETS];
int numnets = 0;

const unsigned char zeroes[16] = {0};

char *state_file = "/var/lib/babel-state";

int protocol_port;
unsigned char protocol_group[16];
int protocol_socket = -1;
int kernel_socket = -1;
static int kernel_routes_changed = 0;

static volatile sig_atomic_t exiting = 0, dumping = 0;

struct network *add_network(char *ifname, int ifindex, int bufsize,
                            int wired, unsigned int cost);
void expire_routes(void);

static int kernel_routes_callback(void *closure);
static void init_signals(void);
static void dump_tables(FILE *out);

int
main(int argc, char **argv)
{
    struct sockaddr_in6 sin6;
    struct ipv6_mreq mreq;
    int i, rc, fd;
    static unsigned char *buf;
    int expiry_time, kernel_dump_time;
    void *vrc;
    unsigned int seed;
    char **arg;

    parse_address("ff02::cca6:c0f9:e182:5373", protocol_group);
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
            rc = parse_address(*arg, protocol_group);
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
        } else if(strcmp(*arg, "-x") == 0 || strcmp(*arg, "-X") == 0) {
            int force = (strcmp(*arg, "-X") == 0);
            if(nummyxroutes >= MAXMYXROUTES) {
                fprintf(stderr, "Too many network routes.\n");
                exit(1);
            }
            SHIFTE();
            rc = parse_net(*arg,
                           myxroutes[nummyxroutes].prefix,
                           &myxroutes[nummyxroutes].plen);
            if(rc < 0)
                goto syntax;
            SHIFTE();
            if(strcmp(*arg, "infinity") == 0)
                myxroutes[nummyxroutes].cost = INFINITY;
            else
                myxroutes[nummyxroutes].cost = atoi(*arg);
            if(myxroutes[nummyxroutes].cost < 0 ||
               myxroutes[nummyxroutes].cost > INFINITY)
                goto syntax;
            myxroutes[nummyxroutes].installed = force ? 2 : 0;
            nummyxroutes++;
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
        } else if(strcmp(*arg, "-c") == 0) {
            SHIFTE();
            add_cost = atoi(*arg);
            if(add_cost < 0 || add_cost > INFINITY)
                goto syntax;
        } else if(strcmp(*arg, "-s") == 0) {
            split_horizon = 0;
        } else if(strcmp(*arg, "-b") == 0) {
            broadcast_txcost = 1;
        } else if(strcmp(*arg, "-S") == 0) {
            SHIFTE();
            state_file = *arg;
        } else if(strcmp(*arg, "-d") == 0) {
            SHIFTE();
            debug = atoi(*arg);
        } else {
            goto syntax;
        }
        SHIFTE();
    }

    if(wireless_hello_interval <= 0)
        wireless_hello_interval = 8;

    if(wired_hello_interval <= 0)
        wired_hello_interval = 30;

    if(update_interval <= 0)
        update_interval =
            MIN(MAX(wireless_hello_interval * 5, wired_hello_interval),
                70);

    if(seqno_interval <= 0)
        seqno_interval = MAX(2 * wireless_hello_interval - 1, 2);

    jitter = MIN(wireless_hello_interval * 1000 / 4, 2000);
    update_jitter = 2 * jitter;

    rc = parse_address(*arg, myid);
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
    seqno = (random() & 0xFF);

    fd = open(state_file, O_RDONLY);
    if(fd < 0 && errno != ENOENT)
        perror("open(babel-state)");
    rc = unlink(state_file);
    if(fd >= 0 && rc < 0) {
        perror("unlink(babel-state)");
        /* If we couldn't unlink it, it might be stale. */
        close(fd);
        fd = -1;
    }
    if(fd >= 0) {
        char buf[100];
        int s, t;
        rc = read(fd, buf, 99);
        if(rc < 0) {
            perror("read(babel-state)");
        } else {
            buf[rc] = '\0';
            rc = sscanf(buf, "%d %d\n", &s, &t);
            if(rc == 2 && s >= 0 && s < 256) {
                debugf("Got %d %d from babel-state.\n", s, t);
                seqno = ((s + 1) & 0xFF);
                if(t >= 1176800000 && t <= now.tv_sec)
                    reboot_time = t;
            } else {
                fprintf(stderr, "Couldn't parse babel-state.\n");
            }
        }
        close(fd);
    }

    rc = kernel_setup(1);
    if(rc < 0) {
        fprintf(stderr, "kernel_setup failed.\n");
        exit(1);
    }

    protocol_socket = babel_socket(protocol_port);
    if(protocol_socket < 0) {
        perror("Couldn't create link local socket");
        goto fail;
    }

    /* Just in case. */
    maxmtu = 1500;

    while(*arg) {
        int ifindex;
        int mtu;

        ifindex = if_nametoindex(*arg);
        if(ifindex <= 0) {
            fprintf(stderr, "Unknown interface %s.\n", *arg);
            goto fail;
        }

        rc = kernel_setup_interface(1, *arg, ifindex);
        if(rc < 0) {
            fprintf(stderr, "kernel_setup_interface(%s, %d) failed.\n",
                    *arg, ifindex);
            goto fail;
        }

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
        mreq.ipv6mr_interface = ifindex;

        rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0) {
            perror("setsockopt(IPV6_JOIN_GROUP)");
            goto fail;
        }

        mtu = kernel_interface_mtu(*arg, ifindex);
        if(mtu < 0) {
            fprintf(stderr, "Warning: couldn't get MTU of interface %s (%d).\n",
                    *arg, ifindex);
            mtu = 1204;
            maxmtu = MAX(maxmtu, 16384);
        } else if(mtu < 1280) {
            fprintf(stderr,
                    "Warning: suspiciously low MTU %d on interface %s (%d).\n",
                    mtu, *arg, ifindex);
            mtu = 1204;
            maxmtu = MAX(maxmtu, 16384);
        } else {
            if(mtu >= 0x10000) {
                fprintf(stderr,
                        "Warning: "
                        "suspiciously high MTU %d on interface %s (%d).\n",
                        mtu, *arg, ifindex);
                maxmtu = MAX(maxmtu, mtu);
                mtu = 32768;
            }
            /* 40 for IPv6 header, 8 for UDP header, 12 for good luck. */
            mtu -= 60;
            maxmtu = MAX(maxmtu, mtu);
        }

        rc = kernel_interface_wireless(*arg, ifindex);
        if(rc < 0) {
            fprintf(stderr,
                    "Warning: "
                    "couldn't determine whether %s is a wireless interface.\n",
                    *arg);
            rc = 1;
        }
        debugf("Adding %s network %s (%d).\n",
               rc ? "wireless" : "wired", *arg, ifindex);
        vrc = add_network(*arg, ifindex, mtu, !rc, rc ? 0 : 128);
        if(vrc == NULL)
            goto fail;
        SHIFT();
    }

    buf = malloc(maxmtu);
    if(buf == NULL) {
        perror("malloc");
        goto fail;
    }

    init_signals();
    check_myxroutes();
    kernel_routes_changed = 0;
    kernel_dump_time = now.tv_sec + 20 + random() % 20;

    expiry_time = now.tv_sec + 20 + random() % 20;

    /* Make some noise so others notice us */
    for(i = 0; i < numnets; i++) {
        send_hello(&nets[i]);
        send_request(&nets[i], NULL, 0, -1);
    }
    for(i = 0; i < numnets; i++) {
        usleep(50000 + random() % 100000);
        flushbuf(&nets[i]);
        gettimeofday(&now, NULL);
        send_hello(&nets[i]);
        send_self_update(&nets[i], 0);
        send_request(&nets[i], NULL, 0, -1);
    }

    debugf("Entering main loop.\n");

    while(1) {
        struct timeval tv;
        fd_set readfds;

        gettimeofday(&now, NULL);
        if(update_flush_time.tv_sec != 0) {
            if(now.tv_sec >= update_flush_time.tv_sec)
                flushupdates();
        }
        for(i = 0; i < numnets; i++) {
            if(nets[i].flush_time.tv_sec != 0) {
                if(timeval_compare(&now, &nets[i].flush_time) >= 0)
                    flushbuf(&nets[i]);
            }
        }

        tv.tv_sec = expiry_time;
        tv.tv_usec = random() % 1000000;
        for(i = 0; i < numnets; i++) {
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
            if(kernel_socket >= 0)
                FD_SET(kernel_socket, &readfds);
            rc = select(MAX(protocol_socket, kernel_socket) + 1,
                        &readfds, NULL, NULL, &tv);
            if(rc < 0) {
                if(errno != EINTR) {
                    perror("select");
                    sleep(1);
                    continue;
                } else {
                    FD_ZERO(&readfds);
                }
            }
        }

        gettimeofday(&now, NULL);

        if(exiting)
            break;

        if(kernel_socket >= 0 && FD_ISSET(kernel_socket, &readfds))
            kernel_callback(kernel_routes_callback, NULL);

        if(FD_ISSET(protocol_socket, &readfds)) {
            rc = babel_recv(protocol_socket, buf, maxmtu,
                              (struct sockaddr*)&sin6, sizeof(sin6));
            if(rc < 0) {
                if(errno != EAGAIN && errno != EINTR) {
                    perror("recv");
                    sleep(1);
                }
            } else {
                for(i = 0; i < numnets; i++) {
                    if(nets[i].ifindex == sin6.sin6_scope_id) {
                        parse_packet((unsigned char*)&sin6.sin6_addr, &nets[i],
                                     buf, rc);
                        VALGRIND_MAKE_MEM_UNDEFINED(buf, maxmtu);
                        break;
                    }
                }
            }
        }

        if(now.tv_sec >= expiry_time) {
            expire_routes();
            expiry_time = now.tv_sec + 20 + random() % 20;
        }

        if(kernel_routes_changed || now.tv_sec >= kernel_dump_time) {
            rc = check_myxroutes();
            if(rc > 0)
                send_self_update(NULL, 1);
            else if(rc < 0)
                fprintf(stderr, "Warning: couldn't check installed routes.\n");
            kernel_routes_changed = 0;
            if(kernel_socket >= 0)
                kernel_dump_time = now.tv_sec + 200 + random() % 100;
            else
                kernel_dump_time = now.tv_sec + 20 + random() % 20;
        }

        for(i = 0; i < numnets; i++) {
            if(now.tv_sec >= nets[i].hello_time + nets[i].hello_interval)
                send_hello(&nets[i]);
            if(now.tv_sec >= nets[i].txcost_time + nets[i].txcost_interval)
                send_txcost(NULL, &nets[i]);
            if(!network_idle(&nets[i])) {
                if(now.tv_sec >= nets[i].update_time + update_interval)
                    send_update(NULL, &nets[i]);
                if(now.tv_sec >=
                   nets[i].self_update_time + nets[i].self_update_interval) {
                    send_self_update(&nets[i], 0);
                }
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
            send_update(routes[i].dest, NULL);
        }
    }
    flushupdates();
    usleep(50000 + random() % 100000);
    for(i = 0; i < numnets; i++) {
        /* Retract self routes. */
        send_self_retract(&nets[i]);
        /* Make sure that we expire quickly from our neighbours'
           association caches. */
        nets[i].hello_interval = 1;
        send_hello(&nets[i]);
        flushbuf(&nets[i]);
    }
    usleep(50000 + random() % 100000);
    for(i = 0; i < numnets; i++) {
        /* Make sure they got it. */
        send_hello(&nets[i]);
        flushbuf(&nets[i]);
        kernel_setup_interface(0, nets[i].ifname, nets[i].ifindex);
    }
    kernel_setup(0);

    fd = open(state_file, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0) {
        perror("creat(babel-state)");
        unlink(state_file);
    } else {
        char buf[100];
        rc = snprintf(buf, 100, "%d %d\n", seqno, (int)now.tv_sec);
        rc = write(fd, buf, rc);
        if(rc < 0) {
            perror("write(babel-state)");
            unlink(state_file);
        }
        close(fd);
    }
    debugf("Done.");
    return 0;

 syntax:
    fprintf(stderr,
            "Syntax: %s "
            "[-m multicast_address] [-p port] [-S state-file]\n"
            "                "
            "[-h hello] [-H wired_hello] [i idle_hello]\n"
            "                "
            "[-u update] [-k metric] [-s] [-P] [-c cost]\n"
            "                "
            "[-d level] [-x net cost] [-X net cost]... address interface...\n",
            argv[0]);
    exit(1);

 fail:
    for(i = 0; i < numnets; i++)
        kernel_setup_interface(0, nets[i].ifname, nets[i].ifindex);
    kernel_setup(0);
    exit(1);
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

    fprintf(out, "My id %s\n", format_address(myid));

    for(i = 0; i < nummyxroutes; i++) {
        fprintf(out, "External %s/%d cost %d%s\n",
                format_address(myxroutes[i].prefix),
                myxroutes[i].plen,
                myxroutes[i].cost,
                myxroutes[i].installed ?
                (myxroutes[i].installed >= 2 ? " (forced)" : " (installed)") :
                "");
    }

    for(i = 0; i < numneighs; i++) {
        if(neighs[i].id[0] == 0)
            continue;
        fprintf(out, "Neighbour %s ", format_address(neighs[i].id));
        fprintf(out, "at %s dev %s reach %04x rxcost %d txcost %d.\n",
               format_address(neighs[i].address),
               neighs[i].network->ifname,
               neighs[i].reach,
               neighbour_rxcost(&neighs[i]),
               neighs[i].txcost);
    }
    for(i = 0; i < numroutes; i++) {
        fprintf(out, "%s metric %d refmetric %d seqno %d age %d ",
               format_address(routes[i].dest->address),
               routes[i].metric, routes[i].refmetric, routes[i].seqno,
               (int)(now.tv_sec - routes[i].time));
        fprintf(out, "via %s nexthop %s%s\n",
               routes[i].nexthop->network->ifname,
               format_address(routes[i].nexthop->address),
               routes[i].installed ? " (installed)" :
               route_feasible(&routes[i]) ? " (feasible)" : "");
    }
    for(i = 0; i < numxroutes; i++) {
        fprintf(out, "%s/%d gw %s cost %d metric %d age %d%s\n",
               format_address(xroutes[i].prefix),
               xroutes[i].plen,
               format_address(xroutes[i].gateway->address),
               xroutes[i].cost,
               xroutes[i].metric,
               (int)(now.tv_sec - xroutes[i].time),
               xroutes[i].installed ? " (installed)" : "");
    }
    fflush(out);
}

static int
kernel_routes_callback(void *closure)
{
    kernel_routes_changed = 1;
    return 1;
}

struct network *
add_network(char *ifname, int ifindex, int mtu, int wired, unsigned int cost)
{
    void *p;

    if(numnets >= MAXNETS) {
        fprintf(stderr, "Too many networks.\n");
        return NULL;
    }

    memset(nets + numnets, 0, sizeof(struct network));
    nets[numnets].ifindex = ifindex;
    nets[numnets].wired = wired;
    nets[numnets].cost = cost;
    nets[numnets].activity_time = now.tv_sec;
    update_hello_interval(&nets[numnets]);
    nets[numnets].bufsize = mtu - sizeof(packet_header);
    strncpy(nets[numnets].ifname, ifname, IF_NAMESIZE);
    p = malloc(nets[numnets].bufsize);
    if(p == NULL) {
        perror("malloc");
        return NULL;
    }
    nets[numnets].sendbuf = p;
    nets[numnets].buffered = 0;
    nets[numnets].bucket_time = now.tv_sec;
    nets[numnets].bucket = 0;
    nets[numnets].hello_seqno = (random() & 0xFF);
    numnets++;
    return &nets[numnets - 1];
}

int
network_idle(struct network *net)
{
    return (idle_hello_interval > 0 &&
            net->activity_time < now.tv_sec - idle_time);
}

void
update_hello_interval(struct network *net)
{
    if(network_idle(net))
        net->hello_interval = idle_hello_interval;
    else if(net->wired)
        net->hello_interval = wired_hello_interval;
    else
        net->hello_interval = wireless_hello_interval;

    net->self_update_interval =
        MAX(15 + nets[numnets].hello_interval / 2,
            nets[numnets].hello_interval);

    net->txcost_interval = 7 * net->hello_interval / 4;
}

void
expire_routes(void)
{
    int i;

    debugf("Expiring old routes.\n");

    for(i = 0; i < numneighs; i++) {
        if(neighs[i].id[0] == 0)
            continue;
        check_neighbour(&neighs[i]);
        /* No need to update_neighbour_metric -- update_route_metric below. */
    }

    i = 0;
    while(i < numroutes) {
        struct route *route = &routes[i];

        if(route->time < now.tv_sec - route_gc_delay) {
            flush_route(route);
            continue;
        }

        update_route_metric(route);

        if(route->installed && route->refmetric < INFINITY) {
            if(route->time < now.tv_sec - MAX(5, route_timeout_delay - 25))
                send_unicast_request(route->nexthop, route->dest,
                                     max_request_hopcount, route->dest->seqno);
        }
        i++;
    }

    i = 0;
    while(i < numxroutes) {
        struct xroute *xroute = &xroutes[i];
        if(xroute->time < now.tv_sec - xroute_gc_delay ||
           (xroute->cost >= INFINITY &&
            xroute->time < now.tv_sec - xroute_hold_delay)) {
            flush_xroute(xroute);
            continue;
        }
        update_xroute_metric(xroute, xroute->cost);
        i++;
    }
}
