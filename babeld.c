/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright (c) 2010 by Vincent Gross

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

struct timeval now;

unsigned char myid[8];
int debug = 0;

int link_detect = 0;
int all_wireless = 0;
int default_wireless_hello_interval = -1;
int default_wired_hello_interval = -1;
int resend_delay = -1;
int do_daemonise = 0;
char *logfile = NULL, *pidfile = "/var/run/babeld.pid";

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
static int kernel_link_changed = 0;
static int kernel_addr_changed = 0;

struct timeval check_neighbours_timeout;

static volatile sig_atomic_t exiting = 0, dumping = 0, reopening = 0;

int local_server_socket = -1, local_socket = -1;
int local_server_port = -1;

static int kernel_routes_callback(int changed, void *closure);
static void init_signals(void);
static void dump_tables(FILE *out);
static int reopen_logfile(void);

int
main(int argc, char **argv)
{
    struct sockaddr_in6 sin6;
    int rc, fd, i, opt;
    time_t expiry_time, source_expiry_time, kernel_dump_time;
    char *config_file = NULL;
    void *vrc;
    unsigned int seed;
    struct interface *ifp;

    gettime(&now);

    rc = read_random_bytes(&seed, sizeof(seed));
    if(rc < 0) {
        perror("read(random)");
        seed = 42;
    }

    seed ^= (now.tv_sec ^ now.tv_usec);
    srandom(seed);

    parse_address("ff02:0:0:0:0:0:1:6", protocol_group, NULL);
    protocol_port = 6696;

    while(1) {
        opt = getopt(argc, argv, "m:p:h:H:i:k:A:PsuS:d:g:lwz:t:T:c:C:DL:I:");
        if(opt < 0)
            break;

        switch(opt) {
        case 'm':
            rc = parse_address(optarg, protocol_group, NULL);
            if(rc < 0)
                goto usage;
            if(protocol_group[0] != 0xff) {
                fprintf(stderr,
                        "%s is not a multicast address\n", optarg);
                goto usage;
            }
            if(protocol_group[1] != 2) {
                fprintf(stderr,
                        "Warning: %s is not a link-local multicast address\n",
                        optarg);
            }
            break;
        case 'p':
            protocol_port = parse_nat(optarg);
            if(protocol_port <= 0 || protocol_port > 0xFFFF)
                goto usage;
            break;
        case 'h':
            default_wireless_hello_interval = parse_msec(optarg);
            if(default_wireless_hello_interval <= 0 ||
               default_wireless_hello_interval > 0xFFFF * 10)
                goto usage;
            break;
        case 'H':
            default_wired_hello_interval = parse_msec(optarg);
            if(default_wired_hello_interval <= 0 ||
               default_wired_hello_interval > 0xFFFF * 10)
                goto usage;
            break;
        case 'k':
            kernel_metric = parse_nat(optarg);
            if(kernel_metric < 0 || kernel_metric > 0xFFFF)
                goto usage;
            break;
        case 'A':
            allow_duplicates = parse_nat(optarg);
            if(allow_duplicates < 0 || allow_duplicates > 0xFFFF)
                goto usage;
            break;
        case 's':
            split_horizon = 0;
            break;
        case 'u':
            keep_unfeasible = 1;
            break;
        case 'S':
            state_file = optarg;
            break;
        case 'd':
            debug = parse_nat(optarg);
            if(debug < 0)
                goto usage;
            break;
        case 'g':
#ifdef NO_LOCAL_INTERFACE
            fprintf(stderr, "Warning: no local interface in this version.\n");
#else
            local_server_port = parse_nat(optarg);
            if(local_server_port <= 0 || local_server_port > 0xFFFF)
                goto usage;
#endif
            break;
        case 'l':
            link_detect = 1;
            break;
        case 'w':
            all_wireless = 1;
            break;
        case 'z':
            {
                char *comma;
                diversity_kind = (int)strtol(optarg, &comma, 0);
                if(*comma == '\0')
                    diversity_factor = 128;
                else if(*comma == ',')
                    diversity_factor = parse_nat(comma + 1);
                else
                    goto usage;
                if(diversity_factor <= 0 || diversity_factor > 256)
                    goto usage;
            }
            break;
        case 't':
            export_table = parse_nat(optarg);
            if(export_table < 0 || export_table > 0xFFFF)
                goto usage;
            break;
        case 'T':
            import_table = parse_nat(optarg);
            if(import_table < 0 || import_table > 0xFFFF)
                goto usage;
            break;
        case 'c':
            config_file = optarg;
            break;
        case 'C':
            rc = parse_config_from_string(optarg);
            if(rc < 0) {
                fprintf(stderr,
                        "Couldn't parse configuration from command line.\n");
                exit(1);
            }
            break;
        case 'D':
            do_daemonise = 1;
            break;
        case 'L':
            logfile = optarg;
            break;
        case 'I':
            pidfile = optarg;
            break;
        default:
            goto usage;
        }
    }

    if(!config_file) {
        if(access("/etc/babeld.conf", F_OK) >= 0)
            config_file = "/etc/babeld.conf";
    }
    if(config_file) {
        rc = parse_config_from_file(config_file);
        if(rc < 0) {
            fprintf(stderr,
                    "Couldn't parse configuration from file %s.\n",
                    config_file);
            exit(1);
        }
    } else {
        if(access("/etc/babel.conf", F_OK) >= 0)
            fprintf(stderr,
                    "Warning: /etc/babel.conf exists, it will be ignored.\n");
    }

    if(default_wireless_hello_interval <= 0)
        default_wireless_hello_interval = 4000;
    default_wireless_hello_interval = MAX(default_wireless_hello_interval, 5);

    if(default_wired_hello_interval <= 0)
        default_wired_hello_interval = 4000;
    default_wired_hello_interval = MAX(default_wired_hello_interval, 5);

    resend_delay = 2000;
    resend_delay = MIN(resend_delay, default_wireless_hello_interval / 2);
    resend_delay = MIN(resend_delay, default_wired_hello_interval / 2);
    resend_delay = MAX(resend_delay, 20);

    if(do_daemonise) {
        if(logfile == NULL)
            logfile = "/var/log/babeld.log";
    }

    rc = reopen_logfile();
    if(rc < 0) {
        perror("reopen_logfile()");
        exit(1);
    }

    fd = open("/dev/null", O_RDONLY);
    if(fd < 0) {
        perror("open(null)");
        exit(1);
    }

    rc = dup2(fd, 0);
    if(rc < 0) {
        perror("dup2(null, 0)");
        exit(1);
    }

    close(fd);

    if(do_daemonise) {
        rc = daemonise();
        if(rc < 0) {
            perror("daemonise");
            exit(1);
        }
    }

    if(pidfile && pidfile[0] != '\0') {
        int pfd, len;
        char buf[100];

        len = snprintf(buf, 100, "%lu", (unsigned long)getpid());
        if(len < 0 || len >= 100) {
            perror("snprintf(getpid)");
            exit(1);
        }

        pfd = open(pidfile, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if(pfd < 0) {
            char buf[40];
            snprintf(buf, 40, "creat(%s)", pidfile);
            buf[39] = '\0';
            perror(buf);
            exit(1);
        }

        rc = write(pfd, buf, len);
        if(rc < len) {
            perror("write(pidfile)");
            goto fail_pid;
        }

        close(pfd);
    }

    rc = kernel_setup(1);
    if(rc < 0) {
        fprintf(stderr, "kernel_setup failed.\n");
        goto fail_pid;
    }

    rc = kernel_setup_socket(1);
    if(rc < 0) {
        fprintf(stderr, "kernel_setup_socket failed.\n");
        kernel_setup(0);
        goto fail_pid;
    }

    rc = finalise_config();
    if(rc < 0) {
        fprintf(stderr, "Couldn't finalise configuration.\n");
        goto fail;
    }

    for(i = optind; i < argc; i++) {
        vrc = add_interface(argv[i], NULL);
        if(vrc == NULL)
            goto fail;
    }

    if(interfaces == NULL) {
        fprintf(stderr, "Eek... asked to run on no interfaces!\n");
        goto fail;
    }

    FOR_ALL_INTERFACES(ifp) {
        /* ifp->ifindex is not necessarily valid at this point */
        int ifindex = if_nametoindex(ifp->name);
        if(ifindex > 0) {
            unsigned char eui[8];
            rc = if_eui64(ifp->name, ifindex, eui);
            if(rc < 0)
                continue;
            memcpy(myid, eui, 8);
            goto have_id;
        }
    }

    /* We failed to get a global EUI64 from the interfaces we were given.
       Let's try to find an interface with a MAC address. */
    for(i = 1; i < 256; i++) {
        char buf[IF_NAMESIZE], *ifname;
        unsigned char eui[8];
        ifname = if_indextoname(i, buf);
        if(ifname == NULL)
            continue;
        rc = if_eui64(ifname, i, eui);
        if(rc < 0)
            continue;
        memcpy(myid, eui, 8);
        goto have_id;
    }

    fprintf(stderr,
            "Warning: couldn't find router id -- using random value.\n");

    rc = read_random_bytes(myid, 8);
    if(rc < 0) {
        perror("read(random)");
        goto fail;
    }
    /* Clear group and global bits */
    myid[0] &= ~3;

 have_id:
    myseqno = (random() & 0xFFFF);

    fd = open(state_file, O_RDONLY);
    if(fd < 0 && errno != ENOENT)
        perror("open(babel-state)");
    rc = unlink(state_file);
    if(fd >= 0 && rc < 0) {
        perror("unlink(babel-state)");
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
                unsigned char sid[8];
                rc = parse_eui64(buf2, sid);
                if(rc < 0) {
                    fprintf(stderr, "Couldn't parse babel-state.\n");
                } else {
                    struct timeval realnow;
                    debugf("Got %s %d %ld from babel-state.\n",
                           format_eui64(sid), s, t);
                    gettimeofday(&realnow, NULL);
                    if(memcmp(sid, myid, 8) == 0)
                        myseqno = seqno_plus(s, 1);
                    else
                        fprintf(stderr, "ID mismatch in babel-state.\n");
                }
            } else {
                fprintf(stderr, "Couldn't parse babel-state.\n");
            }
        }
        close(fd);
        fd = -1;
    }

    protocol_socket = babel_socket(protocol_port);
    if(protocol_socket < 0) {
        perror("Couldn't create link local socket");
        goto fail;
    }

#ifndef NO_LOCAL_INTERFACE
    if(local_server_port >= 0) {
        local_server_socket = tcp_server_socket(local_server_port, 1);
        if(local_server_socket < 0) {
            perror("local_server_socket");
            goto fail;
        }
    }
#endif

    init_signals();
    rc = resize_receive_buffer(1500);
    if(rc < 0)
        goto fail;
    check_interfaces();
    if(receive_buffer == NULL)
        goto fail;

    rc = check_xroutes(0);
    if(rc < 0)
        fprintf(stderr, "Warning: couldn't check exported routes.\n");
    kernel_routes_changed = 0;
    kernel_link_changed = 0;
    kernel_addr_changed = 0;
    kernel_dump_time = now.tv_sec + roughly(30);
    schedule_neighbours_check(5000, 1);
    expiry_time = now.tv_sec + roughly(30);
    source_expiry_time = now.tv_sec + roughly(300);

    /* Make some noise so that others notice us, and send retractions in
       case we were restarted recently */
    FOR_ALL_INTERFACES(ifp) {
        if(!if_up(ifp))
            continue;
        /* Apply jitter before we send the first message. */
        usleep(roughly(10000));
        gettime(&now);
        send_hello(ifp);
        send_wildcard_retraction(ifp);
    }

    FOR_ALL_INTERFACES(ifp) {
        if(!if_up(ifp))
            continue;
        usleep(roughly(10000));
        gettime(&now);
        send_hello(ifp);
        send_wildcard_retraction(ifp);
        send_self_update(ifp);
        send_request(ifp, NULL, 0);
        flushupdates(ifp);
        flushbuf(ifp);
    }

    debugf("Entering main loop.\n");

    while(1) {
        struct timeval tv;
        fd_set readfds;

        gettime(&now);

        tv = check_neighbours_timeout;
        timeval_min_sec(&tv, expiry_time);
        timeval_min_sec(&tv, source_expiry_time);
        timeval_min_sec(&tv, kernel_dump_time);
        timeval_min(&tv, &resend_time);
        FOR_ALL_INTERFACES(ifp) {
            if(!if_up(ifp))
                continue;
            timeval_min(&tv, &ifp->flush_timeout);
            timeval_min(&tv, &ifp->hello_timeout);
            timeval_min(&tv, &ifp->update_timeout);
            timeval_min(&tv, &ifp->update_flush_timeout);
        }
        timeval_min(&tv, &unicast_flush_timeout);
        FD_ZERO(&readfds);
        if(timeval_compare(&tv, &now) > 0) {
            int maxfd = 0;
            timeval_minus(&tv, &tv, &now);
            FD_SET(protocol_socket, &readfds);
            maxfd = MAX(maxfd, protocol_socket);
            if(kernel_socket < 0) kernel_setup_socket(1);
            if(kernel_socket >= 0) {
                FD_SET(kernel_socket, &readfds);
                maxfd = MAX(maxfd, kernel_socket);
            }
#ifndef NO_LOCAL_INTERFACE
            if(local_socket >= 0) {
                FD_SET(local_socket, &readfds);
                maxfd = MAX(maxfd, local_socket);
            } else if(local_server_socket >= 0) {
                FD_SET(local_server_socket, &readfds);
                maxfd = MAX(maxfd, local_server_socket);
            }
#endif
            rc = select(maxfd + 1, &readfds, NULL, NULL, &tv);
            if(rc < 0) {
                if(errno != EINTR) {
                    perror("select");
                    sleep(1);
                }
                rc = 0;
                FD_ZERO(&readfds);
            }
        }

        gettime(&now);

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
                FOR_ALL_INTERFACES(ifp) {
                    if(!if_up(ifp))
                        continue;
                    if(ifp->ifindex == sin6.sin6_scope_id) {
                        parse_packet((unsigned char*)&sin6.sin6_addr, ifp,
                                     receive_buffer, rc);
                        VALGRIND_MAKE_MEM_UNDEFINED(receive_buffer,
                                                    receive_buffer_size);
                        break;
                    }
                }
            }
        }

#ifndef NO_LOCAL_INTERFACE
        if(local_server_socket >= 0 &&
           FD_ISSET(local_server_socket, &readfds)) {
            if(local_socket >= 0) {
                close(local_socket);
                local_socket = -1;
            }
            local_socket = accept(local_server_socket, NULL, NULL);
            if(local_socket < 0) {
                if(errno != EINTR && errno != EAGAIN)
                    perror("accept(local_server_socket)");
            } else {
                local_notify_all();
            }
        }

        if(local_socket >= 0 && FD_ISSET(local_socket, &readfds)) {
            rc = local_read(local_socket);
            if(rc <= 0) {
                if(rc < 0)
                    perror("read(local_socket)");
                close(local_socket);
                local_socket = -1;
            }
        }
#endif

        if(reopening) {
            kernel_dump_time = now.tv_sec;
            check_neighbours_timeout = now;
            expiry_time = now.tv_sec;
            rc = reopen_logfile();
            if(rc < 0) {
                perror("reopen_logfile");
                break;
            }
            reopening = 0;
        }

        if(kernel_link_changed || kernel_addr_changed) {
            check_interfaces();
            kernel_link_changed = 0;
        }

        if(kernel_routes_changed || kernel_addr_changed ||
           now.tv_sec >= kernel_dump_time) {
            rc = check_xroutes(1);
            if(rc < 0)
                fprintf(stderr, "Warning: couldn't check exported routes.\n");
            kernel_routes_changed = kernel_addr_changed = 0;
            if(kernel_socket >= 0)
                kernel_dump_time = now.tv_sec + roughly(300);
            else
                kernel_dump_time = now.tv_sec + roughly(30);
        }

        if(timeval_compare(&check_neighbours_timeout, &now) < 0) {
            int msecs;
            msecs = check_neighbours();
            msecs = MAX(msecs, 10);
            schedule_neighbours_check(msecs, 1);
        }

        if(now.tv_sec >= expiry_time) {
            check_interfaces();
            expire_routes();
            expire_resend();
            expiry_time = now.tv_sec + roughly(30);
        }

        if(now.tv_sec >= source_expiry_time) {
            expire_sources();
            source_expiry_time = now.tv_sec + roughly(300);
        }

        FOR_ALL_INTERFACES(ifp) {
            if(!if_up(ifp))
                continue;
            if(timeval_compare(&now, &ifp->hello_timeout) >= 0)
                send_hello(ifp);
            if(timeval_compare(&now, &ifp->update_timeout) >= 0)
                send_update(ifp, 0, NULL, 0);
            if(timeval_compare(&now, &ifp->update_flush_timeout) >= 0)
                flushupdates(ifp);
        }

        if(resend_time.tv_sec != 0) {
            if(timeval_compare(&now, &resend_time) >= 0)
                do_resend();
        }

        if(unicast_flush_timeout.tv_sec != 0) {
            if(timeval_compare(&now, &unicast_flush_timeout) >= 0)
                flush_unicast(1);
        }

        FOR_ALL_INTERFACES(ifp) {
            if(!if_up(ifp))
                continue;
            if(ifp->flush_timeout.tv_sec != 0) {
                if(timeval_compare(&now, &ifp->flush_timeout) >= 0)
                    flushbuf(ifp);
            }
        }

        if(UNLIKELY(debug || dumping)) {
            dump_tables(stdout);
            dumping = 0;
        }
    }

    debugf("Exiting...\n");
    usleep(roughly(10000));
    gettime(&now);

    /* We need to flush so interface_up won't try to reinstall. */
    flush_all_routes();

    FOR_ALL_INTERFACES(ifp) {
        if(!if_up(ifp))
            continue;
        send_wildcard_retraction(ifp);
        /* Make sure that we expire quickly from our neighbours'
           association caches. */
        send_hello_noupdate(ifp, 10);
        flushbuf(ifp);
        usleep(roughly(1000));
        gettime(&now);
    }
    FOR_ALL_INTERFACES(ifp) {
        if(!if_up(ifp))
            continue;
        /* Make sure they got it. */
        send_wildcard_retraction(ifp);
        send_hello_noupdate(ifp, 1);
        flushbuf(ifp);
        usleep(roughly(10000));
        gettime(&now);
        interface_up(ifp, 0);
    }
    kernel_setup_socket(0);
    kernel_setup(0);

    fd = open(state_file, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0) {
        perror("creat(babel-state)");
        unlink(state_file);
    } else {
        struct timeval realnow;
        char buf[100];
        gettimeofday(&realnow, NULL);
        rc = snprintf(buf, 100, "%s %d %ld\n",
                      format_eui64(myid), (int)myseqno,
                      (long)realnow.tv_sec);
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
    if(pidfile)
        unlink(pidfile);
    debugf("Done.\n");
    return 0;

 usage:
    fprintf(stderr,
            "Syntax: %s "
            "[-m multicast_address] [-p port] [-S state-file]\n"
            "                "
            "[-h hello] [-H wired_hello] [-z kind[,factor]]\n"
            "                "
            "[-k metric] [-A metric] [-s] [-l] [-w] [-u] [-g port]\n"
            "                "
            "[-t table] [-T table] [-c file] [-C statement]\n"
            "                "
            "[-d level] [-D] [-L logfile] [-I pidfile]\n"
            "                "
            "[id] interface...\n",
            argv[0]);
    exit(1);

 fail:
    FOR_ALL_INTERFACES(ifp) {
        if(!if_up(ifp))
            continue;
        interface_up(ifp, 0);
    }
    kernel_setup_socket(0);
    kernel_setup(0);
 fail_pid:
    if(pidfile)
        unlink(pidfile);
    exit(1);
}

/* Schedule a neighbours check after roughly 3/2 times msecs have elapsed. */
void
schedule_neighbours_check(int msecs, int override)
{
    struct timeval timeout;

    timeval_add_msec(&timeout, &now, roughly(msecs * 3 / 2));
    if(override)
        check_neighbours_timeout = timeout;
    else
        timeval_min(&check_neighbours_timeout, &timeout);
}

int
resize_receive_buffer(int size)
{
    if(size <= receive_buffer_size)
        return 0;

    if(receive_buffer == NULL) {
        receive_buffer = malloc(size);
        if(receive_buffer == NULL) {
            perror("malloc(receive_buffer)");
            return -1;
        }
        receive_buffer_size = size;
    } else {
        unsigned char *new;
        new = realloc(receive_buffer, size);
        if(new == NULL) {
            perror("realloc(receive_buffer)");
            return -1;
        }
        receive_buffer = new;
        receive_buffer_size = size;
    }
    return 1;
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
sigreopening(int signo)
{
    reopening = 1;
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
    sa.sa_handler = SIG_IGN;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigreopening;
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
dump_route_callback(struct babel_route *route, void *closure)
{
    FILE *out = (FILE*)closure;
    const unsigned char *nexthop =
        memcmp(route->nexthop, route->neigh->address, 16) == 0 ?
        NULL : route->nexthop;
    char channels[100];

    if(route->channels[0] == 0)
        channels[0] = '\0';
    else {
        int k, j = 0;
        snprintf(channels, 100, " chan (");
        j = strlen(channels);
        for(k = 0; k < DIVERSITY_HOPS; k++) {
            if(route->channels[k] == 0)
                break;
            if(k > 0)
                channels[j++] = ',';
            snprintf(channels + j, 100 - j, "%d", route->channels[k]);
            j = strlen(channels);
        }
        snprintf(channels + j, 100 - j, ")");
        if(k == 0)
            channels[0] = '\0';
    }

    fprintf(out, "%s metric %d refmetric %d id %s seqno %d%s age %d "
            "via %s neigh %s%s%s%s\n",
            format_prefix(route->src->prefix, route->src->plen),
            route_metric(route), route->refmetric,
            format_eui64(route->src->id),
            (int)route->seqno,
            channels,
            (int)(now.tv_sec - route->time),
            route->neigh->ifp->name,
            format_address(route->neigh->address),
            nexthop ? " nexthop " : "",
            nexthop ? format_address(nexthop) : "",
            route->installed ? " (installed)" :
            route_feasible(route) ? " (feasible)" : "");
}

static void
dump_xroute_callback(struct xroute *xroute, void *closure)
{
    FILE *out = (FILE*)closure;
    fprintf(out, "%s metric %d (exported)\n",
            format_prefix(xroute->prefix, xroute->plen),
            xroute->metric);
}

static void
dump_tables(FILE *out)
{
    struct neighbour *neigh;

    fprintf(out, "\n");

    fprintf(out, "My id %s seqno %d\n", format_eui64(myid), myseqno);

    FOR_ALL_NEIGHBOURS(neigh) {
        fprintf(out, "Neighbour %s dev %s reach %04x rxcost %d txcost %d chan %d%s.\n",
                format_address(neigh->address),
                neigh->ifp->name,
                neigh->reach,
                neighbour_rxcost(neigh),
                neigh->txcost,
                neigh->ifp->channel,
                if_up(neigh->ifp) ? "" : " (down)");
    }
    for_all_xroutes(dump_xroute_callback, out);
    for_all_routes(dump_route_callback, out);
    fflush(out);
}

static int
reopen_logfile()
{
    int lfd, rc;

    if(logfile == NULL)
        return 0;

    lfd = open(logfile, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if(lfd < 0)
        return -1;

    fflush(stdout);
    fflush(stderr);

    rc = dup2(lfd, 1);
    if(rc < 0)
        return -1;

    rc = dup2(lfd, 2);
    if(rc < 0)
        return -1;

    if(lfd > 2)
        close(lfd);

    return 1;
}

static int
kernel_routes_callback(int changed, void *closure)
{
    if (changed & CHANGE_LINK)
        kernel_link_changed = 1;
    if (changed & CHANGE_ADDR)
        kernel_addr_changed = 1;
    if (changed & CHANGE_ROUTE)
        kernel_routes_changed = 1;
    return 1;
}
