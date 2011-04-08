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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "babeld.h"
#include "util.h"
#include "net.h"
#include "network.h"
#include "source.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "resend.h"
#include "message.h"
#include "config.h"
#include "kernel.h"

unsigned char packet_header[4] = {42, 2};

int parasitic = 0;
int split_horizon = 1;

unsigned short myseqno = 0;
struct timeval seqno_time = {0, 0};

#define UNICAST_BUFSIZE 1024
int unicast_buffered = 0;
unsigned char *unicast_buffer = NULL;
struct neighbour *unicast_neighbour = NULL;
struct timeval unicast_flush_timeout = {0, 0};

static const unsigned char v4prefix[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };
static const unsigned char ll_prefix[16] =
    {0xFE, 0x80};

static int
network_prefix(int ae, int plen, unsigned int omitted,
               const unsigned char *p, const unsigned char *dp,
               unsigned int len, unsigned char *p_r)
{
    unsigned pb;
    unsigned char prefix[16];

    if(plen >= 0)
        pb = (plen + 7) / 8;
    else if(ae == 1)
        pb = 4;
    else
        pb = 16;

    if(pb > 16)
        return -1;

    memset(prefix, 0, 16);

    switch(ae) {
    case 0: break;
    case 1:
        if(omitted > 4 || pb > 4 || (pb > omitted && len < pb - omitted))
            return -1;
        memcpy(prefix, v4prefix, 12);
        if(omitted) {
            if (dp == NULL || !v4mapped(dp)) return -1;
            memcpy(prefix, dp, 12 + omitted);
        }
        if(pb > omitted) memcpy(prefix + 12 + omitted, p, pb);
        break;
    case 2:
        if(omitted > 16 || (pb > omitted && len < pb - omitted)) return -1;
        if(omitted) {
            if (dp == NULL || v4mapped(dp)) return -1;
            memcpy(prefix, dp, omitted);
        }
        if(pb > omitted) memcpy(prefix + omitted, p, pb - omitted);
        break;
    case 3:
        if(pb > 8 && len < pb - 8) return -1;
        prefix[0] = 0xfe;
        prefix[1] = 0x80;
        if(pb > 8) memcpy(prefix + 8, p, pb - 8);
        break;
    default:
        return -1;
    }

    mask_prefix(p_r, prefix, plen < 0 ? 128 : ae == 1 ? plen + 96 : plen);
    return 1;
}

static int
network_address(int ae, const unsigned char *a, unsigned int len,
                unsigned char *a_r)
{
    return network_prefix(ae, -1, 0, a, NULL, len, a_r);
}

void
parse_packet(const unsigned char *from, struct network *net,
             const unsigned char *packet, int packetlen)
{
    int i;
    const unsigned char *message;
    unsigned char type, len;
    int bodylen;
    struct neighbour *neigh;
    int have_router_id = 0, have_v4_prefix = 0, have_v6_prefix = 0,
        have_v4_nh = 0, have_v6_nh = 0;
    unsigned char router_id[8], v4_prefix[16], v6_prefix[16],
        v4_nh[16], v6_nh[16];


    if(from[0] != 0xFE || (from[1] & 0xC0) != 0x80) {
        fprintf(stderr, "Received packet from non-local address %s.\n",
                format_address(from));
        return;
    }

    if(packet[0] != 42) {
        fprintf(stderr, "Received malformed packet on %s from %s.\n",
                net->ifname, format_address(from));
        return;
    }

    if(packet[1] != 2) {
        fprintf(stderr,
                "Received packet with unknown version %d on %s from %s.\n",
                packet[1], net->ifname, format_address(from));
        return;
    }

    neigh = find_neighbour(from, net);
    if(neigh == NULL) {
        fprintf(stderr, "Couldn't allocate neighbour.\n");
        return;
    }

    DO_NTOHS(bodylen, packet + 2);

    if(bodylen + 4 > packetlen) {
        fprintf(stderr, "Received truncated packet (%d + 4 > %d).\n",
                bodylen, packetlen);
        bodylen = packetlen - 4;
    }

    i = 0;
    while(i < bodylen) {
        message = packet + 4 + i;
        type = message[0];
        if(type == MESSAGE_PAD1) {
            debugf("Received pad1 from %s on %s.\n",
                   format_address(from), net->ifname);
            i++;
            continue;
        }
        if(i + 1 > bodylen) {
            fprintf(stderr, "Received truncated message.\n");
            break;
        }
        len = message[1];
        if(i + len > bodylen) {
            fprintf(stderr, "Received truncated message.\n");
            break;
        }

        if(type == MESSAGE_PADN) {
            debugf("Received pad%d from %s on %s.\n",
                   len, format_address(from), net->ifname);
        } else if(type == MESSAGE_ACK_REQ) {
            unsigned short nonce, interval;
            if(len < 6) goto fail;
            DO_NTOHS(nonce, message + 4);
            DO_NTOHS(interval, message + 6);
            debugf("Received ack-req (%04X %d) from %s on %s.\n",
                   nonce, interval, format_address(from), net->ifname);
            send_ack(neigh, nonce, interval);
        } else if(type == MESSAGE_ACK) {
            debugf("Received ack from %s on %s.\n",
                   format_address(from), net->ifname);
            /* Nothing right now */
        } else if(type == MESSAGE_HELLO) {
            unsigned short seqno, interval;
            int changed;
            if(len < 6) goto fail;
            DO_NTOHS(seqno, message + 4);
            DO_NTOHS(interval, message + 6);
            debugf("Received hello %d (%d) from %s on %s.\n",
                   seqno, interval,
                   format_address(from), net->ifname);
            net->activity_time = now.tv_sec;
            update_hello_interval(net);
            changed = update_neighbour(neigh, seqno, interval);
            if(changed)
                update_neighbour_metric(neigh);
            if(interval > 0)
                schedule_neighbours_check(interval * 10, 0);
        } else if(type == MESSAGE_IHU) {
            unsigned short txcost, interval;
            unsigned char address[16];
            int rc;
            if(len < 6) goto fail;
            DO_NTOHS(txcost, message + 4);
            DO_NTOHS(interval, message + 6);
            rc = network_address(message[2], message + 8, len - 6, address);
            if(rc < 0) goto fail;
            debugf("Received ihu %d (%d) from %s on %s for %s.\n",
                   txcost, interval,
                   format_address(from), net->ifname,
                   format_address(address));
            if(message[2] == 0 || network_ll_address(net, address)) {
                neigh->txcost = txcost;
                neigh->ihu_time = now;
                neigh->ihu_interval = interval;
                update_neighbour_metric(neigh);
                if(interval > 0)
                    schedule_neighbours_check(interval * 10 * 3, 0);
            }
        } else if(type == MESSAGE_ROUTER_ID) {
            if(len < 10) {
                have_router_id = 0;
                goto fail;
            }
            memcpy(router_id, message + 4, 8);
            have_router_id = 1;
            debugf("Received router-id %s from %s on %s.\n",
                   format_eui64(router_id), format_address(from), net->ifname);
        } else if(type == MESSAGE_NH) {
            unsigned char nh[16];
            int rc;
            if(len < 2) {
                have_v4_nh = 0;
                have_v6_nh = 0;
                goto fail;
            }
            rc = network_address(message[2], message + 4, len - 2,
                                 nh);
            if(rc < 0) {
                have_v4_nh = 0;
                have_v6_nh = 0;
                goto fail;
            }
            debugf("Received nh %s (%d) from %s on %s.\n",
                   format_address(nh), message[2],
                   format_address(from), net->ifname);
            if(message[2] == 1) {
                memcpy(v4_nh, nh, 16);
                have_v4_nh = 1;
            } else {
                memcpy(v6_nh, nh, 16);
                have_v6_nh = 1;
            }
        } else if(type == MESSAGE_UPDATE) {
            unsigned char prefix[16], *nh;
            unsigned char plen;
            unsigned short interval, seqno, metric;
            int rc;
            if(len < 10) {
                if(len < 2 || message[3] & 0x80)
                    have_v4_prefix = have_v6_prefix = 0;
                goto fail;
            }
            DO_NTOHS(interval, message + 6);
            DO_NTOHS(seqno, message + 8);
            DO_NTOHS(metric, message + 10);
            if(message[5] == 0 ||
               (message[3] == 1 ? have_v4_prefix : have_v6_prefix))
                rc = network_prefix(message[2], message[4], message[5],
                                    message + 12,
                                    message[2] == 1 ? v4_prefix : v6_prefix,
                                    len - 10, prefix);
            else
                rc = -1;
            if(rc < 0) {
                if(message[3] & 0x80)
                    have_v4_prefix = have_v6_prefix = 0;
                goto fail;
            }

            plen = message[4] + (message[2] == 1 ? 96 : 0);

            if(message[3] & 0x80) {
                if(message[2] == 1) {
                    memcpy(v4_prefix, prefix, 16);
                    have_v4_prefix = 1;
                } else {
                    memcpy(v6_prefix, prefix, 16);
                    have_v6_prefix = 1;
                }
            }
            if(message[3] & 0x40) {
                if(message[2] == 1) {
                    memset(router_id, 0, 4);
                    memcpy(router_id + 4, prefix + 12, 4);
                } else {
                    memcpy(router_id, prefix + 8, 8);
                }
                have_router_id = 1;
            }
            if(!have_router_id && message[2] != 0) {
                fprintf(stderr, "Received prefix with no router id.\n");
                goto fail;
            }
            debugf("Received update%s%s for %s from %s on %s.\n",
                   (message[3] & 0x80) ? "/prefix" : "",
                   (message[3] & 0x40) ? "/id" : "",
                   format_prefix(prefix, plen),
                   format_address(from), net->ifname);

            if(message[2] == 0) {
                if(metric < 0xFFFF) {
                    fprintf(stderr,
                            "Received wildcard update with finite metric.\n");
                    goto done;
                }
                retract_neighbour_routes(neigh);
                goto done;
            } else if(message[2] == 1) {
                if(!have_v4_nh)
                    goto fail;
                nh = v4_nh;
            } else if(have_v6_nh) {
                nh = v6_nh;
            } else {
                nh = neigh->address;
            }

            if(message[2] == 1) {
                if(!net->ipv4)
                    goto done;
            }

            update_route(router_id, prefix, plen, seqno, metric, interval,
                         neigh, nh);
        } else if(type == MESSAGE_REQUEST) {
            unsigned char prefix[16], plen;
            int rc;
            if(len < 2) goto fail;
            rc = network_prefix(message[2], message[3], 0,
                                message + 4, NULL, len - 2, prefix);
            if(rc < 0) goto fail;
            plen = message[3] + (message[2] == 1 ? 96 : 0);
            debugf("Received request for %s from %s on %s.\n",
                   message[2] == 0 ? "any" : format_prefix(prefix, plen),
                   format_address(from), net->ifname);
            if(message[2] == 0) {
                /* If a neighbour is requesting a full route dump from us,
                   we might as well send it an IHU. */
                send_ihu(neigh, NULL);
                send_update(neigh->network, 0, NULL, 0);
            } else {
                send_update(neigh->network, 0, prefix, plen);
            }
        } else if(type == MESSAGE_MH_REQUEST) {
            unsigned char prefix[16], plen;
            unsigned short seqno;
            int rc;
            if(len < 14) goto fail;
            DO_NTOHS(seqno, message + 4);
            rc = network_prefix(message[2], message[3], 0,
                                message + 16, NULL, len - 14, prefix);
            if(rc < 0) goto fail;
            plen = message[3] + (message[2] == 1 ? 96 : 0);
            debugf("Received request (%d) for %s from %s on %s (%s, %d).\n",
                   message[6],
                   format_prefix(prefix, plen),
                   format_address(from), net->ifname,
                   format_eui64(message + 8), seqno);
            handle_request(neigh, prefix, plen, message[6],
                           seqno, message + 8);
        } else {
            debugf("Received unknown packet type %d from %s on %s.\n",
                   type, format_address(from), net->ifname);
        }
    done:
        i += len + 2;
        continue;

    fail:
        fprintf(stderr, "Couldn't parse packet (%d, %d) from %s on %s.\n",
                message[0], message[1], format_address(from), net->ifname);
        goto done;
    }
    return;
}

/* Under normal circumstances, there are enough moderation mechanisms
   elsewhere in the protocol to make sure that this last-ditch check
   should never trigger.  But I'm superstitious. */

static int
check_bucket(struct network *net)
{
    if(net->bucket <= 0) {
        int seconds = now.tv_sec - net->bucket_time;
        if(seconds > 0) {
            net->bucket = MIN(BUCKET_TOKENS_MAX,
                              seconds * BUCKET_TOKENS_PER_SEC);
        }
        /* Reset bucket time unconditionally, in case clock is stepped. */
        net->bucket_time = now.tv_sec;
    }

    if(net->bucket > 0) {
        net->bucket--;
        return 1;
    } else {
        return 0;
    }
}

void
flushbuf(struct network *net)
{
    int rc;
    struct sockaddr_in6 sin6;

    assert(net->buffered <= net->bufsize);

    flushupdates(net);

    if(net->buffered > 0) {
        debugf("  (flushing %d buffered bytes on %s)\n",
               net->buffered, net->ifname);
        if(check_bucket(net)) {
            memset(&sin6, 0, sizeof(sin6));
            sin6.sin6_family = AF_INET6;
            memcpy(&sin6.sin6_addr, protocol_group, 16);
            sin6.sin6_port = htons(protocol_port);
            sin6.sin6_scope_id = net->ifindex;
            DO_HTONS(packet_header + 2, net->buffered);
            rc = babel_send(protocol_socket,
                            packet_header, sizeof(packet_header),
                            net->sendbuf, net->buffered,
                            (struct sockaddr*)&sin6, sizeof(sin6));
            if(rc < 0)
                perror("send");
        } else {
            fprintf(stderr, "Warning: bucket full, dropping packet to %s.\n",
                    net->ifname);
        }
    }
    VALGRIND_MAKE_MEM_UNDEFINED(net->sendbuf, net->bufsize);
    net->buffered = 0;
    net->have_buffered_hello = 0;
    net->have_buffered_id = 0;
    net->have_buffered_nh = 0;
    net->have_buffered_prefix = 0;
    net->flush_timeout.tv_sec = 0;
    net->flush_timeout.tv_usec = 0;
}

static void
schedule_flush(struct network *net)
{
    unsigned msecs = jitter(net, 0);
    if(net->flush_timeout.tv_sec != 0 &&
       timeval_minus_msec(&net->flush_timeout, &now) < msecs)
        return;
    delay_jitter(&net->flush_timeout, msecs);
}

static void
schedule_flush_now(struct network *net)
{
    /* Almost now */
    unsigned msecs = roughly(10);
    if(net->flush_timeout.tv_sec != 0 &&
       timeval_minus_msec(&net->flush_timeout, &now) < msecs)
        return;
    delay_jitter(&net->flush_timeout, msecs);
}

static void
schedule_unicast_flush(unsigned msecs)
{
    if(!unicast_neighbour)
        return;
    if(unicast_flush_timeout.tv_sec != 0 &&
       timeval_minus_msec(&unicast_flush_timeout, &now) < msecs)
        return;
    unicast_flush_timeout.tv_usec = (now.tv_usec + msecs * 1000) % 1000000;
    unicast_flush_timeout.tv_sec =
        now.tv_sec + (now.tv_usec / 1000 + msecs) / 1000;
}

static void
ensure_space(struct network *net, int space)
{
    if(net->bufsize - net->buffered < space)
        flushbuf(net);
}

static void
start_message(struct network *net, int type, int len)
{
    if(net->bufsize - net->buffered < len + 2)
        flushbuf(net);
    net->sendbuf[net->buffered++] = type;
    net->sendbuf[net->buffered++] = len;
}

static void
end_message(struct network *net, int type, int bytes)
{
    assert(net->buffered >= bytes + 2 &&
           net->sendbuf[net->buffered - bytes - 2] == type &&
           net->sendbuf[net->buffered - bytes - 1] == bytes);
    schedule_flush(net);
}

static void
accumulate_byte(struct network *net, unsigned char value)
{
    net->sendbuf[net->buffered++] = value;
}

static void
accumulate_short(struct network *net, unsigned short value)
{
    DO_HTONS(net->sendbuf + net->buffered, value);
    net->buffered += 2;
}

static void
accumulate_bytes(struct network *net,
                 const unsigned char *value, unsigned len)
{
    memcpy(net->sendbuf + net->buffered, value, len);
    net->buffered += len;
}

static int
start_unicast_message(struct neighbour *neigh, int type, int len)
{
    if(unicast_neighbour) {
        if(neigh != unicast_neighbour ||
           unicast_buffered + len + 2 >=
           MIN(UNICAST_BUFSIZE, neigh->network->bufsize))
            flush_unicast(0);
    }
    if(!unicast_buffer)
        unicast_buffer = malloc(UNICAST_BUFSIZE);
    if(!unicast_buffer) {
        perror("malloc(unicast_buffer)");
        return -1;
    }

    unicast_neighbour = neigh;

    unicast_buffer[unicast_buffered++] = type;
    unicast_buffer[unicast_buffered++] = len;
    return 1;
}

static void
end_unicast_message(struct neighbour *neigh, int type, int bytes)
{
    assert(unicast_neighbour == neigh && unicast_buffered >= bytes + 2 &&
           unicast_buffer[unicast_buffered - bytes - 2] == type &&
           unicast_buffer[unicast_buffered - bytes - 1] == bytes);
    schedule_unicast_flush(jitter(neigh->network, 0));
}

static void
accumulate_unicast_byte(struct neighbour *neigh, unsigned char value)
{
    unicast_buffer[unicast_buffered++] = value;
}

static void
accumulate_unicast_short(struct neighbour *neigh, unsigned short value)
{
    DO_HTONS(unicast_buffer + unicast_buffered, value);
    unicast_buffered += 2;
}

static void
accumulate_unicast_bytes(struct neighbour *neigh,
                         const unsigned char *value, unsigned len)
{
    memcpy(unicast_buffer + unicast_buffered, value, len);
    unicast_buffered += len;
}

void
send_ack(struct neighbour *neigh, unsigned short nonce, unsigned short interval)
{
    int rc;
    debugf("Sending ack (%04x) to %s on %s.\n",
           nonce, format_address(neigh->address), neigh->network->ifname);
    rc = start_unicast_message(neigh, MESSAGE_ACK, 2); if(rc < 0) return;
    accumulate_unicast_short(neigh, nonce);
    end_unicast_message(neigh, MESSAGE_ACK, 2);
    /* Roughly yields a value no larger than 3/2, so this meets the deadline */
    schedule_unicast_flush(roughly(interval * 6));
}

void
send_hello_noupdate(struct network *net, unsigned interval)
{
    /* This avoids sending multiple hellos in a single packet, which breaks
       link quality estimation. */
    if(net->have_buffered_hello)
        flushbuf(net);

    net->hello_seqno = seqno_plus(net->hello_seqno, 1);
    delay_jitter(&net->hello_timeout, net->hello_interval);

    if(!net_up(net))
        return;

    debugf("Sending hello %d (%d) to %s.\n",
           net->hello_seqno, interval, net->ifname);

    start_message(net, MESSAGE_HELLO, 6);
    accumulate_short(net, 0);
    accumulate_short(net, net->hello_seqno);
    accumulate_short(net, interval > 0xFFFF ? 0xFFFF : interval);
    end_message(net, MESSAGE_HELLO, 6);
    net->have_buffered_hello = 1;
}

void
send_hello(struct network *net)
{
    int changed;
    changed = update_hello_interval(net);
    send_hello_noupdate(net, (net->hello_interval + 9) / 10);
    /* Send full IHU every 3 hellos, and marginal IHU each time */
    if(changed || net->hello_seqno % 3 == 0)
        send_ihu(NULL, net);
    else
        send_marginal_ihu(net);
}

void
flush_unicast(int dofree)
{
    struct sockaddr_in6 sin6;
    int rc;

    if(unicast_buffered == 0)
        goto done;

    if(!net_up(unicast_neighbour->network))
        goto done;

    /* Preserve ordering of messages */
    flushbuf(unicast_neighbour->network);

    if(check_bucket(unicast_neighbour->network)) {
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        memcpy(&sin6.sin6_addr, unicast_neighbour->address, 16);
        sin6.sin6_port = htons(protocol_port);
        sin6.sin6_scope_id = unicast_neighbour->network->ifindex;
        DO_HTONS(packet_header + 2, unicast_buffered);
        rc = babel_send(protocol_socket,
                        packet_header, sizeof(packet_header),
                        unicast_buffer, unicast_buffered,
                        (struct sockaddr*)&sin6, sizeof(sin6));
        if(rc < 0)
            perror("send(unicast)");
    } else {
        fprintf(stderr,
                "Warning: bucket full, dropping unicast packet"
                "to %s if %s.\n",
                format_address(unicast_neighbour->address),
                unicast_neighbour->network->ifname);
    }

 done:
    VALGRIND_MAKE_MEM_UNDEFINED(unicast_buffer, UNICAST_BUFSIZE);
    unicast_buffered = 0;
    if(dofree && unicast_buffer) {
        free(unicast_buffer);
        unicast_buffer = NULL;
    }
    unicast_neighbour = NULL;
    unicast_flush_timeout.tv_sec = 0;
    unicast_flush_timeout.tv_usec = 0;
}

static void
really_send_update(struct network *net,
                   const unsigned char *id,
                   const unsigned char *prefix, unsigned char plen,
                   unsigned short seqno, unsigned short metric)
{
    int add_metric, v4, real_plen, omit = 0;
    const unsigned char *real_prefix;
    unsigned short flags = 0;

    if(!net_up(net))
        return;

    add_metric = output_filter(id, prefix, plen, net->ifindex);
    if(add_metric >= INFINITY)
        return;

    metric = MIN(metric + add_metric, INFINITY);
    /* Worst case */
    ensure_space(net, 20 + 12 + 28);

    v4 = plen >= 96 && v4mapped(prefix);

    if(v4) {
        if(!net->ipv4)
            return;
        if(!net->have_buffered_nh ||
           memcmp(net->buffered_nh, net->ipv4, 4) != 0) {
            start_message(net, MESSAGE_NH, 6);
            accumulate_byte(net, 1);
            accumulate_byte(net, 0);
            accumulate_bytes(net, net->ipv4, 4);
            end_message(net, MESSAGE_NH, 6);
            memcpy(net->buffered_nh, net->ipv4, 4);
            net->have_buffered_nh = 1;
        }

        real_prefix = prefix + 12;
        real_plen = plen - 96;
    } else {
        if(net->have_buffered_prefix) {
            while(omit < plen / 8 &&
                  net->buffered_prefix[omit] == prefix[omit])
                omit++;
        }
        if(!net->have_buffered_prefix || plen >= 48)
            flags |= 0x80;
        real_prefix = prefix;
        real_plen = plen;
    }

    if(!net->have_buffered_id || memcmp(id, net->buffered_id, 8) != 0) {
        if(real_plen == 128 && memcmp(real_prefix + 8, id, 8) == 0) {
            flags |= 0x40;
        } else {
            start_message(net, MESSAGE_ROUTER_ID, 10);
            accumulate_short(net, 0);
            accumulate_bytes(net, id, 8);
            end_message(net, MESSAGE_ROUTER_ID, 10);
        }
        memcpy(net->buffered_id, id, 16);
        net->have_buffered_id = 1;
    }

    start_message(net, MESSAGE_UPDATE, 10 + (real_plen + 7) / 8 - omit);
    accumulate_byte(net, v4 ? 1 : 2);
    accumulate_byte(net, flags);
    accumulate_byte(net, real_plen);
    accumulate_byte(net, omit);
    accumulate_short(net, (net->update_interval + 5) / 10);
    accumulate_short(net, seqno);
    accumulate_short(net, metric);
    accumulate_bytes(net, real_prefix + omit, (real_plen + 7) / 8 - omit);
    end_message(net, MESSAGE_UPDATE, 10 + (real_plen + 7) / 8 - omit);

    if(flags & 0x80) {
        memcpy(net->buffered_prefix, prefix, 16);
        net->have_buffered_prefix = 1;
    }
}

static int
compare_buffered_updates(const void *av, const void *bv)
{
    const struct buffered_update *a = av, *b = bv;
    int rc, v4a, v4b, ma, mb;

    rc = memcmp(a->id, b->id, 8);
    if(rc != 0)
        return rc;

    v4a = (a->plen >= 96 && v4mapped(a->prefix));
    v4b = (b->plen >= 96 && v4mapped(b->prefix));

    if(v4a > v4b)
        return 1;
    else if(v4a < v4b)
        return -1;

    ma = (!v4a && a->plen == 128 && memcmp(a->prefix + 8, a->id, 8) == 0);
    mb = (!v4b && b->plen == 128 && memcmp(b->prefix + 8, b->id, 8) == 0);

    if(ma > mb)
        return -1;
    else if(mb > ma)
        return 1;

    if(a->plen < b->plen)
        return 1;
    else if(a->plen > b->plen)
        return -1;

    return memcmp(a->prefix, b->prefix, 16);
}

void
flushupdates(struct network *net)
{
    struct xroute *xroute;
    struct route *route;
    const unsigned char *last_prefix = NULL;
    unsigned char last_plen = 0xFF;
    int i;

    if(net == NULL) {
        struct network *n;
        FOR_ALL_NETS(n)
            flushupdates(n);
        return;
    }

    if(net->num_buffered_updates > 0) {
        struct buffered_update *b = net->buffered_updates;
        int n = net->num_buffered_updates;

        net->buffered_updates = NULL;
        net->update_bufsize = 0;
        net->num_buffered_updates = 0;

        if(!net_up(net))
            goto done;

        debugf("  (flushing %d buffered updates on %s (%d))\n",
               n, net->ifname, net->ifindex);

        /* In order to send fewer update messages, we want to send updates
           with the same router-id together, with IPv6 going out before IPv4. */

        for(i = 0; i < n; i++) {
            route = find_installed_route(b[i].prefix, b[i].plen);
            if(route)
                memcpy(b[i].id, route->src->id, 8);
            else
                memcpy(b[i].id, myid, 8);
        }

        qsort(b, n, sizeof(struct buffered_update), compare_buffered_updates);

        for(i = 0; i < n; i++) {
            unsigned short seqno;
            unsigned short metric;

            /* The same update may be scheduled multiple times before it is
               sent out.  Since our buffer is now sorted, it is enough to
               compare with the previous update. */

            if(last_prefix) {
                if(b[i].plen == last_plen &&
                   memcmp(b[i].prefix, last_prefix, 16) == 0)
                    continue;
            }

            xroute = find_xroute(b[i].prefix, b[i].plen);
            route = find_installed_route(b[i].prefix, b[i].plen);

            if(xroute && (!route || xroute->metric <= kernel_metric)) {
                really_send_update(net, myid,
                                   xroute->prefix, xroute->plen,
                                   myseqno, xroute->metric);
                last_prefix = xroute->prefix;
                last_plen = xroute->plen;
            } else if(route) {
                seqno = route->seqno;
                metric = route_metric(route);
                if(metric < INFINITY)
                    satisfy_request(route->src->prefix, route->src->plen,
                                    seqno, route->src->id, net);
                if((net->flags & NET_SPLIT_HORIZON) &&
                   route->neigh->network == net)
                    continue;
                really_send_update(net, route->src->id,
                                   route->src->prefix,
                                   route->src->plen,
                                   seqno, metric);
                update_source(route->src, seqno, metric);
                last_prefix = route->src->prefix;
                last_plen = route->src->plen;
            } else {
            /* There's no route for this prefix.  This can happen shortly
               after an xroute has been retracted, so send a retraction. */
                really_send_update(net, myid, b[i].prefix, b[i].plen,
                                   myseqno, INFINITY);
            }
        }
        schedule_flush_now(net);
    done:
        free(b);
    }
    net->update_flush_timeout.tv_sec = 0;
    net->update_flush_timeout.tv_usec = 0;
}

static void
schedule_update_flush(struct network *net, int urgent)
{
    unsigned msecs;
    msecs = update_jitter(net, urgent);
    if(net->update_flush_timeout.tv_sec != 0 &&
       timeval_minus_msec(&net->update_flush_timeout, &now) < msecs)
        return;
    delay_jitter(&net->update_flush_timeout, msecs);
}

static void
buffer_update(struct network *net,
              const unsigned char *prefix, unsigned char plen)
{
    if(net->num_buffered_updates > 0 &&
       net->num_buffered_updates >= net->update_bufsize)
        flushupdates(net);

    if(net->update_bufsize == 0) {
        int n;
        assert(net->buffered_updates == NULL);
        n = MAX(net->bufsize / 16, 4);
    again:
        net->buffered_updates = malloc(n * sizeof(struct buffered_update));
        if(net->buffered_updates == NULL) {
            perror("malloc(buffered_updates)");
            if(n > 4) {
                n = 4;
                goto again;
            }
            return;
        }
        net->update_bufsize = n;
        net->num_buffered_updates = 0;
    }

    memcpy(net->buffered_updates[net->num_buffered_updates].prefix,
           prefix, 16);
    net->buffered_updates[net->num_buffered_updates].plen = plen;
    net->num_buffered_updates++;
}

void
send_update(struct network *net, int urgent,
            const unsigned char *prefix, unsigned char plen)
{
    int i;

    if(net == NULL) {
        struct network *n;
        struct route *route;
        FOR_ALL_NETS(n)
            send_update(n, urgent, prefix, plen);
        if(prefix) {
            /* Since flushupdates only deals with non-wildcard interfaces, we
               need to do this now. */
            route = find_installed_route(prefix, plen);
            if(route && route_metric(route) < INFINITY)
                satisfy_request(prefix, plen, route->src->seqno, route->src->id,
                                NULL);
        }
        return;
    }

    if(!net_up(net))
        return;

    if(prefix) {
        if(!parasitic || find_xroute(prefix, plen)) {
            debugf("Sending update to %s for %s.\n",
                   net->ifname, format_prefix(prefix, plen));
            buffer_update(net, prefix, plen);
        }
    } else {
        if(!network_idle(net)) {
            send_self_update(net);
            if(!parasitic) {
                debugf("Sending update to %s for any.\n", net->ifname);
                for(i = 0; i < numroutes; i++)
                    if(routes[i].installed)
                        buffer_update(net,
                                      routes[i].src->prefix,
                                      routes[i].src->plen);
            }
        }
        delay_jitter(&net->update_timeout, net->update_interval);
    }
    schedule_update_flush(net, urgent);
}

void
send_update_resend(struct network *net,
                   const unsigned char *prefix, unsigned char plen)
{
    int delay;

    assert(prefix != NULL);

    send_update(net, 1, prefix, plen);

    delay = 2000;
    delay = MIN(delay, wireless_hello_interval / 2);
    delay = MIN(delay, wired_hello_interval / 2);
    delay = MAX(delay, 10);
    record_resend(RESEND_UPDATE, prefix, plen, 0, 0, NULL, delay);
}

void
send_wildcard_retraction(struct network *net)
{
    if(net == NULL) {
        struct network *n;
        FOR_ALL_NETS(n)
            send_wildcard_retraction(n);
        return;
    }

    if(!net_up(net))
        return;

    start_message(net, MESSAGE_UPDATE, 10);
    accumulate_byte(net, 0);
    accumulate_byte(net, 0x40);
    accumulate_byte(net, 0);
    accumulate_byte(net, 0);
    accumulate_short(net, 0xFFFF);
    accumulate_short(net, myseqno);
    accumulate_short(net, 0xFFFF);
    end_message(net, MESSAGE_UPDATE, 10);

    net->have_buffered_id = 0;
}

void
update_myseqno()
{
    myseqno = seqno_plus(myseqno, 1);
    seqno_time = now;
}

void
send_self_update(struct network *net)
{
    int i;

    if(net == NULL) {
        struct network *n;
        FOR_ALL_NETS(n) {
            if(!net_up(n))
                continue;
            send_self_update(n);
        }
        return;
    }

    if(!network_idle(net)) {
        debugf("Sending self update to %s.\n", net->ifname);
        for(i = 0; i < numxroutes; i++)
            send_update(net, 0, xroutes[i].prefix, xroutes[i].plen);
    }
}

void
send_ihu(struct neighbour *neigh, struct network *net)
{
    int rxcost, interval;
    int ll;

    if(neigh == NULL && net == NULL) {
        struct network *n;
        FOR_ALL_NETS(n) {
            if(net_up(n))
                continue;
            send_ihu(NULL, n);
        }
        return;
    }

    if(neigh == NULL) {
        struct neighbour *ngh;
        FOR_ALL_NEIGHBOURS(ngh) {
            if(ngh->network == net)
                send_ihu(ngh, net);
        }
        return;
    }


    if(net && neigh->network != net)
        return;

    net = neigh->network;
    if(!net_up(net))
        return;

    rxcost = neighbour_rxcost(neigh);
    interval = (net->hello_interval * 3 + 9) / 10;

    /* Conceptually, an IHU is a unicast message.  We usually send them as
       multicast, since this allows aggregation into a single packet and
       avoids an ARP exchange.  If we already have a unicast message queued
       for this neighbour, however, we might as well piggyback the IHU. */
    debugf("Sending %sihu %d on %s to %s.\n",
           unicast_neighbour == neigh ? "unicast " : "",
           rxcost,
           neigh->network->ifname,
           format_address(neigh->address));

    ll = in_prefix(neigh->address, ll_prefix, 64);

    if(unicast_neighbour != neigh) {
        start_message(net, MESSAGE_IHU, ll ? 14 : 22);
        accumulate_byte(net, ll ? 3 : 2);
        accumulate_byte(net, 0);
        accumulate_short(net, rxcost);
        accumulate_short(net, interval);
        if(ll)
            accumulate_bytes(net, neigh->address + 8, 8);
        else
            accumulate_bytes(net, neigh->address, 16);
        end_message(net, MESSAGE_IHU, ll ? 14 : 22);
    } else {
        int rc;
        rc = start_unicast_message(neigh, MESSAGE_IHU, ll ? 14 : 22);
        if(rc < 0) return;
        accumulate_unicast_byte(neigh, ll ? 3 : 2);
        accumulate_unicast_byte(neigh, 0);
        accumulate_unicast_short(neigh, rxcost);
        accumulate_unicast_short(neigh, interval);
        if(ll)
            accumulate_unicast_bytes(neigh, neigh->address + 8, 8);
        else
            accumulate_unicast_bytes(neigh, neigh->address, 16);
        end_unicast_message(neigh, MESSAGE_IHU, ll ? 14 : 22);
    }
}

/* Send IHUs to all marginal neighbours */
void
send_marginal_ihu(struct network *net)
{
    struct neighbour *neigh;
    FOR_ALL_NEIGHBOURS(neigh) {
        if(net && neigh->network != net)
            continue;
        if(neigh->txcost >= 384 || (neigh->reach & 0xF000) != 0xF000)
            send_ihu(neigh, net);
    }
}

void
send_request(struct network *net,
             const unsigned char *prefix, unsigned char plen)
{
    int v4, len;

    if(net == NULL) {
        struct network *n;
        FOR_ALL_NETS(n) {
            if(net_up(n))
                continue;
            send_request(n, prefix, plen);
        }
        return;
    }

    /* make sure any buffered updates go out before this request. */
    flushupdates(net);

    if(!net_up(net))
        return;

    debugf("sending request to %s for %s.\n",
           net->ifname, prefix ? format_prefix(prefix, plen) : "any");
    v4 = plen >= 96 && v4mapped(prefix);
    len = !prefix ? 2 : v4 ? 6 : 18;

    start_message(net, MESSAGE_REQUEST, len);
    accumulate_byte(net, !prefix ? 0 : v4 ? 1 : 2);
    accumulate_byte(net, !prefix ? 0 : v4 ? plen - 96 : plen);
    if(prefix) {
        if(v4)
            accumulate_bytes(net, prefix + 12, 4);
        else
            accumulate_bytes(net, prefix, 16);
    }
    end_message(net, MESSAGE_REQUEST, len);
}

void
send_unicast_request(struct neighbour *neigh,
                     const unsigned char *prefix, unsigned char plen)
{
    int rc, v4, len;

    /* make sure any buffered updates go out before this request. */
    flushupdates(neigh->network);

    debugf("sending unicast request to %s for %s.\n",
           format_address(neigh->address),
           prefix ? format_prefix(prefix, plen) : "any");
    v4 = plen >= 96 && v4mapped(prefix);
    len = !prefix ? 2 : v4 ? 6 : 18;

    rc = start_unicast_message(neigh, MESSAGE_REQUEST, len);
    if(rc < 0) return;
    accumulate_unicast_byte(neigh, !prefix ? 0 : v4 ? 1 : 2);
    accumulate_unicast_byte(neigh, !prefix ? 0 : v4 ? plen - 96 : plen);
    if(prefix) {
        if(v4)
            accumulate_unicast_bytes(neigh, prefix + 12, 4);
        else
            accumulate_unicast_bytes(neigh, prefix, 16);
    }
    end_unicast_message(neigh, MESSAGE_REQUEST, len);
}

void
send_multihop_request(struct network *net,
                      const unsigned char *prefix, unsigned char plen,
                      unsigned short seqno, const unsigned char *id,
                      unsigned short hop_count)
{
    int v4, pb, len;

    /* Make sure any buffered updates go out before this request. */
    flushupdates(net);

    if(net == NULL) {
        struct network *n;
        FOR_ALL_NETS(n) {
            if(!net_up(n))
                continue;
            send_multihop_request(n, prefix, plen, seqno, id, hop_count);
        }
        return;
    }

    if(!net_up(net))
        return;

    debugf("Sending request (%d) on %s for %s.\n",
           hop_count, net->ifname, format_prefix(prefix, plen));
    v4 = plen >= 96 && v4mapped(prefix);
    pb = v4 ? ((plen - 96) + 7) / 8 : (plen + 7) / 8;
    len = 6 + 8 + pb;

    start_message(net, MESSAGE_MH_REQUEST, len);
    accumulate_byte(net, v4 ? 1 : 2);
    accumulate_byte(net, v4 ? plen - 96 : plen);
    accumulate_short(net, seqno);
    accumulate_byte(net, hop_count);
    accumulate_byte(net, 0);
    accumulate_bytes(net, id, 8);
    if(prefix) {
        if(v4)
            accumulate_bytes(net, prefix + 12, pb);
        else
            accumulate_bytes(net, prefix, pb);
    }
    end_message(net, MESSAGE_MH_REQUEST, len);
}

void
send_unicast_multihop_request(struct neighbour *neigh,
                              const unsigned char *prefix, unsigned char plen,
                              unsigned short seqno, const unsigned char *id,
                              unsigned short hop_count)
{
    int rc, v4, pb, len;

    /* Make sure any buffered updates go out before this request. */
    flushupdates(neigh->network);

    debugf("Sending multi-hop request to %s for %s (%d hops).\n",
           format_address(neigh->address),
           format_prefix(prefix, plen), hop_count);
    v4 = plen >= 96 && v4mapped(prefix);
    pb = v4 ? ((plen - 96) + 7) / 8 : (plen + 7) / 8;
    len = 6 + 8 + pb;

    rc = start_unicast_message(neigh, MESSAGE_MH_REQUEST, len);
    if(rc < 0) return;
    accumulate_unicast_byte(neigh, v4 ? 1 : 2);
    accumulate_unicast_byte(neigh, v4 ? plen - 96 : plen);
    accumulate_unicast_short(neigh, seqno);
    accumulate_unicast_byte(neigh, hop_count);
    accumulate_unicast_byte(neigh, 0);
    accumulate_unicast_bytes(neigh, id, 8);
    if(prefix) {
        if(v4)
            accumulate_unicast_bytes(neigh, prefix + 12, pb);
        else
            accumulate_unicast_bytes(neigh, prefix, pb);
    }
    end_unicast_message(neigh, MESSAGE_MH_REQUEST, len);
}

void
send_request_resend(struct neighbour *neigh,
                    const unsigned char *prefix, unsigned char plen,
                    unsigned short seqno, unsigned char *id)
{
    int delay;

    if(neigh)
        send_unicast_multihop_request(neigh, prefix, plen, seqno, id, 127);
    else
        send_multihop_request(NULL, prefix, plen, seqno, id, 127);

    delay = 2000;
    delay = MIN(delay, wireless_hello_interval / 2);
    delay = MIN(delay, wired_hello_interval / 2);
    delay = MAX(delay, 10);
    record_resend(RESEND_REQUEST, prefix, plen, seqno, id,
                  neigh ? neigh->network : NULL, delay);
}

void
handle_request(struct neighbour *neigh, const unsigned char *prefix,
               unsigned char plen, unsigned char hop_count,
               unsigned short seqno, const unsigned char *id)
{
    struct xroute *xroute;
    struct route *route;
    struct neighbour *successor = NULL;

    xroute = find_xroute(prefix, plen);
    route = find_installed_route(prefix, plen);

    if(xroute && (!route || xroute->metric <= kernel_metric)) {
        if(hop_count > 0 && memcmp(id, myid, 8) == 0) {
            if(seqno_compare(seqno, myseqno) > 0) {
                if(seqno_minus(seqno, myseqno) > 100) {
                    /* Hopelessly out-of-date request */
                    return;
                }
                update_myseqno();
            }
        }
        send_update(neigh->network, 1, prefix, plen);
        return;
    }

    if(route &&
       (memcmp(id, route->src->id, 8) != 0 ||
        seqno_compare(seqno, route->seqno) <= 0)) {
        send_update(neigh->network, 1, prefix, plen);
        return;
    }

    if(hop_count <= 1)
        return;

    if(route && memcmp(id, route->src->id, 8) == 0 &&
       seqno_minus(seqno, route->seqno) > 100) {
        /* Hopelessly out-of-date */
        return;
    }

    if(request_redundant(neigh->network, prefix, plen, seqno, id))
        return;

    /* Let's try to forward this request. */
    if(route && route_metric(route) < INFINITY)
        successor = route->neigh;

    if(!successor || successor == neigh) {
        /* We were about to forward a request to its requestor.  Try to
           find a different neighbour to forward the request to. */
        struct route *other_route;

        other_route = find_best_route(prefix, plen, 0, neigh);
        if(other_route && route_metric(other_route) < INFINITY)
            successor = other_route->neigh;
    }

    if(!successor || successor == neigh)
        /* Give up */
        return;

    send_unicast_multihop_request(successor, prefix, plen, seqno, id,
                                  hop_count - 1);
    record_resend(RESEND_REQUEST, prefix, plen, seqno, id,
                  neigh->network, 0);
}
