/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "send.h"

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#include "iid_modules/iid_modules.h"
#include "ip_target_file.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "shard.h"
#include "state.h"
#include "validate.h"

#include "../lib/blocklist.h"
#include "../lib/gmp-ext.h"
#include "../lib/lockfd.h"
#include "../lib/logger.h"
#include "../lib/util.h"

// OS specific functions called by send_run
static inline int send_packet(sock_t sock, void *buf, int len, uint32_t idx);

static inline int send_run_init(sock_t sock);

// Include the right implementations
#if defined(PFRING)
#include "send-pfring.h"
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
    defined(__DragonFly__)
#include "send-bsd.h"
#else // LINUX
#include "send-linux.h"
#endif // __APPLE__ || __FreeBSD__ || __NetBSD__ || __DragonFly__

// The iterator over the cyclic group

// Lock for send run
static pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;

// Source IP address offset for outgoing packets
static uint32_t srcip_offset;

// Source ports for outgoing packets
static uint16_t num_src_ports;

void sig_handler_increase_speed(UNUSED int signal) {
    int old_rate = xconf.rate;
    xconf.rate += (xconf.rate * 0.05);
    log_info("send", "send rate increased from %i to %i pps.", old_rate,
             xconf.rate);
}

void sig_handler_decrease_speed(UNUSED int signal) {
    int old_rate = xconf.rate;
    xconf.rate -= (xconf.rate * 0.05);
    log_info("send", "send rate decreased from %i to %i pps.", old_rate,
             xconf.rate);
}

// global sender initialize (not thread specific)
iterator_t *send_init(void) {
    log_debug("send", "send_init for global send start.");

    // only allow bandwidth or rate
    if (xconf.bandwidth > 0 && xconf.rate > 0) {
        log_fatal("send",
                  "must specify rate or bandwidth, or neither, not both.");
    }
    // convert specified bandwidth to packet rate
    if (xconf.bandwidth > 0) {
        size_t pkt_len = xconf.probe_module->packet_length;
        pkt_len *= 8;
        // 7 byte MAC preamble, 1 byte Start frame, 4 byte CRC, 12 byte
        // inter-frame gap
        pkt_len += 8 * 24;
        // adjust calculated length if less than the minimum size of an
        // ethernet frame
        if (pkt_len < 84 * 8) {
            pkt_len = 84 * 8;
        }
        // rate is a uint32_t so, don't overflow
        if (xconf.bandwidth / pkt_len > 0xFFFFFFFFu) {
            xconf.rate = 0;
        } else {
            xconf.rate = xconf.bandwidth / pkt_len;
            if (xconf.rate == 0) {
                log_warn("send",
                         "bandwidth %lu bit/s is slower than 1 pkt/s, setting "
                         "rate to 1 pkt/s",
                         xconf.bandwidth);
                xconf.rate = 1;
            }
        }
        log_debug("send",
                  "using bandwidth %lu bits/s for %zu byte probe, rate set to "
                  "%d pkt/s",
                  xconf.bandwidth, pkt_len / 8, xconf.rate);
    }
    // convert default placeholder to default value
    if (xconf.rate == -1) {
        // default 1 pps
        xconf.rate = 1;
    }
    // log rate, if explicitly specified
    if (xconf.rate < 0) {
        log_fatal("send", "rate impossibly slow");
    }
    if (xconf.rate > 0 && xconf.bandwidth <= 0) {
        size_t pkt_len = xconf.probe_module->packet_length;
        pkt_len *= 8;
        // 7 byte MAC preamble, 1 byte Start frame, 4 byte CRC, 12 byte
        // inter-frame gap
        pkt_len += 8 * 24;
        // adjust calculated length if less than the minimum size of an
        // ethernet frame
        if (pkt_len < 84 * 8) {
            pkt_len = 84 * 8;
        }
        xconf.bandwidth = xconf.rate * pkt_len;
    }

    char rate_str[20];
    char bd_str[20];
    number_string(xconf.rate, rate_str, 20);
    bits_string(xconf.bandwidth, bd_str, 20);
    log_debug("send", "rate set to %sp/s", rate_str);
    log_debug("send", "bandwidth set to %sb/s", bd_str);

    // automatically set sender-thread-num
    /*
    if ((int) ceil(xconf.rate / 1000000.0) > xconf.senders) {
        xconf.senders = (int) ceil(xconf.rate / 1000000.0);
        log_warn("send",
                 "sender thread number is not enough to send on this rate=%d "
                 "\n\t\t\t\t (for GMP lib computing performance), automatically
    " "set sender-thread-num to %d", xconf.rate, xconf.senders); if
    (xconf.senders > xconf.pin_cores_len) log_fatal("send", "sender thread num >
    core num");
    }*/

    // generate a new primitive root and starting position
    iterator_t *it;
    uint32_t    num_subshards =
        (uint32_t) xconf.senders * (uint32_t) xconf.total_shards;
    mpz_t block_allowed_ip_port;
    mpz_init(block_allowed_ip_port);
    blocklist_count_allowed_ip_port(block_allowed_ip_port);
    if (mpz_lt_ui(block_allowed_ip_port, num_subshards)) {
        log_fatal("send", "senders * shards > allowed probing address");
    }
    if (xsend.max_targets && (num_subshards > xsend.max_targets)) {
        log_fatal("send", "senders * shards > max targets");
    }

    it = iterator_init(xconf.senders, xconf.shard_num, xconf.total_shards);

    // determine the source address offset from which we'll send packets
    char *temp_addr =
        inet_in2constr(xconf.source_ip_addresses[0], xconf.ipv46_flag);
    log_debug("send", "src_ipv%d_1st: %s", xconf.ipv46_flag, temp_addr);
    temp_addr =
        inet_in2constr(xconf.source_ip_addresses[xconf.number_source_ips - 1],
                       xconf.ipv46_flag);
    log_debug("send", "src_ipv%d_1st: %s", xconf.ipv46_flag, temp_addr);
    if (xconf.number_source_ips == 1) {
        srcip_offset = 0;
    } else {
        uint32_t offset = (uint32_t)(aesrand_getword(xconf.aes) & 0xFFFFFFFF);
        srcip_offset    = offset % (xconf.number_source_ips);
    }

    // process the source port range that XMap is allowed to use
    num_src_ports = xconf.source_port_last - xconf.source_port_first + 1;
    log_debug("send", "xmap will send from %i address%s on %u source ports",
              xconf.number_source_ips,
              ((xconf.number_source_ips == 1) ? "" : "es"), num_src_ports);

    // global initialization for send module
    assert(xconf.probe_module);
    if (xconf.probe_module->global_init) {
        if (xconf.probe_module->global_init(&xconf)) {
            log_fatal("send",
                      "global initialization for probe module (%s) failed",
                      xconf.probe_module->name);
        }
        log_debug("send", "probe module global initialize");
    }

    // global initialization for iid module
    assert(xconf.iid_module);
    if (xconf.iid_module->global_init) {
        if (xconf.iid_module->global_init(&xconf)) {
            log_fatal("send", "global initialization for iid module failed.");
        }
        log_debug("send", "iid module global initialize");
    }

    // just generate IP address
    if (xconf.dryrun) {
        log_info("send", "dryrun mode -- won't actually send packets");
    }

    // initialize random validation key
    validate_init();

    // setup signal handlers for changing scan speed
    signal(SIGUSR1, sig_handler_increase_speed);
    signal(SIGUSR2, sig_handler_decrease_speed);

    // start
    xsend.start = now();

    mpz_clear(block_allowed_ip_port);
    free(temp_addr);

    log_debug("send", "send_init for global send completed.");

    return it;
}

static inline uint8_t *get_src_ip(const uint8_t *dst, int local_offset) {
    if (xconf.number_source_ips == 1) {
        return xconf.source_ip_addresses[0];
    }

    uint8_t offset = srcip_offset + local_offset;
    int     i;
    for (i = 0; i < xconf.ipv46_bytes; i++)
        offset += dst[i];
    offset %= xconf.number_source_ips;

    return xconf.source_ip_addresses[offset];
}

// one sender thread
int send_run(sock_t st, shard_t *sd) {
    log_debug("send", "send thread started");
    pthread_mutex_lock(&send_mutex);

    // Allocate a buffer to hold the outgoing packet
    char buff[MAX_PACKET_SIZE];
    memset(buff, 0, MAX_PACKET_SIZE);

    // OS specific per-thread init
    if (send_run_init(st)) {
        return -1;
    }

    // probe thread initialize
    void *probe_data;
    if (xconf.probe_module->thread_init)
        xconf.probe_module->thread_init(buff, xconf.hw_mac, xconf.gw_mac,
                                        &probe_data);

    // iid thread initialize
    if (xconf.iid_module->thread_init) xconf.iid_module->thread_init();

    pthread_mutex_unlock(&send_mutex);

    // adaptive timing to hit target rate
    uint64_t        count      = 0;
    uint64_t        last_count = count;
    uint32_t        delay      = 0;
    int             interval   = 0;
    volatile int    vi;
    struct timespec ts, rem;
    double          send_rate =
        (double) xconf.rate / ((double) xconf.senders * xconf.batch);
    const double slow_rate = 50; // packets per seconds per thread
    // at which it uses the slow methods
    long      nsec_per_sec = 1000 * 1000 * 1000;
    long long sleep_time   = nsec_per_sec;
    double    last_time    = now();
    if (xconf.rate > 0) {
        delay = 10000;
        if (send_rate < slow_rate) {
            // set the inital time difference
            sleep_time = (double) nsec_per_sec / send_rate;
            last_time  = now() - (1.0 / send_rate);
        } else {
            // estimate initial rate, sleep for 1/rate time needs how many delay
            // times
            for (vi = delay; vi--;)
                ;
            delay *=
                1 / (now() - last_time) /
                ((double) xconf.rate / ((double) xconf.senders * xconf.batch));
            interval  = (int) (((double) xconf.rate /
                               ((double) xconf.senders * xconf.batch)) /
                              20);
            last_time = now();
        }
    }

    // Get the initial IP to scan.
    ipaddr_n_t dst_ip[xconf.ipv46_bytes];
    port_h_t   dst_port;
    memset(dst_ip, 0, xconf.ipv46_bytes);
    if (xconf.list_of_ips_filename) {
        if (ip_target_file_get_ip(dst_ip, sd) == EXIT_FAILURE)
            memset(dst_ip, 0, xconf.ipv46_bytes);
        dst_port = ip_target_file_get_port(sd);
    } else
        dst_port = shard_get_current_ip_prefix_port(dst_ip, sd);

    ipaddr_n_t current_ip_suffix[xconf.ipv46_bytes];
    uint32_t   idx = 0; // pfring buffer index
    mpz_t      temp;    // temp using
    mpz_init(temp);

    log_debug("send", "1st scanned IPv%d prefix: %s", xconf.ipv46_flag,
              inet_in2constr(dst_ip, xconf.ipv46_flag));

    int b = 0;
    // while for sending
    while (1) {
        // Check if we've finished this shard or thread before sending each
        // packet, regardless of batch size.
        if (sd->state.max_hosts &&
            sd->state.hosts_scanned >= sd->state.max_hosts) {
            log_debug("send",
                      "send thread %hhu finished (max targets of %u reached)",
                      sd->thread_id, sd->state.max_hosts);
            goto cleanup;
        }
        mpz_from_uint8s(temp, dst_ip, xconf.ipv46_bytes);
        if (mpz_eq_ui(temp, PMAP_SHARD_DONE)) {
            log_debug("send", "send thread %hhu finished, shard depleted",
                      sd->thread_id);
            goto cleanup;
        }

        // generate iid_num iid for per prefix
        for (int u = 0; u < xconf.iid_num; u++) {
            if (!xconf.list_of_ips_filename) { // not get ip from file
                xconf.iid_module->get_current_iid(current_ip_suffix, u, NULL);
                for (int k = 0; k < xconf.ipv46_bytes; k++)
                    dst_ip[k] = dst_ip[k] | current_ip_suffix[k];
            }

            // send packet_streams number of packet to per dst address
            for (int i = 0; i < xconf.packet_streams; i++) {
                // Check if the program has otherwise completed and break out of
                // the send loop.
                if (xrecv.complete) {
                    goto cleanup;
                }
                if (xconf.max_runtime &&
                    xconf.max_runtime <= now() - xsend.start) {
                    goto cleanup;
                }
                if (sd->state.max_packets &&
                    sd->state.packets_sent >= sd->state.max_packets) {
                    log_debug(
                        "send",
                        "send thread %hhu finished (max packets of %u reached)",
                        sd->thread_id, sd->state.max_packets);
                    goto cleanup;
                }

                count++;
                ipaddr_n_t *src_ip = get_src_ip(dst_ip, i);
                uint8_t     ttl    = xconf.probe_ttl;
                size_t      length = xconf.probe_module->packet_length;
                xconf.probe_module->make_packet(buff, &length, src_ip, dst_ip,
                                                dst_port, ttl, i, probe_data);
                if (length > MAX_PACKET_SIZE) {
                    log_fatal("send",
                              "send thread %hhu set length (%zu) larger than "
                              "MAX (%zu)",
                              sd->thread_id, length, MAX_PACKET_SIZE);
                }

                // sleeping, maybe send batch before sleeping
                if (b >= xconf.batch) {
                    // Adaptive timing delay
                    send_rate = (double) xconf.rate /
                                ((double) xconf.senders * xconf.batch);
                    if (count && delay > 0) {
                        if (send_rate < slow_rate) {
                            double t         = now();
                            double last_rate = (1.0 / (t - last_time));
                            sleep_time *= ((last_rate / send_rate) + 1) / 2;
                            ts.tv_sec  = sleep_time / nsec_per_sec;
                            ts.tv_nsec = sleep_time % nsec_per_sec;
                            log_debug("sleep",
                                      "sleep for %d sec, %ld nanoseconds",
                                      ts.tv_sec, ts.tv_nsec);
                            while (nanosleep(&ts, &rem) == -1) {
                            }
                            last_time = t;
                        } else {
                            for (vi = delay; vi--;)
                                ;
                            if (!interval || (count % interval == 0)) {
                                double t = now();
                                assert(count > last_count);
                                assert(t > last_time);
                                double multiplier =
                                    (double) (count - last_count) /
                                    (t - last_time) /
                                    (xconf.rate / xconf.senders);
                                uint32_t old_delay = delay;
                                delay *= multiplier;
                                if (delay == old_delay) {
                                    if (multiplier > 1.0) {
                                        delay *= 2;
                                    } else if (multiplier < 1.0) {
                                        delay *= 0.5;
                                    }
                                }
                                last_count = count;
                                last_time  = t;
                            }
                        }
                    }
                    b = 1;
                } else {
                    b++;
                }

                if (xconf.dryrun) { // just generating packet
                    lock_file(stdout);
                    xconf.probe_module->print_packet(stdout, buff);
                    unlock_file(stdout);
                } else {
                    void *contents =
                        buff +
                        xconf.send_ip_pkts *
                            sizeof(struct ether_header); // only send IP packet
                    length -=
                        (xconf.send_ip_pkts * sizeof(struct ether_header));
                    int any_sends_successful = 0;

                    // sending
                    // send one packet for attempts times until one being
                    // successful
                    for (int j = 0; j < xconf.num_retries; j++) {
                        // log_info("send", "IP=%s", inet_in2constr(dst_ip,
                        // xconf.ipv46_flag));
                        int rc =
                            send_packet(st, contents, length,
                                        idx); // idx for pfring buffer index
                        sd->state.packets_tried++;
                        if (rc < 0) { // failed
                            char addr_str[64];
                            inet_in2str(dst_ip, addr_str, 64, 6);
                            log_debug("send", "send_packet failed for %s. %s",
                                      addr_str, strerror(errno));
                        } else {
                            any_sends_successful = 1;
                            break;
                        }
                    }
                    if (!any_sends_successful) {
                        sd->state.packets_failed++;
                    }
                    idx++;
                    idx &= 0xFFu; // shifting pfring buffer index
                }

                sd->state.packets_sent++;
            }
        }

        // Track the number of hosts we actually scanned.
        sd->state.hosts_scanned++;

        // Get the next IP to scan
        if (xconf.list_of_ips_filename) {
            if (ip_target_file_get_ip(dst_ip, sd) == EXIT_FAILURE)
                memset(dst_ip, 0, xconf.ipv46_bytes);
            dst_port = ip_target_file_get_port(sd);
        } else
            dst_port = shard_get_next_ip_prefix_port(dst_ip, sd);
    }

cleanup:
    sd->completeCb(sd->thread_id, sd->args);
    if (xconf.dryrun) {
        lock_file(stdout);
        fflush(stdout);
        unlock_file(stdout);
    }
    mpz_clear(temp);
    log_debug("send", "thread %hu cleanly finished", sd->thread_id);

    return EXIT_SUCCESS;
}
