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

#include "recv.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "fieldset.h"
#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"
#include "recv-internal.h"
#include "state.h"
#include "validate.h"

#include "../lib/includes.h"
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

static u_char   fake_eth_hdr[65535];
static sock_t   st;
static char     buff[MAX_PACKET_SIZE];
static void    *probe_data;
static uint32_t idx = 0; // pfring buffer index

void handle_packet(uint32_t buflen, const u_char *bytes,
                   const struct timespec ts) {
    struct ip      *ip_header;
    struct ip6_hdr *ip6_header;
    ipaddr_n_t      dst_ip[xconf.ipv46_bytes];
    memset(dst_ip, 0, xconf.ipv46_bytes);

    if (xconf.ipv46_flag == IPV6_FLAG) {
        if ((sizeof(struct ip6_hdr) + xconf.data_link_size) > buflen) {
            // buffer not large enough to contain ethernet
            // and ipv6 headers. further action would overrun buf
            return;
        }
        ip6_header = (struct ip6_hdr *) &bytes[xconf.data_link_size];
        ip_header  = (struct ip *) ip6_header;
        for (int k = 0; k < xconf.ipv46_bytes; k++)
            dst_ip[k] = ((uint8_t *) &(ip6_header->ip6_src))[k];
    } else {
        if ((sizeof(struct ip) + xconf.data_link_size) > buflen) {
            // buffer not large enough to contain ethernet
            // and ip headers. further action would overrun buf
            return;
        }
        ip_header = (struct ip *) &bytes[xconf.data_link_size];
        for (int k = 0; k < xconf.ipv46_bytes; k++)
            dst_ip[k] = ((uint8_t *) &(ip_header->ip_src))[k];
    }

    int     is_repeat = 1;
    uint8_t ttl       = xconf.probe_ttl;
    size_t  length    = xconf.probe_module->packet_length;
    int     ret       = xconf.probe_module->validate_packet(
                  ip_header,
                  buflen - (xconf.send_ip_pkts ? 0 : sizeof(struct ether_header)),
                  &is_repeat, buff, &length, ttl);
    switch (ret) {
    case PACKET_VALID:
        xrecv.validation_passed++;
        break;
    case PACKET_INVALID:
        xrecv.validation_failed++;
        return;
    case PACKET_AGAIN: {
        if (is_repeat) return;
        void *contents =
            buff + xconf.send_ip_pkts *
                       sizeof(struct ether_header); // only send IP packet
        length -= (xconf.send_ip_pkts * sizeof(struct ether_header));
        int rc = send_packet(st, contents, length,
                             idx); // idx for pfring buffer index
        if (rc < 0) {              // failed
            char addr_str[64];
            inet_in2str(dst_ip, addr_str, 64, xconf.ipv46_flag);
            log_debug("recv", "send_packet failed for %s. %s", addr_str,
                      strerror(errno));
        }
        xrecv.validation_again++;
        break;
    }
    default:
        xrecv.validation_failed++;
        return;
    }

    // track whether this is the first packet in an IP fragment.
    if (xconf.ipv46_flag == IPV4_FLAG) {
        if (ip_header->ip_off & (u_short) (IP_MF)) {
            xrecv.ip_fragments++;
        }
    }

    fieldset_t *fs = fs_new_fieldset();

    if (xconf.ipv46_flag == IPV6_FLAG) {
        fs_add_ipv6_fields(fs, ip6_header);
    } else {
        fs_add_ip_fields(fs, ip_header);
    }

    // HACK:
    // probe modules expect the full ethernet frame
    // in process_packet. For VPN, we only get back an IP frame.
    // Here, we fake an ethernet frame (which is initialized to
    // have ETH_P_IP proto and 00s for dest/src).
    if (xconf.send_ip_pkts) {
        if (buflen > sizeof(fake_eth_hdr)) {
            buflen = sizeof(fake_eth_hdr);
        }
        memcpy(&fake_eth_hdr[sizeof(struct ether_header)],
               bytes + xconf.data_link_size, buflen);
        bytes = fake_eth_hdr;
    }
    xconf.probe_module->process_packet(bytes, buflen, fs, ts);
    fs_add_system_fields(fs, is_repeat, xsend.complete);

    int success_index = xconf.fsconf.success_index;
    assert(success_index < fs->len);
    int is_success = fs_get_uint64_by_index(fs, success_index);

    if (is_success) {
        xrecv.success_total++;
        if (!is_repeat) {
            xrecv.success_unique++;
        }
        if (xsend.complete) {
            xrecv.cooldown_total++;
            if (!is_repeat) {
                xrecv.cooldown_unique++;
            }
        }
    } else {
        xrecv.failure_total++;
    }
    // probe module includes app_success field
    if (xconf.fsconf.app_success_index >= 0) {
        int is_app_success =
            fs_get_uint64_by_index(fs, xconf.fsconf.app_success_index);
        if (is_app_success) {
            xrecv.app_success_total++;
            if (!is_repeat) {
                xrecv.app_success_unique++;
            }
        }
    }

    fieldset_t *o = NULL;
    // we need to translate the data provided by the probe module
    // into a fieldset that can be used by the output module
    if (!is_success && xconf.filter_unsuccessful) {
        goto cleanup;
    }
    if (is_repeat && xconf.filter_duplicates) {
        goto cleanup;
    }
    if (!evaluate_expression(xconf.filter.expression, fs)) {
        goto cleanup;
    }
    xrecv.filter_success++;
    o = translate_fieldset(fs, &xconf.fsconf.translation);
    if (xconf.output_module && xconf.output_module->process_ip) {
        xconf.output_module->process_ip(o);
    }

cleanup:
    fs_free(fs);
    free(o);
    if (xconf.output_module && xconf.output_module->update &&
        !(xrecv.success_unique % xconf.output_module->update_interval)) {
        xconf.output_module->update(&xconf, &xsend, &xrecv);
    }
}

int recv_run(pthread_mutex_t *recv_ready_mutex, sock_t st_) {
    log_debug("recv", "recv thread started");
    log_debug("recv", "capturing responses on %s", xconf.iface);

    // for send
    st = st_;
    memset(buff, 0, MAX_PACKET_SIZE);
    if (xconf.probe_module->thread_init)
        xconf.probe_module->thread_init(buff, xconf.hw_mac, xconf.gw_mac,
                                        &probe_data);

    // OS specific send thread init
    if (send_run_init(st)) {
        return -1;
    }

    recv_init();

    if (xconf.send_ip_pkts) {
        struct ether_header *eth = (struct ether_header *) fake_eth_hdr;
        memset(fake_eth_hdr, 0, sizeof(fake_eth_hdr));
        if (xconf.ipv46_flag == IPV4_FLAG)
            eth->ether_type = htons(ETHERTYPE_IP);
        else
            eth->ether_type = htons(ETHERTYPE_IPV6);
    }

    if (xconf.filter_duplicates) {
        log_debug("recv", "duplicate responses will be excluded from output");
    } else {
        log_debug("recv", "duplicate responses will be included in output");
    }
    if (xconf.filter_unsuccessful) {
        log_debug("recv",
                  "unsuccessful responses will be excluded from output");
    } else {
        log_debug("recv", "unsuccessful responses will be included in output");
    }

    pthread_mutex_lock(recv_ready_mutex);
    xconf.recv_ready = 1;
    pthread_mutex_unlock(recv_ready_mutex);
    xrecv.start = now();
    if (xconf.max_results == 0) {
        xconf.max_results = -1;
    }

    do {
        if (xconf.dryrun) {
            sleep(1);
        } else {
            recv_packets();
            if (xconf.max_results &&
                xrecv.filter_success >= xconf.max_results) {
                break;
            }
        }
    } while (!(xsend.complete && (now() - xsend.finish > xconf.cooldown_secs)));

    xrecv.finish = now();

    // get final pcap statistics before closing
    recv_update_stats();
    if (!xconf.dryrun) {
        pthread_mutex_lock(recv_ready_mutex);
        recv_cleanup();
        pthread_mutex_unlock(recv_ready_mutex);
    }

    xrecv.complete = 1;
    log_debug("recv", "thread finished");

    return 0;
}
