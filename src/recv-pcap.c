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

#include "recv-internal.h"

#include <assert.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined __linux__ && __linux__
#include <pcap/sll.h>
#endif

#include "probe_modules/probe_modules.h"
#include "state.h"

#include "../lib/logger.h"

#define PCAP_PROMISC 1
#define PCAP_TIMEOUT 1000

static pcap_t *pc = NULL;

void packet_cb(u_char __attribute__((__unused__)) * user,
               const struct pcap_pkthdr *p, const u_char *bytes) {
    struct timespec ts;
    if (!p) {
        return;
    }

    if (xrecv.filter_success >= xconf.max_results) {
        // Libpcap can process multiple packets per pcap_dispatch;
        // we need to throw out results once we've
        // gotten our --max-results worth.
        return;
    }

    // length of entire packet captured by libpcap
    uint32_t buflen = (uint32_t) p->caplen;
    ts.tv_sec       = p->ts.tv_sec;
    ts.tv_nsec      = p->ts.tv_usec * 1000;
    handle_packet(buflen, bytes, ts);
}

#define BPFLEN 1024

void recv_init() {
    char bpftmp[BPFLEN];
    char errbuf[PCAP_ERRBUF_SIZE];

    pc = pcap_open_live(xconf.iface, xconf.probe_module->pcap_snaplen,
                        PCAP_PROMISC, PCAP_TIMEOUT, errbuf);
    if (pc == NULL) {
        log_fatal("recv", "could not open device %s: %s", xconf.iface, errbuf);
    }
    switch (pcap_datalink(pc)) {
    case DLT_EN10MB:
        log_info("recv", "Data link layer Ethernet");
        xconf.data_link_size = sizeof(struct ether_header);
        break;
    case DLT_RAW:
        log_info("recv", "Data link RAW");
        xconf.data_link_size = 0;
        break;
#if defined __linux__ && __linux__
    case DLT_LINUX_SLL:
        log_info("recv", "Data link cooked socket");
        xconf.data_link_size = SLL_HDR_LEN;
        break;
#endif
    default:
        log_error("recv", "unknown data link layer");
    }

    struct bpf_program bpf;

    if (!xconf.send_ip_pkts) {
        snprintf(bpftmp, sizeof(bpftmp) - 1,
                 "not ether src %02x:%02x:%02x:%02x:%02x:%02x", xconf.hw_mac[0],
                 xconf.hw_mac[1], xconf.hw_mac[2], xconf.hw_mac[3],
                 xconf.hw_mac[4], xconf.hw_mac[5]);
        assert(strlen(xconf.probe_module->pcap_filter) + 10 <
               (BPFLEN - strlen(bpftmp)));
    } else {
        bpftmp[0] = 0;
    }
    if (xconf.probe_module->pcap_filter) {
        if (!xconf.send_ip_pkts) {
            strcat(bpftmp, " and (");
        } else {
            strcat(bpftmp, "(");
        }
        strcat(bpftmp, xconf.probe_module->pcap_filter);
        strcat(bpftmp, ")");
    }
    if (strcmp(bpftmp, "") != 0) {
        if (pcap_compile(pc, &bpf, bpftmp, 1, 0) < 0) {
            log_fatal("recv", "couldn't compile bpf filter");
        }
        if (pcap_setfilter(pc, &bpf) < 0) {
            log_fatal("recv", "couldn't install bpf filter");
        }
    }
    // set pcap_dispatch to not hang if it never receives any packets
    // this could occur if you ever scan a small number of hosts as
    // documented in issue #74.
    if (pcap_setnonblock(pc, 1, errbuf) == -1) {
        log_fatal("recv", "pcap_setnonblock error:%s", errbuf);
    }
}

void recv_packets() {
    int ret = pcap_dispatch(pc, -1, packet_cb, NULL);
    if (ret == -1) {
        log_fatal("recv", "pcap_dispatch error");
    } else if (ret == 0) {
        usleep(1000);
    }
}

void recv_cleanup() {
    pcap_close(pc);
    pc = NULL;
}

int recv_update_stats(void) {
    if (!pc) {
        return EXIT_FAILURE;
    }

    struct pcap_stat pcst;
    if (pcap_stats(pc, &pcst)) {
        log_error("recv", "unable to retrieve pcap statistics: %s",
                  pcap_geterr(pc));
        return EXIT_FAILURE;
    } else {
        xrecv.pcap_recv   = pcst.ps_recv;
        xrecv.pcap_drop   = pcst.ps_drop;
        xrecv.pcap_ifdrop = pcst.ps_ifdrop;
    }

    return EXIT_SUCCESS;
}
