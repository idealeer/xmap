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
#include "recv.h"

#include <errno.h>
#include <pfring_zc.h>
#include <unistd.h>

#include "../lib/includes.h"
#include "../lib/logger.h"
#include "state.h"

static pfring_zc_pkt_buff *pf_buffer;
static pfring_zc_queue *pf_recv;

void recv_init() {
    // Get the socket and packet handle
    pf_recv = xconf.pf.recv;
    pf_buffer = pfring_zc_get_packet_handle(xconf.pf.cluster);

    if (pf_buffer == NULL) {
        log_fatal("recv", "could not get pfring packet handle: %s", strerror(errno));
    }

    xconf.data_link_size = sizeof(struct ether_header);     // TODO case?
}

void recv_cleanup() {
    if (!pf_recv) {
        return;
    }

    pfring_zc_sync_queue(pf_recv, rx_only);
}

void recv_packets() {
    int ret;

    // Poll for packets
    ret = pfring_zc_recv_pkt(pf_recv, &pf_buffer, 0);
    if (ret == 0) {
        usleep(1000);
        return;
    }

    // Handle other errors, by not doing anything and logging
    if (ret != 1) {
        log_error("recv", "pfring error: %d", ret);
        return;
    }

    // Successfully got a packet, now handle it
    struct timespec ts;
    ts.tv_sec = pf_buffer->ts.tv_sec;
    ts.tv_nsec = pf_buffer->ts.tv_nsec;

    uint8_t *pkt_buf = pfring_zc_pkt_buff_data(pf_buffer, pf_recv);
    handle_packet(pf_buffer->len, pkt_buf, ts);
}

int recv_update_stats(void) {
    if (!pf_recv) {
        return EXIT_FAILURE;
    }

    pfring_zc_stat pfst;
    if (pfring_zc_stats(pf_recv, &pfst)) {
        log_error("recv", "unable to retrieve pfring statistics");
        return EXIT_FAILURE;
    } else {
        xrecv.pcap_recv = pfst.recv;
        xrecv.pcap_drop = pfst.drop;
    }

    return EXIT_SUCCESS;
}
