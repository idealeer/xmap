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

#ifndef XMAP_SHARD_H
#define XMAP_SHARD_H

#include <gmp.h>
#include <stdint.h>
#include <stdio.h>

#include "../lib/types.h"
#include "cyclic.h"

#define PMAP_SHARD_DONE 0

typedef void (*shard_complete_cb)(uint8_t id, void *args);

typedef struct shard {
    struct shard_state {
        uint64_t packets_sent;
        uint64_t hosts_scanned;
        uint64_t max_hosts;
        uint64_t max_packets;
        uint64_t hosts_blocklisted;
        uint64_t hosts_allowlisted;
        uint64_t packets_failed;
        uint64_t packets_tried;
        mpz_t    first_scanned;
    } state;
    struct shard_params {
        mpz_t first;
        mpz_t last;
        mpz_t factor;
        mpz_t modulus;
    } params;
    struct shard_ip_target_file_params {
        uint64_t first;
        uint64_t last;
        uint64_t current;
        uint64_t total;
        FILE    *fp;
        long     pos;
        uint32_t port_current;
        uint32_t port_total;
        uint32_t index_current;
        uint32_t index_total;
    } ip_target_file_params;
    mpz_t             current;
    uint64_t          iterations;
    uint8_t           thread_id;
    shard_complete_cb completeCb;
    void             *args;
} shard_t;

void shard_init(shard_t *shard, uint16_t shard_idx, uint16_t num_shards,
                uint8_t thread_idx, uint8_t num_threads,
                uint64_t max_total_targets, uint64_t max_total_packets,
                uint64_t list_of_ips_count, const cycle_t *cycle,
                shard_complete_cb cb, void *args);

void shard_get_current_ip_prefix_port_index(void *prefix, shard_t *shard,
                                            port_h_t  *port_f,
                                            index_h_t *index_f);

void shard_get_next_ip_prefix_port_index(void *prefix, shard_t *shard,
                                         port_h_t *port_f, index_h_t *index_f);

void shard_free(shard_t *shard);

#endif // XMAP_SHARD_H
