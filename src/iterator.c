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

#include "iterator.h"

#include <assert.h>
#include <pthread.h>

#include "cyclic.h"
#include "ip_target_file.h"
#include "state.h"

#include "../lib/blocklist.h"
#include "../lib/gmp-ext.h"
#include "../lib/logger.h"
#include "../lib/xalloc.h"

struct iterator {
    cycle_t         cycle;
    uint8_t         num_threads;
    shard_t *       thread_shards;
    uint8_t *       complete;
    pthread_mutex_t mutex;
    uint32_t        curr_threads;
};

// callback instance
void shard_complete_cbi(uint8_t thread_id, void *args) {
    iterator_t *it = (iterator_t *) args;
    assert(thread_id < it->num_threads);

    pthread_mutex_lock(&it->mutex);
    it->complete[thread_id] = 1;
    it->curr_threads--;

    shard_t *s = &it->thread_shards[thread_id];
    xsend.packets_sent += s->state.packets_sent;
    xsend.hosts_scanned += s->state.hosts_scanned;
    xsend.blocklisted += s->state.hosts_blocklisted;
    xsend.allowlisted += s->state.hosts_allowlisted;
    xsend.sendto_failures += s->state.packets_failed;
    xsend.packets_tried += s->state.packets_tried;

    uint8_t done = 1;
    for (uint8_t i = 0; done && (i < it->num_threads); i++) {
        done = done && it->complete[i];
    }
    if (done) {
        xsend.finish   = now();
        xsend.complete = 1;
        mpz_set(xsend.first_scanned, it->thread_shards[0].state.first_scanned);
    }

    pthread_mutex_unlock(&it->mutex);
}

iterator_t *iterator_init(uint8_t num_threads, uint16_t shard,
                          uint16_t num_shards) {
    log_debug("iterator", "iterator_init start");

    mpz_t num_addrs_ports;
    mpz_init(num_addrs_ports);
    blocklist_count_allowed_ip_port(num_addrs_ports);
    mpz_t group_min_size;
    mpz_init_set(group_min_size, num_addrs_ports);

    mpz_t two, temp;
    mpz_init_set_ui(two, 2);
    mpz_init(temp);

    iterator_t *          it    = xmalloc(sizeof(struct iterator));
    const cyclic_group_t *group = get_group(group_min_size);

    mpz_pow_ui(temp, two, xconf.max_probe_port_len);
    if (mpz_gt(num_addrs_ports, temp)) {
        mpz_sub_ui(temp, temp, 1);
        mpz_set(xsend.max_index, temp);
    } else {
        mpz_set(xsend.max_index, num_addrs_ports);
    }
    log_debug("iterator", "max index %s", mpz_to_str10(xsend.max_index));

    it->cycle         = make_cycle(group, xconf.aes);
    it->num_threads   = num_threads;
    it->curr_threads  = num_threads;
    it->thread_shards = xcalloc(num_threads, sizeof(shard_t));
    it->complete      = xcalloc(it->num_threads, sizeof(uint8_t));
    pthread_mutex_init(&it->mutex, NULL);

    for (uint8_t i = 0; i < num_threads; i++) {
        shard_init(&it->thread_shards[i], shard, num_shards, i, num_threads,
                   xsend.max_targets, xsend.max_packets, xconf.list_of_ip_count,
                   &it->cycle, shard_complete_cbi, it);
    }

    if (xconf.list_of_ips_filename) ip_target_set_thread_pos(it);

    mpz_set(xconf.generator, it->cycle.generator);

    log_debug("iterator", "iterator_init completed");

    return it;
}

uint64_t iterator_get_scanned(iterator_t *it) {
    uint64_t sent = 0;
    for (uint8_t i = 0; i < it->num_threads; i++)
        sent += it->thread_shards[i].state.hosts_scanned;

    return sent;
}

uint64_t iterator_get_sent(iterator_t *it) {
    uint64_t sent = 0;
    for (uint8_t i = 0; i < it->num_threads; i++)
        sent += it->thread_shards[i].state.packets_sent;

    return sent;
}

uint64_t iterator_get_iterations(iterator_t *it) {
    uint64_t iterations = 0;
    for (uint8_t i = 0; i < it->num_threads; i++)
        iterations += it->thread_shards[i].iterations;

    return iterations;
}

uint64_t iterator_get_fail(iterator_t *it) {
    uint32_t fails = 0;
    for (uint8_t i = 0; i < it->num_threads; i++)
        fails += it->thread_shards[i].state.packets_failed;

    return fails;
}

uint64_t iterator_get_tried(iterator_t *it) {
    uint64_t sent = 0;
    for (uint8_t i = 0; i < it->num_threads; i++)
        sent += it->thread_shards[i].state.packets_tried;

    return sent;
}

shard_t *get_shard(iterator_t *it, uint8_t thread_id) {
    assert(thread_id < it->num_threads);

    return &it->thread_shards[thread_id];
}

uint8_t get_num_threads(iterator_t *it) { return it->num_threads; }

uint32_t iterator_get_curr_send_threads(iterator_t *it) {
    assert(it);

    return it->curr_threads;
}

void iterator_free(iterator_t *it) {
    for (int i = 0; i < it->num_threads; i++)
        shard_free(&(it->thread_shards[i]));
    close_cycle(it->cycle);

    log_debug("iterator", "cleaning up");
}
