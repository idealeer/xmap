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

#ifndef XMAP_ITERATOR_H
#define XMAP_ITERATOR_H

#include <gmp.h>
#include <stdint.h>

#include "shard.h"

typedef struct iterator iterator_t;

iterator_t *iterator_init(uint8_t num_threads, uint16_t shard,
                          uint16_t num_shards);

uint64_t iterator_get_scanned(iterator_t *it);

uint64_t iterator_get_sent(iterator_t *it);

uint64_t iterator_get_iterations(iterator_t *it);

uint64_t iterator_get_fail(iterator_t *it);

uint64_t iterator_get_tried(iterator_t *it);

shard_t *get_shard(iterator_t *it, uint8_t thread_id);

uint8_t get_num_threads(iterator_t *it);

uint32_t iterator_get_curr_send_threads(iterator_t *it);

void iterator_free(iterator_t *it);

#endif // XMAP_ITERATOR_H
