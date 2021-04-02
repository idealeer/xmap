/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_IP_TARGET_FILE_H
#define XMAP_IP_TARGET_FILE_H

#include <gmp.h>
#include <stdint.h>

#include "iterator.h"

int64_t ip_target_file_init(char *file);

int ip_target_set_thread_pos(iterator_t *it);

int ip_target_file_get_ip(void *ip, shard_t *shard);

port_h_t ip_target_file_get_port(shard_t *shard);

#endif // XMAP_IP_TARGET_FILE_H
