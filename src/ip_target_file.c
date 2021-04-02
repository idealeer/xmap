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

#include "ip_target_file.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "state.h"

#include "../lib/blocklist.h"
#include "../lib/logger.h"
#include "../lib/util.h"

#define LOGGER_NAME "ip_target_file"

static int ipv46_flag;

int64_t ip_target_file_init(char *file) {
    if (!file)
        log_fatal(LOGGER_NAME, "ip_target_file_init called with NULL filename");
    ipv46_flag = xconf.ipv46_flag;

    return get_file_lines(file);
}

int ip_target_set_thread_pos(iterator_t *it) {
    FILE *fp = fopen(xconf.list_of_ips_filename, "r");
    if (fp == NULL) {
        log_fatal(LOGGER_NAME,
                  "ip_target_set_thread_pos called with NULL filename");
    }

    char     line[64];
    long     pos;
    int      i           = 0;
    uint64_t count       = 0;
    shard_t *sd          = get_shard(it, i);
    uint8_t  num_threads = get_num_threads(it);
    do {
        if (sd->ip_target_file_params.first == count) {
            fgetpos(fp, (fpos_t *) &pos);
            rewind(sd->ip_target_file_params.fp);
            fseek(sd->ip_target_file_params.fp, pos, SEEK_SET);
            sd->ip_target_file_params.pos = pos;
            i++;
            if (i >= num_threads) return EXIT_SUCCESS;
            sd = get_shard(it, i);
        }
        count++;
    } while (fgets(line, sizeof(line), fp));
    fclose(fp);

    return EXIT_SUCCESS;
}

static int recover_thread_file_params(shard_t *shard) {
    if (shard->ip_target_file_params.port_current + 1 >=
        shard->ip_target_file_params.port_total)
        return EXIT_FAILURE;
    shard->ip_target_file_params.port_current++;
    shard->ip_target_file_params.current = shard->ip_target_file_params.first;
    rewind(shard->ip_target_file_params.fp);
    fseek(shard->ip_target_file_params.fp, shard->ip_target_file_params.pos,
          SEEK_SET);
    return EXIT_SUCCESS;
}

int ip_target_file_get_ip(void *ip, shard_t *shard) {
    if (shard->ip_target_file_params.current >=
        shard->ip_target_file_params.last)
        if (recover_thread_file_params(shard)) return EXIT_FAILURE;

    FILE *fp = shard->ip_target_file_params.fp;
    assert(fp);

    char  line[64];
    char *ret, *pos;

    ret = fgets(line, sizeof(line), fp);
    if (ret == NULL)
        if (recover_thread_file_params(shard)) return EXIT_FAILURE;

    shard->ip_target_file_params.current++;
    pos = strchr(line, '\n');
    if (pos != NULL) *pos = '\0';
    pos = strchr(line, '/');
    if (pos != NULL) *pos = '\0';
    if (!inet_str2in(line, ip, ipv46_flag)) {
        if (!xconf.ignore_filelist_error)
            log_fatal(LOGGER_NAME,
                      "could not parse IPv%d address from line: %s: %s",
                      ipv46_flag, line, strerror(errno));
        goto goon;
    }

    while (!blocklist_is_allowed_ip(ip)) {
    goon:
        if (shard->ip_target_file_params.current >=
            shard->ip_target_file_params.last)
            if (recover_thread_file_params(shard)) return EXIT_FAILURE;
        ret = fgets(line, sizeof(line), fp);
        if (ret == NULL)
            if (recover_thread_file_params(shard)) return EXIT_FAILURE;
        shard->ip_target_file_params.current++;
        pos = strchr(line, '\n');
        if (pos != NULL) *pos = '\0';
        pos = strchr(line, '/');
        if (pos != NULL) *pos = '\0';
        if (!inet_str2in(line, ip, ipv46_flag)) {
            if (!xconf.ignore_filelist_error)
                log_fatal(LOGGER_NAME,
                          "could not parse IPv%d address from line: %s: %s",
                          ipv46_flag, line, strerror(errno));
        }
    }

    return EXIT_SUCCESS;
}

port_h_t ip_target_file_get_port(shard_t *shard) {
    return xconf.target_port_list[shard->ip_target_file_params.port_current];
}
