/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "iid_modules.h"

#include <assert.h>
#include <string.h>

iid_module_t module_low_fill;
static int   ipv46_bytes;

int low_fill_global_init(struct state_conf *conf) {
    assert(conf);
    ipv46_bytes = conf->ipv46_bytes;
    memset(IID, 0, ipv46_bytes);

    int i = (xconf.max_probe_len / 8) > (ipv46_bytes - 2)
                ? xconf.max_probe_len / 8
                : ipv46_bytes - 2;
    for (; i < ipv46_bytes; i++)
        IID[i] = 0xff;
    i = xconf.max_probe_len % 8;
    if (i) {
        IID[xconf.max_probe_len / 8] >>= i;
    }

    return EXIT_SUCCESS;
}

int low_fill_thread_init(void) { return EXIT_SUCCESS; }

int low_fill_get_current_iid(void *iid, UNUSED int iid_index,
                             UNUSED void *args) {
    memcpy(iid, IID, ipv46_bytes);

    return EXIT_SUCCESS;
}

int low_fill_close(void) { return EXIT_SUCCESS; }

iid_module_t module_low_fill = {
    .name            = "low_fill",
    .global_init     = low_fill_global_init,
    .thread_init     = low_fill_thread_init,
    .get_current_iid = low_fill_get_current_iid,
    .close           = low_fill_close,
    .helptext = "Low fill mode IID (suffix), e.g., 2001:db8:1234:5678::FFFF."};
