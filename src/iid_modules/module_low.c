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

iid_module_t module_low;
static int   ipv46_bytes;

int low_global_init(struct state_conf *conf) {
    assert(conf);
    ipv46_bytes = conf->ipv46_bytes;
    memset(IID, 0, ipv46_bytes);
    ((uint8_t *) IID)[ipv46_bytes - 1] = 1;

    int i = 0;
    for (i = 0; i < xconf.max_probe_len / 8; i++)
        IID[i] = 0x00;
    i = xconf.max_probe_len % 8;
    if (i) {
        int j = 0xff >> i;
        IID[xconf.max_probe_len / 8] &= j;
    }

    return EXIT_SUCCESS;
}

int low_thread_init(void) { return EXIT_SUCCESS; }

int low_get_current_iid(void *iid, UNUSED int iid_index, UNUSED void *args) {
    memcpy(iid, IID, ipv46_bytes);

    return EXIT_SUCCESS;
}

int low_close(void) { return EXIT_SUCCESS; }

iid_module_t module_low = {
    .name            = "low",
    .global_init     = low_global_init,
    .thread_init     = low_thread_init,
    .get_current_iid = low_get_current_iid,
    .close           = low_close,
    .helptext        = "Low mode IID (suffix), e.g., 2001:db8:1234:5678::1."};
