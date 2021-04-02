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

iid_module_t module_zero;
static int   ipv46_bytes;

int zero_global_init(struct state_conf *conf) {
    assert(conf);
    ipv46_bytes = conf->ipv46_bytes;
    memset(IID, 0, ipv46_bytes);

    return EXIT_SUCCESS;
}

int zero_thread_init(void) { return EXIT_SUCCESS; }

int zero_get_current_iid(void *iid, UNUSED int iid_index, UNUSED void *args) {
    memcpy(iid, IID, ipv46_bytes);

    return EXIT_SUCCESS;
}

int zero_close(void) { return EXIT_SUCCESS; }

iid_module_t module_zero = {
    .name            = "zero",
    .global_init     = zero_global_init,
    .thread_init     = zero_thread_init,
    .get_current_iid = zero_get_current_iid,
    .close           = zero_close,
    .helptext        = "Zero mode IID (suffix), e.g., 2001:db8:1234:5678::."};
