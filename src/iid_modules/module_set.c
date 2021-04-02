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

#include "../../lib/logger.h"
#include "../../lib/util.h"

iid_module_t module_set;
static int   ipv46_bytes;

int set_global_init(struct state_conf *conf) {
    assert(conf);
    ipv46_bytes = conf->ipv46_bytes;
    memset(IID, 0, ipv46_bytes);

    if (!xconf.iid_args) {
        log_fatal("iid-module", "Set mode: NULL args for IPv%d",
                  xconf.ipv46_flag);
    }
    if (!inet_str2in(xconf.iid_args, IID, xconf.ipv46_flag)) {
        log_fatal("iid-module", "Set mode: unknown args `%s' for IPv%d",
                  xconf.iid_args, xconf.ipv46_flag);
    }

    int i;
    for (i = 0; i < xconf.max_probe_len / 8; i++)
        IID[i] = 0x00;
    i = xconf.max_probe_len % 8;
    if (i) {
        int j = 0xff >> i;
        IID[xconf.max_probe_len / 8] &= j;
    }

    return EXIT_SUCCESS;
}

int set_thread_init(void) { return EXIT_SUCCESS; }

int set_get_current_iid(void *iid, UNUSED int iid_index, UNUSED void *args) {
    memcpy(iid, IID, ipv46_bytes);

    return EXIT_SUCCESS;
}

int set_close(void) { return EXIT_SUCCESS; }

iid_module_t module_set = {.name            = "set",
                           .global_init     = set_global_init,
                           .thread_init     = set_thread_init,
                           .get_current_iid = set_get_current_iid,
                           .close           = set_close,
                           .helptext =
                               "Set mode IID (suffix), extract the suffix of "
                               "`--iid-args' as targets' IID (suffix).\n"
                               "    --iid-args=ipv46_address."};
