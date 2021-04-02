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
#include <time.h>

#include "../../lib/gmp-ext.h"

iid_module_t module_rand;

static gmp_randstate_t random_state;
static int             ipv46_bytes;
static int             iid_bits;
static int             max_probe_len_div8;
static int             max_probe_len_mod8;

int rand_global_init(struct state_conf *conf) {
    assert(conf);
    gmp_randinit_default(random_state);
    time_t t = time(NULL);
    gmp_randseed_ui(random_state, t);
    ipv46_bytes        = conf->ipv46_bytes;
    iid_bits           = xconf.ipv46_bits - xconf.max_probe_len;
    max_probe_len_div8 = xconf.max_probe_len / 8;
    max_probe_len_mod8 = xconf.max_probe_len % 8;

    return EXIT_SUCCESS;
}

int rand_thread_init(void) { return EXIT_SUCCESS; }

int rand_get_current_iid(void *iid, UNUSED int iid_index, UNUSED void *args) {
    mpz_t rand_m;
    mpz_init(rand_m);
    mpz_urandomb(rand_m, random_state, iid_bits);
    mpz_to_uint8s(rand_m, (uint8_t *) iid, ipv46_bytes);
    uint8_t *IID = (uint8_t *) iid;

    for (int i = 0; i < max_probe_len_div8; i++)
        IID[i] = 0x00;
    if (max_probe_len_mod8) {
        int j = 0xff >> max_probe_len_mod8;
        IID[max_probe_len_div8] &= j;
    }
    mpz_clear(rand_m);

    return EXIT_SUCCESS;
}

int rand_close_(void) { return EXIT_SUCCESS; }

iid_module_t module_rand = {.name            = "rand",
                            .global_init     = rand_global_init,
                            .thread_init     = rand_thread_init,
                            .get_current_iid = rand_get_current_iid,
                            .close           = rand_close_,
                            .helptext =
                                "Random mode IID (suffix), e.g., "
                                "2001:db8:1234:5678:1783:ab42:9247:cb38."};
