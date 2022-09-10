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

#include "validate.h"

#include <assert.h>
#include <string.h>

#include "state.h"

#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/rijndael-alg-fst.h"

#define AES_ROUNDS 10
#define AES_BLOCK_WORDS 4
#define AES_KEY_BYTES 16

static int      inited = 0;
static uint32_t aes_sched[(AES_ROUNDS + 1) * 4];

void validate_init() {
    uint8_t key[AES_KEY_BYTES];
    memset(key, 0, AES_KEY_BYTES);
    if (xconf.seed_provided) {
        for (uint8_t i = 0; i < sizeof(xconf.seed); ++i) {
            key[i] = (uint8_t) ((xconf.seed >> 8 * i) & 0xFF);
        }
    } else {
        if (!random_bytes(key, AES_KEY_BYTES)) {
            log_fatal("validate", "couldn't get random bytes");
        }
    }
    if (rijndaelKeySetupEnc(aes_sched, key, AES_KEY_BYTES * 8) != AES_ROUNDS) {
        log_fatal("validate", "couldn't initialize AES key");
    }
    inited = 1;
}

void validate_gen(const uint8_t *src_ip, const uint8_t *dst_ip,
                  port_h_t dst_port, uint8_t output[VALIDATE_BYTES]) {
    assert(inited);

    uint8_t aes_input[AES_KEY_BYTES];
    memset(aes_input, 0, AES_KEY_BYTES);
    int i;
    for (i = 0; i < xconf.ipv46_bytes; i++)
        aes_input[i] = src_ip[i] ^ dst_ip[i];
    aes_input[0] ^= (uint8_t) (dst_port >> 8u);
    aes_input[3] ^= (uint8_t) (dst_port & 0xffu);
    rijndaelEncrypt(aes_sched, AES_ROUNDS, (uint8_t *) aes_input, output);
}
