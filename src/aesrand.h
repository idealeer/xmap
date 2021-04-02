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

#ifndef XMAP_AESRAND_H
#define XMAP_AESRAND_H

#include <gmp.h>
#include <stdint.h>

typedef struct aesrand aesrand_t;

aesrand_t *aesrand_init_from_random();

aesrand_t *aesrand_init_from_seed(uint64_t);

uint64_t aesrand_getword(aesrand_t *aes);

void aesrand_get128bits(mpz_t rop, aesrand_t *aes);

aesrand_t *aesrand_free(aesrand_t *aes);

#endif // XMAP_AESRAND_H
