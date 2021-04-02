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

#ifndef XMAP_CYCLIC_H
#define XMAP_CYCLIC_H

#include <gmp.h>
#include <stddef.h>
#include <stdint.h>

#include "aesrand.h"

#define MAX_MPZ_STR_LEN 50
#define MAX_PRIM_FACTOR_SIZE 10

// Represents a multiplicative cyclic group (Z/pZ)*
typedef struct _cyclic_group {
    char prime[MAX_MPZ_STR_LEN];          // p
    char known_primroot[MAX_MPZ_STR_LEN]; // Known primitive root of (Z/pZ)*
    char prime_factors[MAX_PRIM_FACTOR_SIZE]
                      [MAX_MPZ_STR_LEN]; // Unique prime factors of (p-1)
    size_t num_prime_factors;            // size of num_prime_factors
} _cyclic_group_t;

typedef struct cyclic_group {
    mpz_t  prime;          // p
    mpz_t  known_primroot; // Known primitive root of (Z/pZ)*
    mpz_t  prime_factors[MAX_PRIM_FACTOR_SIZE]; // Unique prime factors of (p-1)
    size_t num_prime_factors;                   // size of num_prime_factors
} cyclic_group_t;

// Represents a cycle in a group
typedef struct cycle {
    const cyclic_group_t *group;
    mpz_t                 generator;
    mpz_t                 order;
    mpz_t                 offset;
} cycle_t;

// Get a cyclic_group_t of at least min_size.
// Pointer into static data, do not free().
const cyclic_group_t *get_group(const mpz_t min_size);

// Generate cycle (find generator and inverse)
cycle_t make_cycle(const cyclic_group_t *group, aesrand_t *aes);

void close_cycle(cycle_t cycle);

#endif // XMAP_CYCLIC_H
