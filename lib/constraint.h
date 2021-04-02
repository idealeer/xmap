/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_CONSTRAINT_H
#define XMAP_CONSTRAINT_H

#include <gmp.h>
#include <stdint.h>

#include "../lib/util.h"

typedef struct _constraint constraint_t;
typedef uint64_t           mpz_t_ui64;
typedef uint32_t           mpz_t_ui32;

// All addresses will initially have the given value.
constraint_t *constraint_init(const mpz_t value, size_t ipvx_max_len);

void constraint_free(constraint_t *con);

void constraint_set(constraint_t *con, const mpz_t prefix, int len,
                    const mpz_t value);

void constraint_lookup_ipvx_for_value(mpz_t value, constraint_t *con,
                                      const mpz_t ipvx);

void constraint_count_ipvx_of_value(mpz_t count, constraint_t *con,
                                    const mpz_t value);

void constraint_paint_value(constraint_t *con, const mpz_t value);

void constraint_lookup_index_for_ipvx(mpz_t ipvx, constraint_t *con,
                                      const mpz_t index, const mpz_t value);

// ui using
constraint_t *constraint_init_ui(mpz_t_ui32 value, size_t ipvx_max_len);

void constraint_set_ui(constraint_t *con, const mpz_t prefix, int len,
                       mpz_t_ui32 value);

void constraint_paint_value_ui(constraint_t *con, mpz_t_ui32 value);

void constraint_lookup_index_for_ipvx_ui(mpz_t ipvx, constraint_t *con,
                                         const mpz_t index, mpz_t_ui32 value);

void constraint_count_ipvx_of_value_ui(mpz_t count, constraint_t *con,
                                       mpz_t_ui32 value);

mpz_t_ui32 constraint_lookup_ipvx_for_value_ui(constraint_t *con,
                                               const mpz_t   ipvx);

// uint32_t compatible
void constraint_set_32(constraint_t *con, mpz_t_ui32 prefix, int len,
                       mpz_t_ui32 value);

mpz_t_ui32 constraint_lookup_ipvx_for_value_32(constraint_t *con,
                                               mpz_t_ui32    ipvx);

mpz_t_ui64 constraint_count_ipvx_of_value_32(constraint_t *con,
                                             mpz_t_ui32    value);

mpz_t_ui32 constraint_lookup_index_for_ipvx_32(constraint_t *con,
                                               mpz_t_ui64    index,
                                               mpz_t_ui32    value);

#endif // XMAP_CONSTRAINT_H
