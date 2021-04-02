/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_GMP_EXT_H
#define XMAP_GMP_EXT_H

#include <gmp.h>
#include <stdint.h>

int mpz_eq(const mpz_t op1, const mpz_t op2);

int mpz_ne(const mpz_t op1, const mpz_t op2);

int mpz_ge(const mpz_t op1, const mpz_t op2);

int mpz_le(const mpz_t op1, const mpz_t op2);

int mpz_gt(const mpz_t op1, const mpz_t op2);

int mpz_lt(const mpz_t op1, const mpz_t op2);

int mpz_eq_ui(const mpz_t op1, unsigned long int op2);

int mpz_ne_ui(const mpz_t op1, unsigned long int op2);

int mpz_ge_ui(const mpz_t op1, unsigned long int op2);

int mpz_le_ui(const mpz_t op1, unsigned long int op2);

int mpz_gt_ui(const mpz_t op1, unsigned long int op2);

int mpz_lt_ui(const mpz_t op1, unsigned long int op2);

int mpz_not_zero(const mpz_t op);

int mpz_zero(const mpz_t op);

void mpz_to_uint8s(const mpz_t op, uint8_t *str, size_t bytes_len);

void mpz_from_uint8s(mpz_t op, const uint8_t *str, size_t bytes_len);

void mpz_to_uint8s_bits(const mpz_t op, uint8_t *str, size_t bits_len);

void mpz_from_uint8s_bits(mpz_t op, const uint8_t *str, size_t bits_len);

char *mpz_to_str10(const mpz_t op);

#endif // XMAP_GMP_EXT_H
