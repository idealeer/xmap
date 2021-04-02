/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "gmp-ext.h"

#include <assert.h>
#include <math.h>

int mpz_eq(const mpz_t op1, const mpz_t op2) { return mpz_cmp(op1, op2) == 0; }

int mpz_ne(const mpz_t op1, const mpz_t op2) { return mpz_cmp(op1, op2) != 0; }

int mpz_ge(const mpz_t op1, const mpz_t op2) { return mpz_cmp(op1, op2) >= 0; }

int mpz_le(const mpz_t op1, const mpz_t op2) { return mpz_cmp(op1, op2) <= 0; }

int mpz_gt(const mpz_t op1, const mpz_t op2) { return mpz_cmp(op1, op2) > 0; }

int mpz_lt(const mpz_t op1, const mpz_t op2) { return mpz_cmp(op1, op2) < 0; }

int mpz_eq_ui(const mpz_t op1, unsigned long int op2) {
    return mpz_cmp_ui(op1, op2) == 0;
}

int mpz_ne_ui(const mpz_t op1, unsigned long int op2) {
    return mpz_cmp_ui(op1, op2) != 0;
}

int mpz_ge_ui(const mpz_t op1, unsigned long int op2) {
    return mpz_cmp_ui(op1, op2) >= 0;
}

int mpz_le_ui(const mpz_t op1, unsigned long int op2) {
    return mpz_cmp_ui(op1, op2) <= 0;
}

int mpz_gt_ui(const mpz_t op1, unsigned long int op2) {
    return mpz_cmp_ui(op1, op2) > 0;
}

int mpz_lt_ui(const mpz_t op1, unsigned long int op2) {
    return mpz_cmp_ui(op1, op2) < 0;
}

int mpz_not_zero(const mpz_t op) { return mpz_ne_ui(op, 0); }

int mpz_zero(const mpz_t op) { return mpz_eq_ui(op, 0); }

void mpz_to_uint8s(const mpz_t op, uint8_t *str, size_t bytes_len) {
    size_t  count;
    uint8_t str_t[bytes_len];
    mpz_export(str_t, &count, 1, 1, 0, 0, op);

    if (count > bytes_len) count = bytes_len;
    for (size_t i = 1; i <= count; i++)
        str[bytes_len - i] = str_t[count - i];
}

void mpz_from_uint8s(mpz_t op, const uint8_t *str, size_t bytes_len) {
    mpz_import(op, bytes_len, 1, 1, 0, 0, str);
}

void mpz_to_uint8s_bits(const mpz_t op, uint8_t *str, size_t bits_len) {
    mpz_t op_;
    mpz_init_set(op_, op);
    size_t shift_len = bits_len % 8;
    if (shift_len) {
        shift_len = 8 - shift_len;
        mpz_mul_2exp(op_, op, shift_len);
    }

    int bytes_len = (int) (ceil((bits_len) / (double) 8));
    mpz_to_uint8s(op_, str, bytes_len);
    mpz_clear(op_);
}

void mpz_from_uint8s_bits(mpz_t op, const uint8_t *str, size_t bits_len) {
    int bytes_len = (int) (ceil((bits_len) / (double) 8));
    mpz_from_uint8s(op, str, bytes_len);
    size_t shift_len = bits_len % 8;

    if (shift_len) {
        shift_len = 8 - shift_len;
        mpz_fdiv_q_2exp(op, op, shift_len);
    }
}

char *mpz_to_str10(const mpz_t op) { return mpz_get_str(NULL, 10, op); }
