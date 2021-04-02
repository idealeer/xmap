/*
 * Blocklist Copyright 2013 Regents of the University of Michigan
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_BLOCKLIST_H
#define XMAP_BLOCKLIST_H

#include <gmp.h>
#include <stdint.h>

typedef struct bl_cidr_node {
    mpz_t                ipvx_address;
    int                  prefix_len;
    struct bl_cidr_node *next;
} bl_cidr_node_t;

int blocklist_init(char *allowlist_filename, char *blocklist_filename,
                   char **allowlist_entries, size_t allowlist_entries_len,
                   char **blocklist_entries, size_t blocklist_entries_len,
                   int ignore_invalid_hosts, size_t ipvx_max_len,
                   size_t port_max_len, size_t ipv46_flag);

void blocklist_prefix(const mpz_t prefix, int prefix_len);

void allowlist_prefix(const mpz_t prefix, int prefix_len);

void blocklist_count_allowed_ip_port(mpz_t count);

void blocklist_count_not_allowed_ip_port(mpz_t count);

void blocklist_count_allowed_ip(mpz_t count);

void blocklist_count_not_allowed_ip(mpz_t count);

void blocklist_lookup_index_for_ipvx_port(mpz_t ipvx, const mpz_t index);

int blocklist_is_allowed_ipvx(const mpz_t ipvx);

int blocklist_is_allowed_ip(const uint8_t *ip);

uint32_t blocklist_ipvx_for_value(const mpz_t ipvx);

bl_cidr_node_t *get_blocklisted_cidrs(void);

bl_cidr_node_t *get_allowlisted_cidrs(void);

void blocklist_free();

#endif // XMAP_BLOCKLIST_H
