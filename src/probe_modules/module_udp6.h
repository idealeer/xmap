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

#ifndef XMAP_MODULE_UDP6_H
#define XMAP_MODULE_UDP6_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../lib/includes.h"
#include "aesrand.h"
#include "state.h"
#include "types.h"

typedef enum udp6_payload_field_type {
    UDP6_DATA,
    UDP6_SADDR_N,
    UDP6_SADDR_A,
    UDP6_DADDR_N,
    UDP6_DADDR_A,
    UDP6_SPORT_N,
    UDP6_SPORT_A,
    UDP6_DPORT_N,
    UDP6_DPORT_A,
    UDP6_RAND_BYTE,
    UDP6_RAND_DIGIT,
    UDP6_RAND_ALPHA,
    UDP6_RAND_ALPHANUM
} udp6_payload_field_type_t;

typedef struct udp6_payload_field_type_def {
    const char               *name;
    const char               *desc;
    udp6_payload_field_type_t ftype;
} udp6_payload_field_type_def_t;

typedef struct udp6_payload_field {
    enum udp6_payload_field_type ftype;
    unsigned int                 length;
    char                        *data;
} udp6_payload_field_t;

typedef struct udp6_payload_template {
    unsigned int                fcount;
    struct udp6_payload_field **fields;
} udp6_payload_template_t;

typedef struct udp6_payload_output {
    int   length;
    char *data;
} udp6_payload_output_t;

int udp6_global_init(struct state_conf *conf);

int udp6_global_cleanup(UNUSED struct state_conf *xconf,
                        UNUSED struct state_send *xsend,
                        UNUSED struct state_recv *xrecv);

int udp6_thread_init(void *buf, macaddr_t *src, macaddr_t *gw, void **arg_ptr);

int udp6_make_packet(void *buf, UNUSED size_t *buf_len, ipaddr_n_t *src_ip,
                     ipaddr_n_t *dst_ip, port_h_t dst_port, uint8_t ttl,
                     int probe_num, UNUSED index_h_t index, void *arg);

void udp6_print_packet(FILE *fp, void *packet);

int udp6_validate_packet(const struct ip *ip_hdr, uint32_t len,
                         UNUSED int *is_repeat, UNUSED void *packet_buf,
                         UNUSED size_t *buf_len, UNUSED uint8_t ttl);

void udp6_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
                         UNUSED struct timespec ts);

void udp6_set_num_sports(int x);

// udp6 field
int udp6_template_build(udp6_payload_template_t *t, char *out, unsigned int len,
                        struct ip6_hdr *ip_hdr, struct udphdr *udp_hdr,
                        aesrand_t *aes);

void udp6_template_free(udp6_payload_template_t *t);

void udp6_template_add_field(udp6_payload_template_t  *t,
                             udp6_payload_field_type_t ftype,
                             unsigned int length, char *data);

int udp6_template_lookup_field(char *vname, udp6_payload_field_t *c);

udp6_payload_template_t *udp6_template_load(char *buf, unsigned int len);

#endif // XMAP_MODULE_UDP6_H
