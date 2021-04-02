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

#ifndef XMAP_MODULE_UDP_H
#define XMAP_MODULE_UDP_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../lib/includes.h"
#include "aesrand.h"
#include "state.h"
#include "types.h"

typedef enum udp_payload_field_type {
    UDP_DATA,
    UDP_SADDR_N,
    UDP_SADDR_A,
    UDP_DADDR_N,
    UDP_DADDR_A,
    UDP_SPORT_N,
    UDP_SPORT_A,
    UDP_DPORT_N,
    UDP_DPORT_A,
    UDP_RAND_BYTE,
    UDP_RAND_DIGIT,
    UDP_RAND_ALPHA,
    UDP_RAND_ALPHANUM
} udp_payload_field_type_t;

typedef struct udp_payload_field_type_def {
    const char *             name;
    const char *             desc;
    udp_payload_field_type_t ftype;
} udp_payload_field_type_def_t;

typedef struct udp_payload_field {
    enum udp_payload_field_type ftype;
    unsigned int                length;
    char *                      data;
} udp_payload_field_t;

typedef struct udp_payload_template {
    unsigned int               fcount;
    struct udp_payload_field **fields;
} udp_payload_template_t;

typedef struct udp_payload_output {
    int   length;
    char *data;
} udp_payload_output_t;

int udp_global_init(struct state_conf *conf);

int udp_global_cleanup(UNUSED struct state_conf *xconf,
                       UNUSED struct state_send *xsend,
                       UNUSED struct state_recv *xrecv);

int udp_thread_init(void *buf, macaddr_t *src, macaddr_t *gw, void **arg_ptr);

int udp_make_packet(void *buf, UNUSED size_t *buf_len, ipaddr_n_t *src_ip,
                    ipaddr_n_t *dst_ip, port_h_t dst_port, uint8_t ttl,
                    int probe_num, UNUSED void *arg);

void udp_print_packet(FILE *fp, void *packet);

int udp_validate_packet(const struct ip *ip_hdr, uint32_t len,
                        UNUSED int *is_repeat);

void udp_process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
                        UNUSED struct timespec ts);

// other
extern const char *udp_unreach_strings[];

void udp_set_num_sports(int x);

// udp field
int udp_template_build(udp_payload_template_t *t, char *out, unsigned int len,
                       struct ip *ip_hdr, struct udphdr *udp_hdr,
                       aesrand_t *aes);

void udp_template_free(udp_payload_template_t *t);

void udp_template_add_field(udp_payload_template_t * t,
                            udp_payload_field_type_t ftype, unsigned int length,
                            char *data);

int udp_template_lookup_field(char *vname, udp_payload_field_t *c);

udp_payload_template_t *udp_template_load(char *buf, unsigned int len);

#endif // XMAP_MODULE_UDP_H
