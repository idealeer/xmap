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

#ifndef XMAP_PROBE_MODULES_H
#define XMAP_PROBE_MODULES_H

#include "../fieldset.h"
#include "../state.h"

#define OUTPUT_TYPE_STATIC 1
#define OUTPUT_TYPE_DYNAMIC 2

#define PACKET_VALID 1
#define PACKET_INVALID 0

typedef struct probe_response_type {
    const uint8_t is_success;
    const char *  name;
} response_type_t;

typedef int (*probe_global_init_cb)(struct state_conf *);

typedef int (*probe_thread_init_cb)(void *packet_buf, macaddr_t *src_mac,
                                    macaddr_t *gw_mac, void **arg_ptr);

typedef int (*probe_make_packet_cb)(void *packet_buf, size_t *buf_len,
                                    ipaddr_n_t *src_ip, ipaddr_n_t *dst_ip,
                                    port_h_t dst_port, uint8_t ttl,
                                    int probe_num, void *arg);

typedef void (*probe_print_packet_cb)(FILE *, void *packet_buf);

typedef int (*probe_validate_packet_cb)(const struct ip *ip_hdr, uint32_t len,
                                        int *is_repeat);

typedef void (*probe_classify_packet_cb)(const u_char *packet_buf, uint32_t len,
                                         fieldset_t *          fs,
                                         const struct timespec ts);

typedef int (*probe_close_cb)(struct state_conf *, struct state_send *,
                              struct state_recv *);

typedef struct probe_module {
    int         ipv46_flag;
    const char *name;
    size_t      packet_length;
    const char *pcap_filter;
    size_t      pcap_snaplen;

    // Should XMap complain if the user hasn't specified valid
    // source and target port numbers?
    uint8_t port_args;

    probe_global_init_cb     global_init;
    probe_thread_init_cb     thread_init;
    probe_make_packet_cb     make_packet;
    probe_print_packet_cb    print_packet;
    probe_validate_packet_cb validate_packet;
    probe_classify_packet_cb process_packet;
    probe_close_cb           close;
    int                      output_type;
    fielddef_t *             fields;
    int                      numfields;
    const char *             helptext;

} probe_module_t;

probe_module_t *get_probe_module_by_name(const char *name, int ipv46_flag);

void fs_add_ip_fields(fieldset_t *fs, struct ip *ip);

void fs_add_ipv6_fields(fieldset_t *fs, struct ip6_hdr *ipv6_hdr);

void fs_add_system_fields(fieldset_t *fs, int is_repeat, int in_cooldown);

void print_probe_modules(int ipv46_flag);

extern int        ip_fields_len;
extern int        ip6_fields_len;
extern int        sys_fields_len;
extern fielddef_t ip_fields[];
extern fielddef_t ip6_fields[];
extern fielddef_t sys_fields[];

#endif // XMAP_PROBE_MODULES_H
