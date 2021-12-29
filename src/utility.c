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

#include "utility.h"

#include <string.h>

#include "../lib/gmp-ext.h"
#include "../lib/logger.h"
#include "../lib/util.h"
#include "state.h"

void add_to_array(const char *ip_str) {
    if (xconf.number_source_ips >= MAX_SOURCE_IP_NUM)
        log_fatal("parse", "over %d source IPv%d addresses provided",
                  MAX_SOURCE_IP_NUM, xconf.ipv46_flag);
    log_debug("parse", "source IPv%d address: %s\n", xconf.ipv46_flag, ip_str);
    inet_str2in(ip_str, xconf.source_ip_addresses[xconf.number_source_ips],
                xconf.ipv46_flag);
    xconf.number_source_ips++;
}

void parse_source_ip_addresses(char given_string[]) {
    char *dash  = strchr(given_string, '-');
    char *comma = strchr(given_string, ',');

    if (dash && comma) {
        *comma = '\0';
        parse_source_ip_addresses(given_string);
        parse_source_ip_addresses(comma + 1);
    } else if (comma) {
        while (comma) {
            *comma = '\0';
            add_to_array(given_string);
            given_string = comma + 1;
            comma        = strchr(given_string, ',');
            if (!comma) {
                add_to_array(given_string);
            }
        }
    } else if (dash) { // range
        *dash = '\0';
        log_debug("parse", "IPv%d address start: %s", xconf.ipv46_flag,
                  given_string);
        log_debug("parse", "IPv%d address end: %s", xconf.ipv46_flag, dash + 1);

        uint8_t ip_start[IP_ADDR_LEN_BYTES];
        uint8_t ip_end[IP_ADDR_LEN_BYTES];
        inet_str2in(given_string, ip_start, xconf.ipv46_flag);
        inet_str2in(dash + 1, ip_end, xconf.ipv46_flag);

        mpz_t ip_start_m, ip_end_m;
        mpz_init(ip_start_m);
        mpz_init(ip_end_m);
        mpz_from_uint8s(ip_start_m, ip_start, xconf.ipv46_bytes);
        mpz_from_uint8s(ip_end_m, ip_end, xconf.ipv46_bytes);

        char ip_str[64];
        while (mpz_le(ip_start_m, ip_end_m)) {
            if (xconf.number_source_ips >= MAX_SOURCE_IP_NUM) {
                // log fatal here
                log_fatal("parse", "over %d source IPv%d addresses provided",
                          MAX_SOURCE_IP_NUM, xconf.ipv46_flag);
            }
            mpz_to_uint8s(ip_start_m, ip_start, xconf.ipv46_bytes);
            for (int i = 0; i < xconf.ipv46_bytes; i++)
                xconf.source_ip_addresses[xconf.number_source_ips][i] =
                    ip_start[i];
            inet_in2str(ip_start, ip_str, 64, xconf.ipv46_flag);
            log_debug("parse", "IPv%d address: %s", xconf.ipv46_flag, ip_str);
            mpz_add_ui(ip_start_m, ip_start_m, 1);
        }

        mpz_clear(ip_start_m);
        mpz_clear(ip_end_m);
    } else {
        add_to_array(given_string);
    }
}

void add_to_target_port_array(int port) {
    if (xconf.target_port_num >= MAX_PORT_NUM)
        log_fatal("parse", "over %d target ports provided", MAX_PORT_NUM);
    if (port < 0 || port >= MAX_PORT_NUM)
        log_fatal("parse", "illegal target port: %d provided", port);
    log_debug("parse", "target port: %d", port);
    xconf.target_port_list[xconf.target_port_num] = port;
    xconf.target_port_flag[port]                  = 1;
    xconf.target_port_num++;
}

void parse_target_ports(char given_string[]) {
    char *dash  = strchr(given_string, '-');
    char *comma = strchr(given_string, ',');
    if (dash && comma) {
        *comma = '\0';
        parse_target_ports(given_string);
        parse_target_ports(comma + 1);
    } else if (comma) {
        while (comma) {
            *comma = '\0';
            add_to_target_port_array(atoi(given_string));
            given_string = comma + 1;
            comma        = strchr(given_string, ',');
            if (!comma) {
                add_to_target_port_array(atoi(given_string));
            }
        }
    } else if (dash) { // range
        *dash          = '\0';
        int port_start = atoi(given_string);
        int port_end   = atoi(dash + 1);

        log_debug("parse", "target port start: %d", port_start);
        log_debug("parse", "target port end: %d", port_end);

        while (port_start <= port_end) {
            add_to_target_port_array(port_start);
            port_start++;
        }
    } else {
        add_to_target_port_array(atoi(given_string));
    }
}

void init_target_port() {
    log_debug("parse", "init target port");
    int full = 1;
    for (int i = 1; i <= 17; i++) {
        if (xconf.target_port_num <= full) {
            log_debug("parse", "target port number: %d", xconf.target_port_num);
            log_debug("parse", "target port bits: %d", xconf.target_port_bits);
            log_debug("parse", "target port full range number: %d",
                      xconf.target_port_full);
            log_debug("parse", "max_probe_port_len: %d",
                      xconf.max_probe_port_len);
            return;
        }
        full *= 2;
        xconf.target_port_bits   = i;
        xconf.target_port_full   = full;
        xconf.max_probe_port_len = xconf.max_probe_len + xconf.target_port_bits;
    }
    log_fatal("parse", "too many target ports (%d), should be <= %d",
              xconf.target_port_num, full / 2);
}
