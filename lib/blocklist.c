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

#include "blocklist.h"

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

#include "constraint.h"
#include "gmp-ext.h"
#include "logger.h"
#include "xalloc.h"

#define ADDR_DISALLOWED 0
#define ADDR_ALLOWED 1

// scanning range on right, like 28 of 2001::/20-28 we just take bits from 0 to
// 28 for blocklisting as if a new IPvX is defined with max-length 28 new
// version: port range added we append the port bits to the end of the IPvX bits
// to gen random <IP, port> IPvX: ip + port

static int IPVX_MAX_PREFIX_LEN = 128; // max IP bits
static int PORT_MAX_BITS       = 16;  // max port bits
static int IPVX_PORT_MAX_BITS  = 144; // max IP + port bits

static int IPV46_FLAG          = 6;   // IPv4/IPv6 flag
static int IP_MAX_PREFIX_LEN   = 128; // IPv4/IPv6 max bits
static int IP_MAX_PREFIX_BYTES = 16;  // IPv4/IPv6 max bits

typedef struct bl_linked_list {
    bl_cidr_node_t *first;
    bl_cidr_node_t *last;
    mpz_t           len;
} bl_ll_t;

static constraint_t *constraint = NULL;

// keep track of the prefixes we've tried to BL/WL
// for logging purposes
static bl_ll_t *blocklisted_cidrs = NULL;
static bl_ll_t *allowlisted_cidrs = NULL;

bl_cidr_node_t *get_blocklisted_cidrs(void) { return blocklisted_cidrs->first; }

bl_cidr_node_t *get_allowlisted_cidrs(void) { return allowlisted_cidrs->first; }

void blocklist_lookup_index_for_ipvx_port(mpz_t ipvx, const mpz_t index) {
    constraint_lookup_index_for_ipvx_ui(ipvx, constraint, index, ADDR_ALLOWED);
}

// check whether a single IP address is allowed to be scanned.
// appending port bits
int blocklist_is_allowed_ipvx(const mpz_t ipvx) {
    mpz_t ipvx_p;
    mpz_init(ipvx_p);
    mpz_mul_2exp(ipvx_p, ipvx, PORT_MAX_BITS);
    int ret =
        constraint_lookup_ipvx_for_value_ui(constraint, ipvx_p) == ADDR_ALLOWED;
    mpz_clear(ipvx_p);

    return ret;
}

int blocklist_is_allowed_ip(const uint8_t *ip) {
    mpz_t prefix;
    mpz_init(prefix);
    mpz_from_uint8s_bits(prefix, ip, IPVX_MAX_PREFIX_LEN);
    int ret = blocklist_is_allowed_ipvx(prefix);
    mpz_clear(prefix);

    return ret;
}

static void bl_ll_add(bl_ll_t *l, const mpz_t addr, uint16_t p) {
    assert(l);
    bl_cidr_node_t *new = xmalloc(sizeof(bl_cidr_node_t));
    new->next           = NULL;
    mpz_init_set(new->ipvx_address, addr);
    new->prefix_len = p;

    if (!l->first) {
        l->first = new;
    } else {
        l->last->next = new;
    }
    l->last = new;
    mpz_add_ui(l->len, l->len, 1);
}

// appending port bits for constraint
// not for cidr list
static void _add_constraint(const mpz_t prefix, int prefix_len, int value) {
    mpz_t ipvx_p;
    mpz_init(ipvx_p);
    mpz_mul_2exp(ipvx_p, prefix, PORT_MAX_BITS);
    constraint_set_ui(constraint, ipvx_p, prefix_len, value);
    mpz_clear(ipvx_p);

    if (value == ADDR_ALLOWED) {
        bl_ll_add(allowlisted_cidrs, prefix, prefix_len);
    } else if (value == ADDR_DISALLOWED) {
        bl_ll_add(blocklisted_cidrs, prefix, prefix_len);
    } else {
        log_fatal("blocklist", "unknown type of blocklist operation specified");
    }
}

// blocklist a CIDR network allocation
void blocklist_prefix(const mpz_t prefix, int prefix_len) {
    _add_constraint(prefix, prefix_len, ADDR_DISALLOWED);
}

// allowlist a CIDR network allocation
void allowlist_prefix(const mpz_t prefix, int prefix_len) {
    _add_constraint(prefix, prefix_len, ADDR_ALLOWED);
}

static int init_from_string(char *ip, int value, const char *name,
                            int ignore_invalid_hosts) {
    char *dash = strchr(ip, '-');
    if (dash) {
        *dash = '\0';
        log_debug("blocklist", "IPv%d address: %s", IPV46_FLAG, ip);
        log_debug("blocklist", "IPv%d address: %s", IPV46_FLAG, dash + 1);

        uint8_t ip_start[IP_MAX_PREFIX_BYTES];
        uint8_t ip_end[IP_MAX_PREFIX_BYTES];
        inet_str2in(ip, ip_start, IPV46_FLAG);
        inet_str2in(dash + 1, ip_end, IPV46_FLAG);

        mpz_t ip_start_m, ip_end_m;
        mpz_init(ip_start_m);
        mpz_init(ip_end_m);
        mpz_from_uint8s(ip_start_m, ip_start, IP_MAX_PREFIX_BYTES);
        mpz_from_uint8s(ip_end_m, ip_end, IP_MAX_PREFIX_BYTES);

        char ip_str[64];
        while (mpz_le(ip_start_m, ip_end_m)) {
            mpz_to_uint8s(ip_start_m, ip_start, IP_MAX_PREFIX_BYTES);
            inet_in2str(ip_start, ip_str, 64, IPV46_FLAG);

            int ret =
                init_from_string(ip_str, value, name, ignore_invalid_hosts);
            if (ret && !ignore_invalid_hosts) {
                log_debug("blocklist",
                          "'%s' is not a valid IPv%d address or hostname",
                          IPV46_FLAG, ip_str);
                return -1;
            }
            mpz_add_ui(ip_start_m, ip_start_m, 1);
        }

        mpz_clear(ip_start_m);
        mpz_clear(ip_end_m);

        return 0;
    } else {
        int   prefix_len = IPVX_MAX_PREFIX_LEN;
        char *slash      = strchr(ip, '/');
        if (slash) {
            *slash    = '\0';
            char *len = slash + 1;
            char *end;
            errno      = 0;
            prefix_len = strtol(len, &end, 10);
            if (end == len || errno != 0 || prefix_len < 0 ||
                prefix_len > IP_MAX_PREFIX_LEN) {
                log_debug("blocklist",
                          "'%s' is not a valid cidr with length:%s", ip, len);
                return -1;
            }
        }

        if (prefix_len > IPVX_MAX_PREFIX_LEN) {
            log_debug(
                "blocklist",
                "no need to %s %s/%d for block-len:%d > max-scanning-len:%d",
                name, ip, prefix_len, prefix_len, IPVX_MAX_PREFIX_LEN);
            return 0;
        }

        mpz_t addr;
        mpz_init(addr);
        struct addrinfo hint, *res;
        memset(&hint, 0, sizeof(hint));
        int ret = -1;

        if (IPV46_FLAG == IPV6_FLAG) {
            struct in6_addr ipv6;
            if (inet_str2in(ip, &ipv6, IPV46_FLAG)) { // ipv6
                mpz_from_uint8s_bits(addr, (uint8_t *) &ipv6,
                                     IPVX_MAX_PREFIX_LEN);
                _add_constraint(addr, prefix_len, value);
                log_debug("blocklist", "%sing: %s/%d", name, ip, prefix_len);
                ret = 0;
                goto cleanup;
            } else {
                goto pdns;
            }
        } else {
            struct in_addr ipv4;
            if (inet_str2in(ip, &ipv4, IPV46_FLAG)) { // ipv4
                mpz_from_uint8s_bits(addr, (uint8_t *) &ipv4,
                                     IPVX_MAX_PREFIX_LEN);
                _add_constraint(addr, prefix_len, value);
                log_debug("blocklist", "%sing: %s/%d", name, ip, prefix_len);
                ret = 0;
                goto cleanup;
            } else {
                goto pdns;
            }
        }

    pdns:
        hint.ai_protocol = IPPROTO_UDP;
        if (getaddrinfo(ip, NULL, &hint, &res)) {
            log_debug("blocklist",
                      "'%s' is not a valid IPv%d address or hostname",
                      IPV46_FLAG, ip);
            goto cleanup;
        }

        // Got some addrinfo, let's see what happens
        char ip_str[64];
        for (struct addrinfo *aip = res; aip; aip = aip->ai_next) {
            if (IPV46_FLAG == IPV6_FLAG) {
                if (aip->ai_family != PF_INET6) continue;
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) aip->ai_addr;
                mpz_from_uint8s_bits(addr, (uint8_t *) &(sa6->sin6_addr),
                                     IPVX_MAX_PREFIX_LEN);
                inet_in2str((struct in6_addr *) &(sa6->sin6_addr), ip_str, 64,
                            IPV6_FLAG);
            } else {
                if (aip->ai_family != PF_INET) continue;
                struct sockaddr_in *sa = (struct sockaddr_in *) aip->ai_addr;
                mpz_from_uint8s_bits(addr, (uint8_t *) &(sa->sin_addr),
                                     IPVX_MAX_PREFIX_LEN);
                inet_in2str((struct in_addr *) &(sa->sin_addr), ip_str, 64,
                            IPV4_FLAG);
            }
            log_debug("blocklist", "%sing: %s(%s)/%d", name, ip, ip_str,
                      prefix_len);
            ret = 0;
            _add_constraint(addr, prefix_len, value);
        }

    cleanup:
        mpz_clear(addr);

        return ret;
    }
}

static int init_from_file(char *file, const char *name, int value,
                          int ignore_invalid_hosts) {
    log_debug("blocklist", "%sing from file: %s", name, file);

    FILE *fp;
    char  line[1000];

    fp = fopen(file, "r");
    if (fp == NULL) {
        log_fatal(name, "unable to open %s file: %s: %s", name, file,
                  strerror(errno));
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        // hostnames can be up to 255 bytes
        char ip[256];
        if ((sscanf(line, "%256s", ip)) == EOF) {
            continue;
        }
        if (init_from_string(ip, value, name, ignore_invalid_hosts)) {
            if (!ignore_invalid_hosts) {
                log_fatal(name, "unable to parse %s file: %s for IPv%d", name,
                          file, IPV46_FLAG);
            }
        }
    }
    fclose(fp);

    return 0;
}

static void init_from_array(char **cidrs, size_t len, const char *name,
                            int value, int ignore_invalid_hosts) {
    log_debug("blocklist", "%sing from input", name);
    for (int i = 0; i < (int) len; i++) {
        int ret = init_from_string(cidrs[i], value, name, ignore_invalid_hosts);
        if (ret && !ignore_invalid_hosts) {
            log_fatal("constraint", "Unable to init from CIDR list: %s",
                      cidrs[i]);
        }
    }
}

// allowed: ip x port
void blocklist_count_allowed_ip_port(mpz_t count) {
    assert(constraint);
    constraint_count_ipvx_of_value_ui(count, constraint, ADDR_ALLOWED);
}

// allowed: ip
void blocklist_count_allowed_ip(mpz_t count) {
    assert(constraint);
    constraint_count_ipvx_of_value_ui(count, constraint, ADDR_ALLOWED);
    mpz_fdiv_q_2exp(count, count, PORT_MAX_BITS);
}

// not allowed: ip x port
void blocklist_count_not_allowed_ip_port(mpz_t count) {
    assert(constraint);
    constraint_count_ipvx_of_value_ui(count, constraint, ADDR_DISALLOWED);
}

// not allowed: ip
void blocklist_count_not_allowed_ip(mpz_t count) {
    assert(constraint);
    constraint_count_ipvx_of_value_ui(count, constraint, ADDR_DISALLOWED);
    mpz_fdiv_q_2exp(count, count, PORT_MAX_BITS);
}

uint32_t blocklist_ipvx_for_value(const mpz_t ipvx) {
    assert(constraint);
    return constraint_lookup_ipvx_for_value_ui(constraint, ipvx);
}

int blocklist_init(char *allowlist_filename, char *blocklist_filename,
                   char **allowlist_entries, size_t allowlist_entries_len,
                   char **blocklist_entries, size_t blocklist_entries_len,
                   int ignore_invalid_hosts, size_t ipvx_max_len,
                   size_t port_max_len, size_t ipv46_flag) {
    assert(!constraint);
    if (port_max_len < 0 || port_max_len > 65535)
        log_fatal("blocklist", "port bits number:%d > max bits number:%d",
                  port_max_len, PORT_MAX_BITS);

    IPVX_MAX_PREFIX_LEN = ipvx_max_len;
    PORT_MAX_BITS       = port_max_len;
    IPV46_FLAG          = ipv46_flag;
    switch (IPV46_FLAG) {
    case IPV6_FLAG:
        IP_MAX_PREFIX_LEN   = 128;
        IP_MAX_PREFIX_BYTES = 16;
        if (IPVX_MAX_PREFIX_LEN > IP_MAX_PREFIX_LEN)
            log_fatal("blocklist", "blocklist-len:%d > IPv%d-max-len:%d",
                      IPVX_MAX_PREFIX_LEN, IPV46_FLAG, IP_MAX_PREFIX_LEN);
        break;
    case IPV4_FLAG:
        IP_MAX_PREFIX_LEN   = 32;
        IP_MAX_PREFIX_BYTES = 4;
        if (IPVX_MAX_PREFIX_LEN > IP_MAX_PREFIX_LEN)
            log_fatal("blocklist", "blocklist-len:%d > IPv%d-max-len:%d",
                      IPVX_MAX_PREFIX_LEN, IPV46_FLAG, IP_MAX_PREFIX_LEN);
        break;
    default:
        log_fatal("blocklist", "not supported IPv%d", IPV46_FLAG);
    }

    IPVX_PORT_MAX_BITS = IPVX_MAX_PREFIX_LEN + PORT_MAX_BITS;
    log_debug("blocklist", "IPVX_MAX_PREFIX_LEN=%d", IPVX_MAX_PREFIX_LEN);
    log_debug("blocklist", "IPv%d_MAX_PREFIX_LEN=%d", IPV46_FLAG,
              IP_MAX_PREFIX_LEN);
    log_debug("blocklist", "PORT_MAX_BITS=%d", PORT_MAX_BITS);
    log_debug("blocklist", "max blocklist len=%d", IPVX_PORT_MAX_BITS);

    blocklisted_cidrs = xcalloc(1, sizeof(bl_ll_t));
    mpz_init_set_ui(blocklisted_cidrs->len, 0);
    allowlisted_cidrs = xcalloc(1, sizeof(bl_ll_t));
    mpz_init_set_ui(allowlisted_cidrs->len, 0);

    if (allowlist_filename && allowlist_entries) {
        log_warn("allowlist",
                 "both a allowlist file and destination addresses were "
                 "specified. The union of these two sources will be utilized.");
    }

    if (allowlist_filename || allowlist_entries_len > 0) {
        // using a allowlist, so default to allowing nothing
        constraint = constraint_init_ui(ADDR_DISALLOWED, IPVX_PORT_MAX_BITS);
        log_debug("blocklist", "blocklisting: all /%d+%d(port)",
                  IPVX_MAX_PREFIX_LEN, PORT_MAX_BITS);
        if (allowlist_filename) {
            init_from_file(allowlist_filename, "allowlist", ADDR_ALLOWED,
                           ignore_invalid_hosts);
        }
        if (allowlist_entries) {
            init_from_array(allowlist_entries, allowlist_entries_len,
                            "allowlist", ADDR_ALLOWED, ignore_invalid_hosts);
        }
    } else {
        // no allowlist, so default to allowing everything
        log_debug("blocklist",
                  "no allowlist file or allowlist entries provided, set to "
                  "allow all /%d+%d(port)",
                  IPVX_MAX_PREFIX_LEN, PORT_MAX_BITS);
        constraint = constraint_init_ui(ADDR_ALLOWED, IPVX_PORT_MAX_BITS);
    }

    if (blocklist_filename) {
        init_from_file(blocklist_filename, "blocklist", ADDR_DISALLOWED,
                       ignore_invalid_hosts);
    }

    if (blocklist_entries) {
        init_from_array(blocklist_entries, blocklist_entries_len, "blocklist",
                        ADDR_DISALLOWED, ignore_invalid_hosts);
    }

    if (IPV46_FLAG == IPV6_FLAG)
        init_from_string(strdup("::"), ADDR_DISALLOWED, "blocklist",
                         ignore_invalid_hosts);
    else
        init_from_string(strdup("0.0.0.0"), ADDR_DISALLOWED, "blocklist",
                         ignore_invalid_hosts);

    constraint_paint_value_ui(constraint, ADDR_ALLOWED);
    mpz_t allowed, total;
    mpz_init_set_ui(allowed, 0);
    mpz_init_set_ui(total, 1);
    mpz_mul_2exp(total, total, IPVX_MAX_PREFIX_LEN);
    blocklist_count_allowed_ip(allowed); // just the number of ip
    mpf_t rate, allowed_f, total_f;
    mpf_init(rate);
    mpf_init(allowed_f);
    mpf_init(total_f);
    mpf_set_z(allowed_f, allowed);
    mpf_set_z(total_f, total);
    mpf_div(rate, allowed_f, total_f);
    log_debug("blocklist",
              "%s addresses (%0.2f%% of address space/0-%d: %s) can be scanned",
              mpz_to_str10(allowed), mpf_get_d(rate) * 100, ipvx_max_len,
              mpz_to_str10(total));

    int ret = EXIT_SUCCESS;
    if (mpz_eq_ui(allowed, 0)) {
        log_error(
            "blocklist",
            "no addresses are eligible to be scanned in the current "
            "configuration. This may be because the blocklist being used by "
            "XMap (%s) prevents any addresses from receiving probe packets.",
            blocklist_filename);
        ret = EXIT_FAILURE;
    }

    mpz_clear(allowed);
    mpz_clear(total);
    mpf_clear(rate);
    mpf_clear(allowed_f);
    mpf_clear(total_f);

    return ret;
}

static void bl_free(bl_cidr_node_t *node) {
    if (node == NULL) return;
    mpz_clear(node->ipvx_address);
    bl_free(node->next);
    free(node);
}

void blocklist_free() {
    constraint_free(constraint);
    bl_free(blocklisted_cidrs->first);
    mpz_clear(blocklisted_cidrs->len);
    bl_free(allowlisted_cidrs->first);
    mpz_clear(allowlisted_cidrs->len);
    log_debug("blocklist", "cleaning up");
}
