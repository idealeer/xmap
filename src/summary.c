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

#include "summary.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "iid_modules/iid_modules.h"
#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"
#include "state.h"

#include "../lib/blocklist.h"
#include "../lib/gmp-ext.h"
#include "../lib/includes.h"
#include "../lib/logger.h"
#include "../lib/util.h"

#define STRTIME_LEN 1024

#include <json.h>

void json_metadata(FILE *file) {
    char send_start_time[STRTIME_LEN + 1];
    assert(dstrftime(send_start_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
                     xsend.start));
    char send_end_time[STRTIME_LEN + 1];
    assert(dstrftime(send_end_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
                     xsend.finish));
    char recv_start_time[STRTIME_LEN + 1];
    assert(dstrftime(recv_start_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
                     xrecv.start));
    char recv_end_time[STRTIME_LEN + 1];
    assert(dstrftime(recv_end_time, STRTIME_LEN, "%Y-%m-%dT%H:%M:%S%z",
                     xrecv.finish));
    double hitrate =
        ((double) 100 * xrecv.success_unique) / ((double) xsend.hosts_scanned);

    json_object *obj = json_object_new_object();

    // scanner host name
    char hostname[1024];
    if (gethostname(hostname, 1023) < 0) {
        log_error("json_metadata", "unable to retrieve local hostname");
    } else {
        hostname[1023] = '\0';
        json_object_object_add(obj, "local_hostname",
                               json_object_new_string(hostname));
        struct hostent *h = gethostbyname(hostname);
        if (h) {
            json_object_object_add(obj, "full_hostname",
                                   json_object_new_string(h->h_name));
        } else {
            log_error("json_metadata", "unable to retrieve complete hostname");
        }
    }

    json_object_object_add(obj, "ipv46_flag",
                           json_object_new_int(xconf.ipv46_flag));
    json_object_object_add(obj, "max_probe_len",
                           json_object_new_int(xconf.max_probe_len));
    json_object_object_add(obj, "max_probe_port_len",
                           json_object_new_int(xconf.max_probe_port_len));
    json_object_object_add(obj, "target_port_num",
                           json_object_new_int(xconf.target_port_num));
    json_object_object_add(obj, "target_port_bits",
                           json_object_new_int(xconf.target_port_bits));
    if (xconf.target_port_num) {
        json_object *target_ports = json_object_new_array();
        for (int i = 0; i < xconf.target_port_num; i++) {
            json_object_array_add(
                target_ports, json_object_new_int(xconf.target_port_list[i]));
        }
        json_object_object_add(obj, "target_ports", target_ports);
    }
    json_object_object_add(obj, "source_port_first",
                           json_object_new_int(xconf.source_port_first));
    json_object_object_add(obj, "source_port_last",
                           json_object_new_int(xconf.source_port_last));
    json_object_object_add(obj, "max_targets",
                           json_object_new_int64(xconf.max_targets));
    json_object_object_add(obj, "max_packets",
                           json_object_new_int64(xconf.max_packets));
    json_object_object_add(obj, "max_runtime",
                           json_object_new_int(xconf.max_runtime));
    json_object_object_add(obj, "max_results",
                           json_object_new_int64(xconf.max_results));
    json_object_object_add(obj, "est_elements",
                           json_object_new_int64(xconf.est_elements));
    json_object_object_add(obj, "output_results",
                           json_object_new_int64(xrecv.filter_success));
    if (xconf.iface) {
        json_object_object_add(obj, "iface",
                               json_object_new_string(xconf.iface));
    }
    char rate_str[20];
    char bd_str[20];
    number_string(xconf.rate, rate_str, 20);
    bits_string(xconf.bandwidth, bd_str, 20);
    strcat(rate_str, "pps");
    strcat(bd_str, "bps");
    json_object_object_add(obj, "rate", json_object_new_string(rate_str));
    json_object_object_add(obj, "bandwidth", json_object_new_string(bd_str));
    json_object_object_add(obj, "batch", json_object_new_int(xconf.batch));
    json_object_object_add(obj, "probes",
                           json_object_new_int(xconf.packet_streams));
    json_object_object_add(obj, "retires",
                           json_object_new_int(xconf.num_retries));
    json_object_object_add(obj, "iid_num", json_object_new_int(xconf.iid_num));
    json_object_object_add(obj, "cooldown_secs",
                           json_object_new_int(xconf.cooldown_secs));
    json_object_object_add(obj, "senders", json_object_new_int(xconf.senders));
    if (xconf.pin_cores_len) {
        json_object *pin_cores = json_object_new_array();
        for (uint32_t i = 0; i < xconf.pin_cores_len; i++) {
            json_object_array_add(pin_cores,
                                  json_object_new_int(xconf.pin_cores[i]));
        }
        json_object_object_add(obj, "pin_cores", pin_cores);
    }
    json_object_object_add(obj, "seed", json_object_new_int64(xconf.seed));
    json_object_object_add(obj, "seed_provided",
                           json_object_new_int(xconf.seed_provided));
    json_object_object_add(
        obj, "generator",
        json_object_new_string(mpz_to_str10(xconf.generator)));
    json_object_object_add(obj, "hitrate", json_object_new_double(hitrate));
    json_object_object_add(obj, "shard_num",
                           json_object_new_int(xconf.shard_num));
    json_object_object_add(obj, "total_shards",
                           json_object_new_int(xconf.total_shards));

    json_object_object_add(obj, "min_hitrate",
                           json_object_new_double(xconf.min_hitrate));
    json_object_object_add(obj, "max_sendto_failures",
                           json_object_new_int64(xconf.max_sendto_failures));

    json_object_object_add(obj, "syslog", json_object_new_int(xconf.syslog));
    json_object_object_add(obj, "filter_duplicates",
                           json_object_new_int(xconf.filter_duplicates));
    json_object_object_add(obj, "filter_unsuccessful",
                           json_object_new_int(xconf.filter_unsuccessful));

    json_object_object_add(obj, "pcap_recv",
                           json_object_new_int64(xrecv.pcap_recv));
    json_object_object_add(obj, "pcap_drop",
                           json_object_new_int64(xrecv.pcap_drop));
    json_object_object_add(obj, "pcap_ifdrop",
                           json_object_new_int64(xrecv.pcap_ifdrop));

    json_object_object_add(obj, "ip_fragments",
                           json_object_new_int64(xrecv.ip_fragments));
    json_object_object_add(
        obj, "blocklist_total_allowed_ip",
        json_object_new_string(mpz_to_str10(xconf.total_allowed_ip)));
    json_object_object_add(
        obj, "blocklist_total_not_allowed_ip",
        json_object_new_string(mpz_to_str10(xconf.total_disallowed_ip)));
    json_object_object_add(obj, "blocklist_total_allowed_ip_port_actual",
                           json_object_new_string(mpz_to_str10(
                               xconf.total_allowed_ip_port_actual)));
    json_object_object_add(
        obj, "blocklist_total_allowed_ip_port",
        json_object_new_string(mpz_to_str10(xconf.total_allowed_ip_port)));
    json_object_object_add(
        obj, "blocklist_total_not_allowed_ip_port",
        json_object_new_string(mpz_to_str10(xconf.total_disallowed_ip_port)));
    json_object_object_add(obj, "validation_passed",
                           json_object_new_int64(xrecv.validation_passed));
    json_object_object_add(obj, "validation_failed",
                           json_object_new_int64(xrecv.validation_failed));

    //	json_object_object_add(obj, "blocklisted",
    //            json_object_new_int64(xsend.blocklisted));
    //	json_object_object_add(obj, "allowlisted",
    //            json_object_new_int64(xsend.allowlisted));
    uint8_t ip[16];
    memset(ip, 0, 16);
    mpz_t ip_1;
    mpz_init(ip_1);
    mpz_sub_ui(xsend.first_scanned, xsend.first_scanned, 1);
    blocklist_lookup_index_for_ipvx_port(ip_1, xsend.first_scanned);
    mpz_to_uint8s_bits(ip_1, ip, xconf.max_probe_len);
    json_object_object_add(
        obj, "first_scanned_prefix",
        json_object_new_string(inet_in2constr(ip, xconf.ipv46_flag)));
    mpz_clear(ip_1);

    json_object_object_add(
        obj, "first_scanned",
        json_object_new_string(mpz_to_str10(xsend.first_scanned)));
    json_object_object_add(obj, "send_to_failures",
                           json_object_new_int64(xsend.sendto_failures));
    json_object_object_add(obj, "packets_sent",
                           json_object_new_int64(xsend.packets_sent));
    json_object_object_add(obj, "packets_tried",
                           json_object_new_int64(xsend.packets_tried));
    json_object_object_add(obj, "hosts_scanned",
                           json_object_new_int64(xsend.hosts_scanned));
    json_object_object_add(obj, "success_total",
                           json_object_new_int64(xrecv.success_total));
    json_object_object_add(obj, "success_unique",
                           json_object_new_int64(xrecv.success_unique));
    if (xconf.fsconf.app_success_index >= 0) {
        json_object_object_add(obj, "app_success_total",
                               json_object_new_int64(xrecv.app_success_total));
        json_object_object_add(obj, "app_success_unique",
                               json_object_new_int64(xrecv.app_success_unique));
    }
    json_object_object_add(obj, "success_cooldown_total",
                           json_object_new_int64(xrecv.cooldown_total));
    json_object_object_add(obj, "success_cooldown_unique",
                           json_object_new_int64(xrecv.cooldown_unique));
    json_object_object_add(obj, "failure_total",
                           json_object_new_int64(xrecv.failure_total));

    json_object_object_add(
        obj, "probe_module",
        json_object_new_string(((probe_module_t *) xconf.probe_module)->name));
    json_object_object_add(
        obj, "output_module",
        json_object_new_string(
            ((output_module_t *) xconf.output_module)->name));
    json_object_object_add(
        obj, "iid_module",
        json_object_new_string(((iid_module_t *) xconf.iid_module)->name));

    json_object_object_add(obj, "send_start_time",
                           json_object_new_string(send_start_time));
    json_object_object_add(obj, "send_end_time",
                           json_object_new_string(send_end_time));
    json_object_object_add(obj, "recv_start_time",
                           json_object_new_string(recv_start_time));
    json_object_object_add(obj, "recv_end_time",
                           json_object_new_string(recv_end_time));

    if (xconf.output_filter_str) {
        json_object_object_add(obj, "output_filter",
                               json_object_new_string(xconf.output_filter_str));
    }
    if (xconf.log_file) {
        json_object_object_add(obj, "log_file",
                               json_object_new_string(xconf.log_file));
    }
    if (xconf.log_directory) {
        json_object_object_add(obj, "log_directory",
                               json_object_new_string(xconf.log_directory));
    }

    if (xconf.destination_cidrs_len) {
        json_object *cli_dest_cidrs = json_object_new_array();
        for (int i = 0; i < xconf.destination_cidrs_len; i++) {
            json_object_array_add(
                cli_dest_cidrs,
                json_object_new_string(xconf.destination_cidrs[i]));
        }
        json_object_object_add(obj, "cli_cidr_destinations", cli_dest_cidrs);
    }
    if (xconf.probe_args) {
        json_object_object_add(obj, "probe_args",
                               json_object_new_string(xconf.probe_args));
    }
    if (xconf.probe_ttl) {
        json_object_object_add(obj, "probe_ttl",
                               json_object_new_int(xconf.probe_ttl));
    }
    if (xconf.output_args) {
        json_object_object_add(obj, "output_args",
                               json_object_new_string(xconf.output_args));
    }
    if (xconf.iid_args) {
        json_object_object_add(obj, "iid_args",
                               json_object_new_string(xconf.iid_args));
    }
    {
        char mac_buf[(MAC_ADDR_LEN * 2) + (MAC_ADDR_LEN - 1) + 1];
        memset(mac_buf, 0, sizeof(mac_buf));
        char *p = mac_buf;
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            if (i == MAC_ADDR_LEN - 1) {
                snprintf(p, 3, "%.2x", xconf.gw_mac[i]);
                p += 2;
            } else {
                snprintf(p, 4, "%.2x:", xconf.gw_mac[i]);
                p += 3;
            }
        }
        json_object_object_add(obj, "gateway_mac",
                               json_object_new_string(mac_buf));
    }
    if (xconf.gw_ip) {
        json_object_object_add(obj, "gateway_ip",
                               json_object_new_string(inet_in2constr(
                                   xconf.gw_ip, xconf.ipv46_flag)));
    }
    {
        char  mac_buf[(ETHER_ADDR_LEN * 2) + (ETHER_ADDR_LEN - 1) + 1];
        char *p = mac_buf;
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            if (i == ETHER_ADDR_LEN - 1) {
                snprintf(p, 3, "%.2x", xconf.hw_mac[i]);
                p += 2;
            } else {
                snprintf(p, 4, "%.2x:", xconf.hw_mac[i]);
                p += 3;
            }
        }
        json_object_object_add(obj, "source_mac",
                               json_object_new_string(mac_buf));
    }
    json_object *source_ips = json_object_new_array();
    for (uint i = 0; i < xconf.number_source_ips; i++) {
        json_object_array_add(
            source_ips, json_object_new_string(inet_in2constr(
                            xconf.source_ip_addresses[i], xconf.ipv46_flag)));
    }
    json_object_object_add(obj, "source_ips", source_ips);
    json_object_object_add(obj, "iplayer",
                           json_object_new_int(xconf.send_ip_pkts));
    if (xconf.output_filename) {
        json_object_object_add(obj, "output_filename",
                               json_object_new_string(xconf.output_filename));
    }
    if (xconf.blocklist_filename) {
        json_object_object_add(
            obj, "blocklist_filename",
            json_object_new_string(xconf.blocklist_filename));
    }
    if (xconf.allowlist_filename) {
        json_object_object_add(
            obj, "allowlist_filename",
            json_object_new_string(xconf.allowlist_filename));
    }
    if (xconf.list_of_ips_filename) {
        json_object_object_add(
            obj, "list_of_ips_filename",
            json_object_new_string(xconf.list_of_ips_filename));
        json_object_object_add(obj, "list_of_ip_count",
                               json_object_new_int(xconf.list_of_ip_count));
        json_object_object_add(
            obj, "list_of_ip_port_count",
            json_object_new_int(xconf.list_of_ip_port_count));
    }
    json_object_object_add(obj, "ignore_blacklist_error",
                           json_object_new_int(xconf.ignore_blacklist_error));
    json_object_object_add(obj, "ignore_filelist_error",
                           json_object_new_int(xconf.ignore_filelist_error));
    if (xconf.config_filename) {
        json_object_object_add(obj, "config_filename",
                               json_object_new_string(xconf.config_filename));
    }
    if (xconf.status_updates_file) {
        json_object_object_add(
            obj, "status_updates_file",
            json_object_new_string(xconf.status_updates_file));
    }
    if (xconf.metadata_filename) {
        json_object_object_add(obj, "metadata_filename",
                               json_object_new_string(xconf.metadata_filename));
    }
    json_object_object_add(obj, "dryrun", json_object_new_int(xconf.dryrun));
    json_object_object_add(obj, "quiet", json_object_new_int(xconf.quiet));
    json_object_object_add(obj, "log_level",
                           json_object_new_int(xconf.log_level));

    // parse out JSON metadata that was supplied on the command-line
    if (xconf.custom_metadata_str) {
        json_object *user = json_tokener_parse(xconf.custom_metadata_str);
        if (!user) {
            log_error("json-metadata", "unable to parse user metadata");
        } else {
            json_object_object_add(obj, "user-metadata", user);
        }
    }

    if (xconf.notes) {
        json_object_object_add(obj, "notes",
                               json_object_new_string(xconf.notes));
    }

    // add blocklisted and allowlisted CIDR blocks
    bl_cidr_node_t *b = get_blocklisted_cidrs();
    if (b) {
        json_object *blocklisted_cidrs = json_object_new_array();
        char         cidr[64];
        uint8_t      ip[16];
        do {
            memset(cidr, 0, 64);
            memset(ip, 0, 16);
            mpz_to_uint8s_bits(b->ipvx_address, ip, xconf.max_probe_len);
            sprintf(cidr, "%s/%i", inet_in2constr(ip, xconf.ipv46_flag),
                    b->prefix_len);
            json_object_array_add(blocklisted_cidrs,
                                  json_object_new_string(cidr));
        } while (b && (b = b->next));
        json_object_object_add(obj, "blocklisted_networks", blocklisted_cidrs);
    }

    b = get_allowlisted_cidrs();
    if (b) {
        json_object *allowlisted_cidrs = json_object_new_array();
        char         cidr[64];
        uint8_t      ip[16];
        do {
            memset(cidr, 0, 64);
            memset(ip, 0, 16);
            mpz_to_uint8s_bits(b->ipvx_address, ip, xconf.max_probe_len);
            sprintf(cidr, "%s/%i", inet_in2constr(ip, xconf.ipv46_flag),
                    b->prefix_len);
            json_object_array_add(allowlisted_cidrs,
                                  json_object_new_string(cidr));
        } while (b && (b = b->next));
        json_object_object_add(obj, "allowlisted_networks", allowlisted_cidrs);
    }

    fprintf(file, "%s\n", json_object_to_json_string(obj));
    json_object_put(obj);
}
