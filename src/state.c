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

#include "state.h"

#include "../lib/logger.h"

// global configuration and defaults
struct state_conf xconf = {
    .ipv46_flag                  = 6,
    .max_probe_len               = 32,
    .target_port_list            = {0},
    .target_port_flag            = {0},
    .target_port_num             = 0,
    .target_port_bits            = 0,
    .target_port_full            = 1,
    .max_probe_port_len          = 32,
    .target_index_num            = 0,
    .target_index_bits           = 0,
    .target_index_full           = 1,
    .max_port_index_len          = 0,
    .max_probe_port_index_len    = 32,
    .source_port_first           = 32768, // (these are the default
    .source_port_last            = 61000, // ephemeral range on Linux)
    .iface                       = NULL,
    .gw_mac                      = {0x00},
    .hw_mac                      = {0x00},
    .gw_ip                       = {0x00},
    .gw_mac_set                  = 0,
    .hw_mac_set                  = 0,
    .source_ip_addresses         = NULL,
    .number_source_ips           = 0,
    .send_ip_pkts                = 0,
    .rate                        = -1,
    .bandwidth                   = 0,
    .batch                       = 1,
    .packet_streams              = 1,
    .cooldown_secs               = 5,
    .max_targets                 = 0,
    .max_packets                 = 0,
    .max_runtime                 = 0,
    .max_results                 = 0,
    .est_elements                = 5e8,
    .senders                     = 1,
    .seed_provided               = 0,
    .seed                        = 0,
    .probe_module                = NULL,
    .probe_args                  = NULL,
    .probe_ttl                   = MAXTTL,
    .output_module               = NULL,
    .output_args                 = NULL,
    .iid_module                  = NULL,
    .iid_args                    = NULL,
    .iid_num                     = 1,
    .output_filename             = NULL,
    .blocklist_filename          = NULL,
    .allowlist_filename          = NULL,
    .list_of_ips_filename        = NULL,
    .list_of_ip_port_count       = 0,
    .list_of_ip_port_index_count = 0,
    .metadata_filename           = NULL,
    .metadata_file               = NULL,
    .notes                       = NULL,
    .custom_metadata_str         = NULL,
    .raw_output_fields           = NULL,
    .output_fields               = NULL,
    .output_filter_str           = NULL,
    .output_fields_len           = 0,
    .log_level                   = XLOG_INFO,
    .syslog                      = 0,
    .log_file                    = NULL,
    .log_directory               = NULL,
    .status_updates_file         = NULL,
    .dryrun                      = 0,
    .quiet                       = 0,
    .filter_duplicates           = 0,
    .filter_unsuccessful         = 0,
    .max_sendto_failures         = -1,
    .recv_ready                  = 0,
    .min_hitrate                 = (float) 0.0,
    .data_link_size              = 0,
    .config_filename             = NULL,
};

// global sender stats and defaults
struct state_send xsend = {
    .start           = 0.0,
    .finish          = 0.0,
    .packets_sent    = 0,
    .hosts_scanned   = 0,
    .blocklisted     = 0,
    .allowlisted     = 0,
    .warmup          = 1,
    .complete        = 0,
    .max_targets     = 0,
    .max_packets     = 0,
    .sendto_failures = 0,
    .packets_tried   = 0,
};

// global receiver stats and defaults
struct state_recv xrecv = {
    .success_unique     = 0,
    .success_total      = 0,
    .app_success_unique = 0,
    .app_success_total  = 0,
    .validation_passed  = 0,
    .validation_failed  = 0,
    .validation_again   = 0,
    .cooldown_unique    = 0,
    .cooldown_total     = 0,
    .failure_total      = 0,
    .filter_success     = 0,
    .ip_fragments       = 0,
    .complete           = 0,
    .pcap_recv          = 0,
    .pcap_drop          = 0,
    .pcap_ifdrop        = 0,
};
