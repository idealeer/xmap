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

#ifndef XMAP_STATE_H
#define XMAP_STATE_H

#include <gmp.h>
#include <stdint.h>
#include <stdio.h>

#ifdef PFRING
#include <pfring_zc.h>
#endif

#include "aesrand.h"
#include "fieldset.h"
#include "filter.h"

#include "../lib/bloom.h"
#include "../lib/includes.h"
#include "../lib/types.h"

#define MAX_PACKET_SIZE 4096
#define MAC_ADDR_LEN_BYTES 6
#define MAX_SOURCE_IP_NUM 1024
#define IP_ADDR_LEN_BYTES 16
#define MAX_PORT_NUM 65536

struct probe_module;
struct output_module;
struct iid_module;

struct fieldset_conf {
    fielddefset_t defs;
    fielddefset_t outdefs;
    translation_t translation;
    int           success_index;
    int           app_success_index;
    int           classification_index;
};

// global configuration
struct state_conf {
    // IPv46 flag
    int ipv46_flag;
    int max_probe_len;
    int ipv46_bytes;
    int ipv46_bits;

    // target cidrs
    char **  destination_cidrs;
    int      destination_cidrs_len;
    port_h_t target_port_list[MAX_PORT_NUM];
    port_h_t target_port_flag[MAX_PORT_NUM];
    int      target_port_num;
    int      target_port_bits;
    int      target_port_full;
    int      max_probe_port_len;

    port_h_t source_port_first;
    port_h_t source_port_last;
    // name of network interface that will be utilized for sending/receiving
    char *     iface;
    macaddr_t  gw_mac[MAC_ADDR_LEN_BYTES];
    macaddr_t  hw_mac[MAC_ADDR_LEN_BYTES];
    ipaddr_n_t gw_ip[IP_ADDR_LEN_BYTES];
    int        gw_mac_set;
    int        hw_mac_set;
    ipaddr_n_t source_ip_addresses[MAX_SOURCE_IP_NUM][IP_ADDR_LEN_BYTES];
    uint32_t   number_source_ips;
    // send ip packet instead of ethernet packet
    int send_ip_pkts;

    // rate in packets per second that the sender will maintain
    int rate;
    // rate in bits per second
    uint64_t bandwidth;
    uint8_t  batch;
    int      packet_streams;
    int      num_retries;
    // how many seconds after the termination of the sender will the receiver
    // continue to process responses
    int cooldown_secs;

    // maximum number of targets that the scanner will probe before terminating
    uint64_t max_targets;
    // maximum number of packets that the scanner will send before
    // terminating
    uint64_t max_packets;
    // maximum number of seconds that scanner will run before terminating
    uint32_t max_runtime;
    // maximum number of results before terminating
    uint64_t max_results;
    // estimated elements of scanning for unique
    uint64_t est_elements;

    // number of sending threads
    uint8_t   senders;
    uint32_t  pin_cores_len;
    uint32_t *pin_cores;
    // should use CLI provided randomization seed instead of generating a random
    // seed.
    int        seed_provided;
    uint64_t   seed;
    aesrand_t *aes;
    // generator of the cyclic multiplicative group that is utilized for address
    // generation
    mpz_t generator;
    // sharding options
    uint16_t shard_num;
    uint16_t total_shards;

    // probe module
    struct probe_module *probe_module;
    char *               probe_args;
    uint8_t              probe_ttl;
    // output module
    struct output_module *output_module;
    char *                output_module_name;
    char *                output_args;
    // IID value
    struct iid_module *iid_module;
    char *             iid_args;
    int                iid_num;
    char *             iid_module_name;

    // file
    char *   output_filename;
    char *   blocklist_filename;
    char *   allowlist_filename;
    char *   list_of_ips_filename;
    uint64_t list_of_ip_count;
    uint64_t list_of_ip_port_count;
    char *   metadata_filename;
    FILE *   metadata_file;
    char *   notes;
    char *   custom_metadata_str;

    // output field
    char *               raw_output_fields;
    char **              output_fields;
    struct output_filter filter;
    char *               output_filter_str;
    struct fieldset_conf fsconf;
    int                  output_fields_len;

    // log & other
    int      log_level;
    char *   log_file;
    char *   log_directory;
    char *   status_updates_file;
    int      dryrun;
    int      quiet;
    int      ignore_blacklist_error;
    int      ignore_filelist_error;
    int      syslog;
    int      filter_duplicates;
    int      filter_unsuccessful;
    int      recv_ready;
    uint64_t max_sendto_failures;
    float    min_hitrate;
    int      data_link_size;
    char *   config_filename;

    mpz_t total_allowed_ip_port;
    mpz_t total_disallowed_ip_port;
    mpz_t total_allowed_ip;
    mpz_t total_disallowed_ip;
    mpz_t total_allowed_ip_port_actual;

#ifdef PFRING
    struct {
        pfring_zc_cluster *    cluster;
        pfring_zc_queue *      send;
        pfring_zc_queue *      recv;
        pfring_zc_queue **     queues;
        pfring_zc_pkt_buff **  buffers;
        pfring_zc_buffer_pool *prefetches;
    } pf;
#endif
};
extern struct state_conf xconf;

// global sender stats
struct state_send {
    double   start;
    double   finish;
    uint64_t packets_sent;
    uint64_t hosts_scanned;
    uint64_t blocklisted;
    uint64_t allowlisted;
    int      warmup;
    int      complete;
    uint64_t max_targets;
    uint64_t max_packets;
    uint64_t sendto_failures;
    uint64_t packets_tried;
    mpz_t    first_scanned;
    mpz_t    max_index; // max index for send
};
extern struct state_send xsend;

// global receiver stats
struct state_recv {
    // valid responses classified as "success"
    uint64_t success_total;
    // unique IPs that sent valid responses classified as "success"
    uint64_t success_unique;
    // valid responses classified as "success"
    uint64_t app_success_total;
    // unique IPs that sent valid responses classified as "success"
    uint64_t app_success_unique;
    // valid responses classified as "success" received during cooldown
    uint64_t cooldown_total;
    // unique IPs that first sent valid "success"es during cooldown
    uint64_t cooldown_unique;
    // valid responses NOT classified as "success"
    uint64_t failure_total;
    // valid responses that passed the filter
    uint64_t filter_success;
    // how many packets did we receive that were marked as being the first
    // fragment in a stream
    uint64_t ip_fragments;
    // metrics about _only_ validate_packet
    uint64_t validation_passed;
    uint64_t validation_failed;

    int    complete; // has the scanner finished sending?
    double start;    // timestamp of when recv started
    double finish;   // timestamp of when recv terminated

    // number of packets captured by pcap filter
    uint64_t pcap_recv;
    // number of packets dropped because there was no room in the operating
    // system's buffer when they arrived, because packets weren't being read
    // fast enough
    uint64_t pcap_drop;
    // number of packets dropped by the network interface or its driver.
    uint64_t pcap_ifdrop;

    // used for repeating check
    BloomFilter bf;
};
extern struct state_recv xrecv;

#endif // XMAP_STATE_H
