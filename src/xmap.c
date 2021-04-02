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

#include <assert.h>
#include <errno.h>
#include <json.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "get_gateway.h"
#include "ip_target_file.h"
#include "monitor.h"
#include "recv.h"
#include "send.h"
#include "shard.h"
#include "socket.h"
#include "state.h"
#include "summary.h"
#include "utility.h"
#include "xopt.h"

#include "iid_modules/iid_modules.h"
#include "output_modules/output_modules.h"
#include "probe_modules/probe_modules.h"

#include "../lib/blocklist.h"
#include "../lib/gmp-ext.h"
#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/util.h"
#include "../lib/xalloc.h"

#ifdef PFRING
#include <pfring_zc.h>
static int32_t distrib_func(pfring_zc_pkt_buff *pkt, pfring_zc_queue *in_queue,
                            void *arg) {
    (void) pkt;
    (void) in_queue;
    (void) arg;

    return 0;
}
#endif

pthread_mutex_t recv_ready_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct send_args {
    uint32_t cpu;
    sock_t   sock;
    shard_t *shard;
} send_args_t;

typedef struct recv_args {
    uint32_t cpu;
} recv_args_t;

typedef struct mon_start_args {
    uint32_t         cpu;
    iterator_t *     it;
    pthread_mutex_t *recv_ready_mutex;
} mon_start_args_t;

const char *default_help_text =
    "By default, XMap prints out unique, successful IPv6/IPv4 addresses (e.g., "
    "a Echo reply from a Echo scan) in ASCII form (e.g., 2001::1234, "
    "192.168.1.5) to stdout (--output-file=-) or the specified output file "
    "(--output-file=file). Internally this is handled by the `csv' output "
    "module and is equivalent to running xmap --output-module=csv "
    "--output-fields=\"saddr,\" --output-filter=\"success = 1 && repeat = 0\".";

static void *start_send(void *args) {
    send_args_t *s = (send_args_t *) args;
    log_debug("xmap", "pinning a send thread to core %u", s->cpu);

    set_cpu(s->cpu);
    send_run(s->sock, s->shard);
    free(s);

    return NULL;
}

static void *start_recv(void *args) {
    recv_args_t *r = (recv_args_t *) args;
    log_debug("xmap", "pinning receive thread to core %u", r->cpu);

    set_cpu(r->cpu);
    recv_run(&recv_ready_mutex);

    return NULL;
}

static void *start_mon(void *args) {
    mon_start_args_t *mon_arg = (mon_start_args_t *) args;
    log_debug("xmap", "pinning monitor thread to core %u", mon_arg->cpu);

    set_cpu(mon_arg->cpu);
    monitor_run(mon_arg->it, mon_arg->recv_ready_mutex);
    free(mon_arg);

    return NULL;
}

static void start_xmap(void) {
    log_debug("xmap", "xmap start.");

    if (xconf.iface == NULL) {
        xconf.iface = get_default_iface();
        if (!xconf.iface) {
            log_fatal("xmap",
                      "could not detect default interface. Try specifying a "
                      "interface `-i|--interface='",
                      xconf.ipv46_flag, xconf.iface);
        }
        log_debug("xmap",
                  "no interface provided. will use default interface: %s.",
                  xconf.iface);
    }

    if (xconf.number_source_ips == 0) {
        if (get_iface_ip(xconf.iface, xconf.source_ip_addresses[0],
                         xconf.ipv46_flag)) {
            log_fatal("xmap",
                      "could not detect default IPv%d address for %s. Try "
                      "specifying a source address `-S|--source-ip'",
                      xconf.ipv46_flag, xconf.iface);
        }
        xconf.number_source_ips++;
        log_debug(
            "xmap",
            "no source IPv%d address given. will use default address: %s",
            xconf.ipv46_flag,
            inet_in2constr(xconf.source_ip_addresses[0], xconf.ipv46_flag));
    }

    // Get the source hardware address, and give it to the probe module
    if (!xconf.hw_mac_set) {
        memset(xconf.hw_mac, 0, MAC_ADDR_LEN);
        if (get_iface_hw_addr(xconf.iface, xconf.hw_mac)) {
            log_fatal("xmap",
                      "could not retrieve hardware address for interface: %s",
                      xconf.iface);
        }
        log_debug("xmap",
                  "no source MAC provided. Automatically detected "
                  "%02x:%02x:%02x:%02x:%02x:%02x for %s",
                  xconf.hw_mac[0], xconf.hw_mac[1], xconf.hw_mac[2],
                  xconf.hw_mac[3], xconf.hw_mac[4], xconf.hw_mac[5],
                  xconf.iface);
    }
    log_debug("xmap", "source MAC address %02x:%02x:%02x:%02x:%02x:%02x",
              xconf.hw_mac[0], xconf.hw_mac[1], xconf.hw_mac[2],
              xconf.hw_mac[3], xconf.hw_mac[4], xconf.hw_mac[5]);

    if (!xconf.gw_mac_set) {
        memset(xconf.gw_ip, 0, xconf.ipv46_bytes);
        if (get_default_gw_ip(xconf.gw_ip, xconf.iface)) {
            log_fatal("xmap",
                      "could not detect default gateway address for %s. Try "
                      "setting default gateway mac address (-G).",
                      xconf.iface);
        }
        // TODO only support to get gw's IPv4 address: IPV4_FLAG
        log_debug("xmap", "found gateway IPv4 address %s on %s",
                  inet_in2constr(xconf.gw_ip, IPV4_FLAG), xconf.iface);

        memset(&xconf.gw_mac, 0, MAC_ADDR_LEN);
        if (get_hw_addr(xconf.gw_ip, xconf.iface, xconf.gw_mac)) {
            log_fatal("xmap",
                      "could not detect GW MAC address for %s on %s. Try "
                      "setting default gateway mac address (-G), or run \"arp "
                      "<gateway_ip>\" in terminal.",
                      inet_in2constr(xconf.gw_ip, IPV4_FLAG), xconf.iface);
        }
        xconf.gw_mac_set = 1;
    }
    log_debug("xmap", "gateway MAC address %02x:%02x:%02x:%02x:%02x:%02x",
              xconf.gw_mac[0], xconf.gw_mac[1], xconf.gw_mac[2],
              xconf.gw_mac[3], xconf.gw_mac[4], xconf.gw_mac[5]);

    // PFRING
#ifdef PFRING
#define MAX_CARD_SLOTS 32768
#define QUEUE_LEN 8192
#define PMAP_PF_BUFFER_SIZE 1536
#define PMAP_PF_ZC_CLUSTER_ID 9627
    uint32_t user_buffers  = xconf.senders * 256;
    uint32_t queue_buffers = xconf.senders * QUEUE_LEN;
    uint32_t card_buffers  = 2 * MAX_CARD_SLOTS;
    uint32_t total_buffers = user_buffers + queue_buffers + card_buffers + 2;
    uint32_t metadata_len  = 0;
    uint32_t numa_node     = 0; // TODO
    xconf.pf.cluster       = pfring_zc_create_cluster(
        PMAP_PF_ZC_CLUSTER_ID, PMAP_PF_BUFFER_SIZE, metadata_len, total_buffers,
        numa_node, NULL, 0);
    if (xconf.pf.cluster == NULL) {
        log_fatal("xmap", "Could not create zc cluster: %s", strerror(errno));
    }

    xconf.pf.buffers = xcalloc(user_buffers, sizeof(pfring_zc_pkt_buff *));
    for (uint32_t i = 0; i < user_buffers; ++i) {
        xconf.pf.buffers[i] = pfring_zc_get_packet_handle(xconf.pf.cluster);
        if (xconf.pf.buffers[i] == NULL) {
            log_fatal("xmap", "Could not get ZC packet handle");
        }
    }

    xconf.pf.send =
        pfring_zc_open_device(xconf.pf.cluster, xconf.iface, tx_only, 0);
    if (xconf.pf.send == NULL) {
        log_fatal("xmap", "Could not open device %s for TX. [%s]", xconf.iface,
                  strerror(errno));
    }

    xconf.pf.recv =
        pfring_zc_open_device(xconf.pf.cluster, xconf.iface, rx_only, 0);
    if (xconf.pf.recv == NULL) {
        log_fatal("xmap", "Could not open device %s for RX. [%s]", xconf.iface,
                  strerror(errno));
    }

    xconf.pf.queues = xcalloc(xconf.senders, sizeof(pfring_zc_queue *));
    for (uint32_t i = 0; i < xconf.senders; ++i) {
        xconf.pf.queues[i] =
            pfring_zc_create_queue(xconf.pf.cluster, QUEUE_LEN);
        if (xconf.pf.queues[i] == NULL) {
            log_fatal("xmap", "Could not create queue: %s", strerror(errno));
        }
    }

    xconf.pf.prefetches = pfring_zc_create_buffer_pool(xconf.pf.cluster, 8);
    if (xconf.pf.prefetches == NULL) {
        log_fatal("xmap", "Could not open prefetch pool: %s", strerror(errno));
    }
#endif

    // Initialization
    log_info("xmap", "probe network: ipv%d", xconf.ipv46_flag);
    log_info("xmap", "probe module: %s", xconf.probe_module->name);
    log_info("xmap", "output module: %s", xconf.output_module->name);
    log_info("xmap", "iid module: %s", xconf.iid_module->name);

    if (xconf.output_module && xconf.output_module->init) {
        if (xconf.output_module->init(&xconf, xconf.output_fields,
                                      xconf.output_fields_len)) {
            log_fatal("xmap", "output module did not initialize successfully.");
        }
    }

    // Send global init
    iterator_t *it = send_init();
    if (!it) log_fatal("xmap", "unable to initialize sending component");

    if (xconf.output_module && xconf.output_module->start)
        xconf.output_module->start(&xconf, &xsend, &xrecv);

    // start threads
    uint32_t   cpu = 0;
    pthread_t *tsend, trecv, tmon;

    // recv thread
    if (!xconf.dryrun) { // TODO how many target will reply? <ip, port>
        if (bloom_filter_init(&xrecv.bf, xconf.est_elements, (float) 1e-5) ==
            BLOOM_FAILURE) {
            log_fatal("xmap",
                      "unable to create bloomfilter for unique results");
        }
        log_debug("xmap", "bloomfilter for unique results <= 4e9");

        recv_args_t *recv_arg = xmalloc(sizeof(recv_args_t));
        recv_arg->cpu         = xconf.pin_cores[cpu % xconf.pin_cores_len];
        cpu += 1;
        int r = pthread_create(&trecv, NULL, start_recv, recv_arg);
        if (r != 0) {
            log_fatal("xmap", "unable to create recv thread");
        }

        for (;;) {
            pthread_mutex_lock(&recv_ready_mutex);
            if (xconf.recv_ready) {
                pthread_mutex_unlock(&recv_ready_mutex);
                break;
            }
            pthread_mutex_unlock(&recv_ready_mutex);
        }
    }

#ifdef PFRING
    pfring_zc_worker *zw = pfring_zc_run_balancer(
        xconf.pf.queues, &xconf.pf.send, xconf.senders, 1, xconf.pf.prefetches,
        round_robin_bursts_policy, NULL, distrib_func, NULL, 0,
        xconf.pin_cores[cpu & xconf.pin_cores_len]);
    cpu += 1;
#endif

    // send thread
    tsend = xmalloc(xconf.senders * sizeof(pthread_t));
    for (uint8_t i = 0; i < xconf.senders; i++) {
        sock_t sock;
        if (xconf.dryrun) {
            sock = get_dryrun_socket();
        } else {
            sock = get_socket(i);
        }

        send_args_t *arg = xmalloc(sizeof(send_args_t));
        arg->sock        = sock;
        arg->shard       = get_shard(it, i);
        arg->cpu         = xconf.pin_cores[cpu % xconf.pin_cores_len];
        cpu += 1;

        int r = pthread_create(&tsend[i], NULL, start_send, arg);
        if (r != 0) {
            log_fatal("xmap", "unable to create send thread");
        }
    }
    log_debug("xmap", "%d sender threads spawned", xconf.senders);

    // monitor thread
    if (!xconf.dryrun) {
        monitor_init();
        mon_start_args_t *mon_arg = xmalloc(sizeof(mon_start_args_t));
        mon_arg->it               = it;
        mon_arg->recv_ready_mutex = &recv_ready_mutex;
        mon_arg->cpu              = xconf.pin_cores[cpu % xconf.pin_cores_len];

        int r = pthread_create(&tmon, NULL, start_mon, mon_arg);
        if (r != 0) {
            log_fatal("xmap", "unable to create monitor thread");
        }
    }

#ifndef PFRING
    drop_privs();
#endif

    // wait for send completion
    for (uint8_t i = 0; i < xconf.senders; i++) {
        int r = pthread_join(tsend[i], NULL);
        if (r != 0) {
            log_fatal("xmap", "unable to join send thread");
        }
    }
    log_debug("xmap", "senders finished");

#ifdef PFRING
    pfring_zc_kill_worker(zw);
    pfring_zc_sync_queue(xconf.pf.send, tx_only);
    log_debug("xmap", "send queue flushed");
#endif

    // wait for recv & monitor completion
    if (!xconf.dryrun) {
        int r = pthread_join(trecv, NULL);
        if (r != 0) {
            log_fatal("xmap", "unable to join recv thread");
        }

        bloom_filter_destroy(&xrecv.bf);
        log_debug("xmap", "receiver finished");

        if (!xconf.quiet || xconf.status_updates_file) {
            r = pthread_join(tmon, NULL);
            if (r != 0) {
                log_fatal("xmap", "unable to join monitor thread");
            }
        }
        log_debug("xmap", "monitor finished");
    }

    // finished
    if (xconf.metadata_filename) {
        json_metadata(xconf.metadata_file);
    }

    if (xconf.output_module && xconf.output_module->close) {
        xconf.output_module->close(&xconf, &xsend, &xrecv);
    }

    if (xconf.probe_module && xconf.probe_module->close) {
        xconf.probe_module->close(&xconf, &xsend, &xrecv);
    }

#ifdef PFRING
    pfring_zc_destroy_cluster(xconf.pf.cluster);
#endif

    // blocklist free
    blocklist_free();

    // iterator free
    iterator_free(it);

    log_info("xmap", "completed");
}

static void init_state() {
    // init for xconf state
    mpz_init(xconf.generator);
    mpz_init(xconf.total_allowed_ip_port);
    mpz_init(xconf.total_disallowed_ip_port);
    mpz_init(xconf.total_allowed_ip);
    mpz_init(xconf.total_disallowed_ip);
    mpz_init(xconf.total_allowed_ip_port_actual);

    // init for xsend state
    mpz_init(xsend.first_scanned);
    mpz_init(xsend.max_index);
}

static void deinit_state() {
    // deinit for xconf state
    mpz_clear(xconf.generator);
    mpz_clear(xconf.total_allowed_ip_port);
    mpz_clear(xconf.total_disallowed_ip_port);
    mpz_clear(xconf.total_allowed_ip);
    mpz_clear(xconf.total_disallowed_ip);
    mpz_clear(xconf.total_allowed_ip_port_actual);

    // deinit for xsend state
    mpz_clear(xsend.first_scanned);
    mpz_clear(xsend.max_index);
}

#define SET_IF_GIVEN(DST, ARG)                                                 \
    {                                                                          \
        if (args.ARG##_given) {                                                \
            (DST) = args.ARG##_arg;                                            \
        };                                                                     \
    }
#define SET_BOOL(DST, ARG)                                                     \
    {                                                                          \
        if (args.ARG##_given) {                                                \
            (DST) = 1;                                                         \
        };                                                                     \
    }

int main(int argc, char *argv[]) {
    struct gengetopt_args_info    args;
    struct cmdline_parser_params *params;
    params                 = cmdline_parser_params_create();
    params->initialize     = 1;
    params->override       = 0;
    params->check_required = 0;

    // parameters parser
    int config_loaded = 0;
    if (cmdline_parser_ext(argc, argv, &args, params) != 0) {
        exit(EXIT_SUCCESS);
    }

    if (args.config_given || file_exists(args.config_arg)) {
        params->initialize = 0;
        params->override   = 0;
        if (cmdline_parser_config_file(args.config_arg, &args, params) != 0) {
            exit(EXIT_FAILURE);
        }
        config_loaded = 1;
    }

    // initialize logging. if no log file or log directory are specified
    // default to using stderr.
    xconf.log_level     = args.verbosity_arg;
    xconf.log_file      = args.log_file_arg;
    xconf.log_directory = args.log_directory_arg;

    if (args.disable_syslog_given) {
        xconf.syslog = 0;
    } else {
        xconf.syslog = 1;
    }

    if (xconf.log_file && xconf.log_directory) {
        log_init(stderr, xconf.log_level, xconf.syslog, "xmap");
        log_fatal("xmap", "log-file and log-directory cannot "
                          "specified simultaneously.");
    }

    FILE *log_location = NULL;
    if (xconf.log_file) {
        log_location = fopen(xconf.log_file, "w");
    } else if (xconf.log_directory) {
        time_t now;
        time(&now);
        struct tm *local = localtime(&now);
        char       path[100];
        strftime(path, 100, "xmap-%Y-%m-%dT%H%M%S%z.log", local);
        char *fullpath =
            xmalloc(strlen(xconf.log_directory) + strlen(path) + 2);
        sprintf(fullpath, "%s/%s", xconf.log_directory, path);
        log_location = fopen(fullpath, "w");
        free(fullpath);
    } else {
        log_location = stderr;
    }

    if (!log_location) {
        log_init(stderr, xconf.log_level, xconf.syslog, "xmap");
        log_fatal("xmap", "unable to open specified log file: %s",
                  strerror(errno));
    }
    log_init(log_location, xconf.log_level, xconf.syslog, "xmap");

    // xmap start
    log_debug("xmap", "xmap main thread started");
    if (config_loaded) {
        xconf.config_filename = args.config_arg;
        log_debug("xmap", "loaded configuration file %s", args.config_arg);
    }

    if (xconf.syslog) {
        log_debug("xmap", "syslog support enabled");
    } else {
        log_debug("xmap", "syslog support disabled");
    }

    // IPv46 parser
    if (!args.ipv6_given && !args.ipv4_given) {
        log_debug(
            "xmap",
            "no `-6'|`-4' flag given, default select to send ipv6 packet");
        xconf.ipv46_flag  = 6;
        xconf.ipv46_bytes = 16;
        xconf.ipv46_bits  = 128;
    } else if (args.ipv6_given) {
        log_debug("xmap", "`-6' flag given, send ipv6 packet");
        xconf.ipv46_flag  = 6;
        xconf.ipv46_bytes = 16;
        xconf.ipv46_bits  = 128;
    } else if (args.ipv4_given) {
        log_debug("xmap", "`-4' flag given, send ipv4 packet");
        xconf.ipv46_flag  = 4;
        xconf.ipv46_bytes = 4;
        xconf.ipv46_bits  = 32;
    }

    // Scanning max bit length
    if (args.max_len_given) {
        enforce_range("scanning max-len", args.max_len_arg, 0,
                      xconf.ipv46_bits);
        xconf.max_probe_len = args.max_len_arg;
        if (xconf.max_probe_len <= 0 ||
            xconf.max_probe_len > xconf.ipv46_bits) {
            log_fatal("xmap", "invalid max probe length: `-x|--max-len=%d'",
                      xconf.max_probe_len);
        }

        xconf.max_probe_port_len = xconf.max_probe_len;
        log_debug("xmap", "ipv%d max probing len=%d, +port=%d",
                  xconf.ipv46_flag, xconf.max_probe_len,
                  xconf.max_probe_port_len);
    } else {
        xconf.max_probe_len      = 32;
        xconf.max_probe_port_len = 32;
        log_debug("xmap",
                  "no `-x|--max-len=' given, default select to scan all /%d "
                  "for ipv%d",
                  xconf.max_probe_len, xconf.ipv46_flag);
    }

    // init state args
    init_state();

    // parse the provided probe and output module s.t. that we can support
    // other command-line helpers (e.g. probe help)
    // Output module
    if (!strcmp(args.output_module_arg, "default")) {
        log_debug("xmap", "no output module provided. will use `csv'.");
        xconf.output_module      = get_output_module_by_name("csv");
        xconf.output_module_name = strdup("csv");
    } else {
        xconf.output_module = get_output_module_by_name(args.output_module_arg);
        if (!xconf.output_module) {
            log_fatal("xmap", "specified output module (%s) does not exist\n",
                      args.output_module_arg);
        }
        xconf.output_module_name = strdup(args.output_module_arg);
    }
    SET_IF_GIVEN(xconf.output_args, output_args);

    // Probe module
    if (!strcmp(args.probe_module_arg, "default")) {
        log_debug("xmap", "no probe module provided. will use `icmp_echo'.");
        xconf.probe_module =
            get_probe_module_by_name("icmp_echo", xconf.ipv46_flag);
    } else {
        xconf.probe_module =
            get_probe_module_by_name(args.probe_module_arg, xconf.ipv46_flag);
        if (!xconf.probe_module) {
            log_fatal("xmap",
                      "specified IPv%d probe module (%s) does not exist\n",
                      xconf.ipv46_flag, args.probe_module_arg);
        }
    }
    SET_IF_GIVEN(xconf.probe_args, probe_args);
    SET_IF_GIVEN(xconf.probe_ttl, probe_ttl);
    // check whether the probe module is going to generate dynamic data
    // and that the output module can support exporting that data out of
    // xmap. If they can't, then quit.
    if (xconf.probe_module->output_type == OUTPUT_TYPE_DYNAMIC &&
        !xconf.output_module->supports_dynamic_output) {
        log_fatal("xmap",
                  "specified probe module (%s) requires dynamic "
                  "output support, which output module (%s) does not support. "
                  "Most likely you want to use JSON output.",
                  args.probe_module_arg, args.output_module_arg);
    }

    // iid module
    if (!strcmp(args.iid_module_arg, "default")) {
        log_debug("xmap", "no iid module provided. will use `low'.");
        xconf.iid_module      = get_iid_module_by_name("low");
        xconf.iid_module_name = strdup("low");
    } else {
        xconf.iid_module = get_iid_module_by_name(args.iid_module_arg);
        if (!xconf.iid_module) {
            log_fatal("xmap", "specified iid module (%s) does not exist\n",
                      args.iid_module_arg);
        }
        xconf.iid_module_name = strdup(args.iid_module_arg);
    }
    if (args.iid_num_given && args.iid_num_arg < 0) {
        log_fatal("xmap", "`--iid-num=' should > 0\n", args.iid_module_arg);
    }
    SET_IF_GIVEN(xconf.iid_args, iid_args);
    SET_IF_GIVEN(xconf.iid_num, iid_num);

    // help output
    if (args.help_given) {
        cmdline_parser_print_help();

        printf("\nProbe-module (IPv%d %s) Help:\n", xconf.ipv46_flag,
               xconf.probe_module->name);
        if (xconf.probe_module->helptext) {
            fprintw(stdout, (char *) xconf.probe_module->helptext, 80);
        } else {
            printf("no help text available\n");
        }

        printf("\nOutput-module (%s) Help:\n", xconf.output_module->name);
        if (!strcmp(args.output_module_arg, "default")) {
            fprintw(stdout, (char *) default_help_text, 80);
        } else if (xconf.output_module->helptext) {
            fprintw(stdout, (char *) xconf.output_module->helptext, 80);
        } else {
            printf("no help text available\n");
        }

        printf("\nIID-module (%s) Help:\n", xconf.iid_module->name);
        if (xconf.iid_module->helptext) {
            fprintw(stdout, (char *) xconf.iid_module->helptext, 80);
        } else {
            printf("no help text available\n");
        }
        printf("\n");
        exit(EXIT_SUCCESS);
    }

    // other help
    if (args.version_given) {
        cmdline_parser_print_version();
        exit(EXIT_SUCCESS);
    }

    if (args.list_output_modules_given) {
        printf("Output-modules:\n");
        print_output_modules();
        exit(EXIT_SUCCESS);
    }

    if (args.list_probe_modules_given) {
        printf("Probe-modules (IPv6):\n");
        print_probe_modules(6);
        printf("Probe-modules (IPv4):\n");
        print_probe_modules(4);
        exit(EXIT_SUCCESS);
    }

    if (args.list_iid_modules_given) {
        printf("IID-modules:\n");
        print_iid_modules();
        exit(EXIT_SUCCESS);
    }

    if (args.iplayer_given) {
        xconf.send_ip_pkts = 1;
        xconf.gw_mac_set   = 1;
        memset(xconf.gw_mac, 0, MAC_ADDR_LEN);
    }

    if (cmdline_parser_required(&args, CMDLINE_PARSER_PACKAGE) != 0) {
        exit(EXIT_FAILURE);
    }

    //// fielddef set
    // now that we know the probe module, let's find what it supports
    memset(&xconf.fsconf, 0, sizeof(struct fieldset_conf));
    // the set of fields made available to a user is constructed
    // of IP header fields + probe module fields + system fields
    fielddefset_t *fds = &(xconf.fsconf.defs);
    if (xconf.ipv46_flag == IPV4_FLAG)
        gen_fielddef_set(fds, (fielddef_t *) &(ip_fields), ip_fields_len);
    else if (xconf.ipv46_flag == IPV6_FLAG)
        gen_fielddef_set(fds, (fielddef_t *) &(ip6_fields), ip6_fields_len);
    gen_fielddef_set(fds, xconf.probe_module->fields,
                     xconf.probe_module->numfields);
    gen_fielddef_set(fds, (fielddef_t *) &(sys_fields), sys_fields_len);
    if (args.list_output_fields_given) {
        printf("IPv%d %s:\n", xconf.ipv46_flag, xconf.probe_module->name);
        for (int i = 0; i < fds->len; i++) {
            printf("%-15s %6s: %s\n", fds->fielddefs[i].name,
                   fds->fielddefs[i].type, fds->fielddefs[i].desc);
        }
        exit(EXIT_SUCCESS);
    }

    // find the fields we need for the framework
    xconf.fsconf.success_index = fds_get_index_by_name(fds, (char *) "success");
    if (xconf.fsconf.success_index < 0) {
        log_fatal("xmap", "probe module does not supply "
                          "required success field.");
    }
    xconf.fsconf.app_success_index =
        fds_get_index_by_name(fds, (char *) "app_success");
    if (xconf.fsconf.app_success_index < 0) {
        log_debug("xmap", "probe module does not supply "
                          "application success field.");
    } else {
        log_debug("xmap",
                  "probe module supplies app_success"
                  " output field. It will be included in monitor output");
    }
    xconf.fsconf.classification_index =
        fds_get_index_by_name(fds, (char *) "clas");
    if (xconf.fsconf.classification_index < 0) {
        log_fatal("xmap", "probe module does not supply "
                          "required packet classification field.");
    }

    // output field
    // default output module does not support multiple fields throw an error
    // if the user asks for this because otherwise we'll generate a
    // malformed CSV file when this gets redirected to the CSV output module
    if (args.output_fields_given &&
        !strcmp(args.output_module_arg, "default")) {
        log_fatal("xmap",
                  "default output module does not support multiple"
                  " fields. Please specify an output module (e.g., -O csv)");
    }
    // process the list of requested output fields.
    if (args.output_fields_given) {
        xconf.raw_output_fields = args.output_fields_arg;
    } else if (!xconf.raw_output_fields) {
        xconf.raw_output_fields =
            (char *) "saddr"; // default output reply IPv6 address
    }
    // add all fields if wildcard received
    if (!strcmp(xconf.raw_output_fields, "*")) {
        xconf.output_fields_len = xconf.fsconf.defs.len;
        xconf.output_fields = xcalloc(xconf.fsconf.defs.len, sizeof(char *));
        for (int i = 0; i < xconf.fsconf.defs.len; i++) {
            xconf.output_fields[i] =
                (char *) xconf.fsconf.defs.fielddefs[i].name;
        }
        fs_generate_full_fieldset_translation(&xconf.fsconf.translation,
                                              &xconf.fsconf.defs);
    } else {
        split_string(xconf.raw_output_fields, &(xconf.output_fields_len),
                     &(xconf.output_fields));
        for (int i = 0; i < xconf.output_fields_len; i++) {
            log_debug("xmap", "requested output field (%i): %s", i,
                      xconf.output_fields[i]);
        }
        // generate a translation that can be used to convert output
        // from a probe module to the input for an output module
        fs_generate_fieldset_translation(
            &xconf.fsconf.translation, &xconf.fsconf.defs, xconf.output_fields,
            xconf.output_fields_len);
    }

    // output filter
    // default filtering behavior is to drop unsuccessful and duplicates
    if (!args.output_filter_arg || !strcmp(args.output_filter_arg, "default")) {
        xconf.filter_duplicates   = 1;
        xconf.filter_unsuccessful = 1;
        log_debug("xmap",
                  "no output filter specified. will use default: exclude "
                  "duplicates and unssuccessful");
    } else if (args.output_filter_arg && !strcmp(args.output_filter_arg, "")) {
        xconf.filter_duplicates   = 0;
        xconf.filter_unsuccessful = 0;
        log_debug("xmap", "empty output filter. will not exclude any values");
    } else {
        // Run it through yyparse to build the expression tree
        if (!parse_filter_string(args.output_filter_arg)) {
            log_fatal("xmap", "unable to parse filter expression");
        }
        // Check the fields used against the fieldset in use
        if (!validate_filter(xconf.filter.expression, &xconf.fsconf.defs)) {
            log_fatal("xmap", "invalid filter");
        }
        xconf.output_filter_str = args.output_filter_arg;
        log_debug("xmap", "will use output filter: %s", args.output_filter_arg);
    }

    // find if xmap wants any specific cidrs scanned instead
    // of the entire Internet
    xconf.destination_cidrs     = args.inputs;
    xconf.destination_cidrs_len = (int) args.inputs_num;
    SET_IF_GIVEN(xconf.blocklist_filename, blacklist_file);
    SET_IF_GIVEN(xconf.allowlist_filename, whitelist_file);
    if ((xconf.ipv46_flag == IPV4_FLAG) && xconf.blocklist_filename &&
        !strcmp(xconf.blocklist_filename, "/etc/xmap/blacklist4.conf")) {
        log_warn(
            "blocklist",
            "XMap is currently using the default blacklist located at "
            "/etc/xmap/blacklist4.conf. By default, this blacklist excludes "
            "locally scoped networks (e.g. 10.0.0.0/8, 127.0.0.1/8, and "
            "192.168.0.0/16). If you are trying to scan local networks, you "
            "can change the default blacklist by editing the default XMap "
            "configuration at /etc/xmap/xmap.conf.");
    }
    if ((xconf.ipv46_flag == IPV6_FLAG) && xconf.allowlist_filename &&
        !strcmp(xconf.allowlist_filename, "/etc/xmap/whitelist6.conf")) {
        log_warn("allowlist",
                 "XMap is currently using the default whitelist located at "
                 "/etc/xmap/whitelist6.conf. By default, this whitelist "
                 "includes 2001::/3. If you are trying to scan other networks, "
                 "you can change the default whitelist by editing the default "
                 "XMap configuration at /etc/xmap/xmap.conf.");
    }

    // target-port
    if (xconf.probe_module->port_args) {
        if (args.source_port_given) {
            char *dash = strchr(args.source_port_arg, '-');
            if (dash) { // range
                *dash                   = '\0';
                xconf.source_port_first = atoi(args.source_port_arg);
                enforce_range("starting source-port", xconf.source_port_first,
                              0, 0xFFFF);
                xconf.source_port_last = atoi(dash + 1);
                enforce_range("ending source-port", xconf.source_port_last, 0,
                              0xFFFF);
                if (xconf.source_port_first > xconf.source_port_last) {
                    fprintf(stderr,
                            "%s: invalid source port range: "
                            "last port is less than first port\n",
                            CMDLINE_PARSER_PACKAGE);
                    exit(EXIT_FAILURE);
                }
            } else { // single port
                int port = atoi(args.source_port_arg);
                enforce_range("source-port", port, 0, 0xFFFF);
                xconf.source_port_first = port;
                xconf.source_port_last  = port;
            }
        }
        log_debug("xmap", "src_port range: [%d, %d]", xconf.source_port_first,
                  xconf.source_port_last);

        if (!args.target_port_given) {
            log_fatal("xmap",
                      "target port (-p) is required for this type of probe: %s",
                      xconf.probe_module->name);
        }
        parse_target_ports(args.target_port_arg);
        init_target_port();
    }

    // iface
    SET_IF_GIVEN(xconf.iface, interface);

    // mac
    if (args.gateway_mac_given) {
        if (!parse_mac(xconf.gw_mac, args.gateway_mac_arg)) {
            fprintf(stderr, "%s: invalid MAC address `%s'\n",
                    CMDLINE_PARSER_PACKAGE, args.gateway_mac_arg);
            exit(EXIT_FAILURE);
        }
        xconf.gw_mac_set = 1;
    }
    if (args.source_mac_given) {
        if (!parse_mac(xconf.hw_mac, args.source_mac_arg)) {
            fprintf(stderr, "%s: invalid MAC address `%s'\n",
                    CMDLINE_PARSER_PACKAGE, args.gateway_mac_arg);
            exit(EXIT_FAILURE);
        }
        log_debug("send",
                  "source MAC address specified on CLI: "
                  "%02x:%02x:%02x:%02x:%02x:%02x",
                  xconf.hw_mac[0], xconf.hw_mac[1], xconf.hw_mac[2],
                  xconf.hw_mac[3], xconf.hw_mac[4], xconf.hw_mac[5]);

        xconf.hw_mac_set = 1;
    }

    // source IP
    if (args.source_ip_given) {
        parse_source_ip_addresses(args.source_ip_arg);
    }

    // rate
    SET_IF_GIVEN(xconf.rate, rate);

    // bandwidth
    if (args.bandwidth_given) {
        // Supported: G,g=*1073741824; M,m=*1048576 K,k=*1024 bits per second
        xconf.bandwidth = atoi(args.bandwidth_arg);
        char *suffix    = args.bandwidth_arg;
        while (*suffix >= '0' && *suffix <= '9') {
            suffix++;
        }
        if (*suffix) {
            switch (*suffix) {
            case 'G':
            case 'g':
                xconf.bandwidth *= 1073741824; // 1024^3
                break;
            case 'M':
            case 'm':
                xconf.bandwidth *= 1048576; // 1024^2
                break;
            case 'K':
            case 'k':
                xconf.bandwidth *= 1024; // 1024
                break;
            default:
                fprintf(stderr,
                        "%s: unknown bandwidth suffix '%s' (supported suffixes "
                        "are G, M and K)\n",
                        CMDLINE_PARSER_PACKAGE, suffix);
                exit(EXIT_FAILURE);
            }
        }
    }

    // batch
    if (args.batch_given) {
        xconf.batch = args.batch_arg;
        if (xconf.batch < 0) {
            log_fatal("xmap", "invalid batch number: `--batch='");
        }
    }

    // packet_stream
    SET_IF_GIVEN(xconf.packet_streams, probes);
    if (xconf.packet_streams < 0) {
        log_fatal("xmap", "invalid probe times: `--probes='");
    }

    // num-retries
    xconf.num_retries = args.retries_arg;
    if (xconf.num_retries < 0) {
        log_fatal("xmap", "invalid retry count: `--retries='");
    }

    // cooldown seconds
    SET_IF_GIVEN(xconf.cooldown_secs, cooldown_secs);
    if (xconf.cooldown_secs < 0) {
        log_fatal("xmap", "invalid cooldown secs: `-c|--cooldown-secs='");
    }

    // max target
    SET_IF_GIVEN(xconf.max_targets, max_targets);
    if (xconf.max_targets < 0) {
        log_fatal("xmap", "invalid max target number: `-n|--max-targets='");
    }
    if (xconf.max_targets) {
        xsend.max_targets = xconf.max_targets;
    }

    // max packet
    SET_IF_GIVEN(xconf.max_packets, max_packets);
    if (xconf.max_packets < 0) {
        log_fatal("xmap", "invalid max packets number: `-k|--max-packets='");
    }
    if (xconf.max_packets) {
        xsend.max_packets = xconf.max_packets;
    }

    // max runtime
    SET_IF_GIVEN(xconf.max_runtime, max_runtime);
    if (xconf.max_runtime < 0) {
        log_fatal("xmap", "invalid max runtime number: `-t|--max-runtime='");
    }

    // max reuslts
    SET_IF_GIVEN(xconf.max_results, max_results);
    if (xconf.max_results < 0) {
        log_fatal("xmap", "invalid max results number: `-N|--max-results='");
    }

    // est target
    SET_IF_GIVEN(xconf.est_elements, est_elements);
    if (xconf.est_elements < 0) {
        log_fatal("xmap", "invalid est element number: `-E|--est-elements='");
    }

    // if there's a list of ips to scan, then initialize file reader
    // blocklist_init should default allow all address space
    // filename
    SET_IF_GIVEN(xconf.output_filename, output_file);
    SET_IF_GIVEN(xconf.list_of_ips_filename, list_of_ips_file);
    if (xconf.list_of_ips_filename) {
        log_debug("xmap", "init ip target file ing...");

        int64_t count = ip_target_file_init(xconf.list_of_ips_filename);
        if (count == -1) log_fatal("xmap", "init ip target file error");
        if (count == 0) {
            log_warn("xmap", "zero ip target file, no need to xmap");
            return EXIT_SUCCESS;
        }
        xconf.list_of_ip_count = count;

        if (xconf.target_port_num)
            xconf.list_of_ip_port_count = count * xconf.target_port_num;
        else
            xconf.list_of_ip_port_count = count;

        log_debug("xmap", "target ipv%d number: %d, <ipv%d, port> number: %d",
                  xconf.ipv46_flag, count, xconf.ipv46_flag,
                  xconf.list_of_ip_port_count);
        log_debug("xmap", "init ip target file completed");

        xconf.max_probe_len      = xconf.ipv46_bits;
        xconf.max_probe_port_len = xconf.max_probe_len + xconf.target_port_bits;
        log_debug("xmap", "load ip target from file, max probe len reset to %d",
                  xconf.max_probe_len);
    }
    xconf.ignore_filelist_error = args.ignore_filelist_error_given;

    // blocklist & allowlist
    if ((xconf.ipv46_flag == IPV6_FLAG) && xconf.blocklist_filename &&
        !strcmp(xconf.blocklist_filename, "/etc/xmap/blacklist4.conf")) {
        xconf.blocklist_filename = NULL;
    }
    if ((xconf.ipv46_flag == IPV4_FLAG) && xconf.allowlist_filename &&
        !strcmp(xconf.allowlist_filename, "/etc/xmap/whitelist6.conf")) {
        xconf.allowlist_filename = NULL;
    }
    if (blocklist_init(xconf.allowlist_filename, xconf.blocklist_filename,
                       xconf.destination_cidrs, xconf.destination_cidrs_len,
                       NULL, 0, xconf.ignore_blacklist_error,
                       xconf.max_probe_len, xconf.target_port_bits,
                       xconf.ipv46_flag)) {
        log_fatal("xmap", "unable to initialize blacklist/whitelist");
    }
    xconf.ignore_blacklist_error = args.ignore_blacklist_error_given;

    // compute number of targets
    blocklist_count_allowed_ip(xconf.total_allowed_ip);
    if (mpz_zero(xconf.total_allowed_ip))
        log_fatal("xmap", "zero eligible addresses to scan");
    if (xconf.target_port_num)
        mpz_mul_ui(xconf.total_allowed_ip_port_actual, xconf.total_allowed_ip,
                   xconf.target_port_num);
    else
        mpz_set(xconf.total_allowed_ip_port_actual, xconf.total_allowed_ip);
    blocklist_count_not_allowed_ip(xconf.total_disallowed_ip);
    blocklist_count_allowed_ip_port(xconf.total_allowed_ip_port);
    blocklist_count_not_allowed_ip_port(xconf.total_disallowed_ip_port);

    // sender thread number
#ifndef PFRING
    // Set the correct number of threads, default to num_cores - 1
    if (args.sender_threads_given) {
        xconf.senders = args.sender_threads_arg;
    } else {
        xconf.senders = 1;
    }

    if (((xsend.max_targets && 2 * xconf.senders >= xsend.max_targets) ||
         (xsend.max_packets && 2 * xconf.senders >= xsend.max_packets) ||
         (xconf.list_of_ips_filename &&
          2 * xconf.senders >= xconf.list_of_ip_count) ||
         mpz_le_ui(xconf.total_allowed_ip_port, 2 * xconf.senders)) &&
        xconf.senders > 1) {
        log_warn("xmap",
                 "too few targets relative to senders, dropping to one sender");
        xconf.senders = 1;
    }
#else
    xconf.senders = args.sender_threads_arg;
#endif

    // Figure out what cores to bind to
    if (args.cores_given) {
        char **core_list = NULL;
        int    len       = 0;
        split_string(args.cores_arg, &len, &core_list);
        xconf.pin_cores_len = (uint32_t) len;
        xconf.pin_cores     = xcalloc(xconf.pin_cores_len, sizeof(uint32_t));
        for (uint32_t i = 0; i < xconf.pin_cores_len; ++i)
            xconf.pin_cores[i] = atoi(core_list[i]);
    } else {
        int num_cores       = sysconf(_SC_NPROCESSORS_ONLN);
        xconf.pin_cores_len = (uint32_t) num_cores;
        xconf.pin_cores     = xcalloc(xconf.pin_cores_len, sizeof(uint32_t));
        for (uint32_t i = 0; i < xconf.pin_cores_len; ++i)
            xconf.pin_cores[i] = i;
    }

    // Check for a random seed
    if (args.seed_given) {
        xconf.seed          = args.seed_arg;
        xconf.seed_provided = 1;
    } else {
        // generate a seed randomly
        if (!random_bytes(&xconf.seed, sizeof(uint64_t))) {
            log_fatal("xmap",
                      "unable to generate random bytes needed for seed");
        }
        xconf.seed_provided = 0;
    }
    xconf.aes = aesrand_init_from_seed(xconf.seed);

    // Set up sharding
    xconf.shard_num    = 0;
    xconf.total_shards = 1;
    if ((args.shard_given || args.shards_given) && !args.seed_given)
        log_fatal("xmap", "need to specify seed if sharding a scan");
    if (args.shard_given ^ args.shards_given)
        log_fatal(
            "xmap",
            "need to specify both shard number and total number of shards");
    if (args.shard_given) enforce_range("shard", args.shard_arg, 0, 65534);
    if (args.shards_given) enforce_range("shards", args.shards_arg, 1, 65535);
    SET_IF_GIVEN(xconf.shard_num, shard);
    SET_IF_GIVEN(xconf.total_shards, shards);
    if (xconf.shard_num >= xconf.total_shards)
        log_fatal("xmap",
                  "with %hhu total shards, shard number (%hhu)"
                  " must be in range [0, %hhu)",
                  xconf.total_shards, xconf.shard_num, xconf.total_shards);

    // metadata
    if (args.metadata_file_arg) {
        xconf.metadata_filename = args.metadata_file_arg;
        if (!strcmp(xconf.metadata_filename, "-")) {
            xconf.metadata_file = stdout;
        } else {
            xconf.metadata_file = fopen(xconf.metadata_filename, "w");
        }

        if (!xconf.metadata_file) {
            log_fatal("metadata", "unable to open metadata file (%s): %s",
                      xconf.metadata_filename, strerror(errno));
        }
        log_debug("metadata", "metdata will be saved to %s",
                  xconf.metadata_filename);
    }
    if (args.user_metadata_given) {
        xconf.custom_metadata_str = args.user_metadata_arg;
        if (!json_tokener_parse(xconf.custom_metadata_str)) {
            log_fatal("metadata", "unable to parse custom user metadata");
        } else {
            log_debug("metadata", "user metadata validated successfully");
        }
    }
    if (args.notes_given) xconf.notes = args.notes_arg;

    // other
    SET_IF_GIVEN(xconf.status_updates_file, status_updates_file);
    SET_BOOL(xconf.dryrun, dryrun);
    SET_BOOL(xconf.quiet, quiet);
    SET_IF_GIVEN(xconf.max_sendto_failures, max_sendto_failures);
    SET_IF_GIVEN(xconf.min_hitrate, min_hitrate);

    if (xconf.max_sendto_failures >= 0)
        log_debug("xmap",
                  "scan will abort if more than %i sendto failures occur",
                  xconf.max_sendto_failures);

    if (xconf.min_hitrate > 0.0)
        log_debug("xmap", "scan will abort if hitrate falls below %f",
                  xconf.min_hitrate);

    // start
    start_xmap();

    cmdline_parser_free(&args);
    free(params);
    deinit_state();

    return EXIT_SUCCESS;
}
