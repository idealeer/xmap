/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "packet_icmp.h"

#include "../../lib/lockfd.h"

#define ICMP_TYPE_MAX_INDEX 40
#define ICMP_CODE_MAX_INDEX 16

static const char *ICMP_TYPE_STR[] = {
    "echoreply",
    "other",
    "other",
    "unreach",
    "srcquench", // 0 - 4
    "redirect",
    "althostaddr",
    "other",
    "echo",
    "rtradvert", // 5 - 9
    "rtrsolicit",
    "timexceed",
    "paramprob",
    "tstamp",
    "tstampreply", // 10 - 14
    "info",
    "inforeply",
    "mask",
    "maskreply",
    "other", // 15 - 19
    "other",
    "other",
    "other",
    "other",
    "other", // 20 - 24
    "other",
    "other",
    "other",
    "other",
    "other", // 25 - 29
    "traceroute",
    "dataconverr",
    "mobile-redirect",
    "ipv6-whereareyou",
    "ipv6-iamhere", // 30 - 34
    "mobile-reg",
    "mobile-regreply",
    "dns",
    "dnsreply",
    "skip",     // 35 - 39
    "photuris", // 40
};

static int ICMP_TYPE_CODE_MAX_INDEX[] = {
    0, 0, 0, 15, 0,  // 0 - 4
    3, 0, 0, 0,  16, // 5 - 9
    0, 1, 2, 0,  0,  // 10 - 14
    0, 0, 0, 0,  0,  // 15 - 19
    0, 0, 0, 0,  0,  // 20 - 24
    0, 0, 0, 0,  0,  // 25 - 29
    0, 0, 0, 0,  0,  // 30 - 34
    0, 0, 0, 0,  0,  // 35 - 39
    5                // 40
};

static const char *ICMP_TYPE_CODE_STR[ICMP_TYPE_MAX_INDEX +
                                      1][ICMP_CODE_MAX_INDEX + 1] = {
    {
        // echoreply: 0
        "no code",
    },
    {// other: 1
     "unknown"},
    {// other: 2
     "unknown"},
    {
        // unreach: 3
        "net unreachable", "host unreachable", "protocol unreachable", // 0 - 2
        "port unreachable", "fragments required",
        "source route failed",                                      // 3 - 5
        "dst net unknown", "dst host unknown", "src host isolated", // 6 - 8
        "dst net admin prohibited", "dst host admin prohibited",
        "dst net unreachable tos", // 9 - 11
        "dst host unreachable tos", "communication admin prohibited",
        "host precedence violation", // 12 - 14
        "precedence cutoff",         // 15
    },
    {
        // echoreply: 4
        "no code",
    },
    {
        // redirect: 5
        "net redirect", "host redirect", "net redirect tos",
        "host redirect tos", // 0 - 3
    },
    {
        // althostaddr: 6
        "alternate address",
    },
    {// other: 7
     "unknown"},
    {// echo: 8
     "no code"},
    {
        // rtradvert: 9
        "router advertisement normal", "unknown", "unknown", "unknown", // 0 - 3
        "unknown", "unknown", "unknown", "unknown",                     // 4 - 7
        "unknown", "unknown", "unknown", "unknown", // 8 - 11
        "unknown", "unknown", "unknown", "unknown", // 12 - 15
        "not route common traffic",                 // 16
    },
    {// rtrsolicit: 10
     "no code"},
    {
        // timexceed: 11
        "transit time exceeded",
        "fragment reassembly time exceeded",
    },
    {
        // paramprob: 12
        "error at pointer",
        "option required",
        "bad length",
    },
    {// tstamp: 13
     "no code"},
    {// tstampreply: 14
     "no code"},
    {// info: 15
     "no code"},
    {// inforeply: 16
     "no code"},
    {// mask: 17
     "no code"},
    {// maskreply: 18
     "no code"},
    {// other: 19
     "unknown"},
    {// other: 20
     "unknown"},
    {// other: 21
     "unknown"},
    {// other: 22
     "unknown"},
    {// other: 23
     "unknown"},
    {// other: 24
     "unknown"},
    {// other: 25
     "unknown"},
    {// other: 26
     "unknown"},
    {// other: 27
     "unknown"},
    {// other: 28
     "unknown"},
    {// other: 29
     "unknown"},
    {// traceroute: 30
     "no code"},
    {// dataconverr: 31
     "no code"},
    {// mobile-redirect: 32
     "no code"},
    {// ipv6-whereareyou: 33
     "no code"},
    {// ipv6-iamhere: 34
     "no code"},
    {// mobile-reg: 35
     "no code"},
    {// mobile-regreply: 36
     "no code"},
    {// dns: 37
     "no code"},
    {// dnsreply: 38
     "no code"},
    {// skip: 39
     "no code"},
    {// photuris: 40
     "bad spi", "authentication failed", "decompression failed",
     "decryption failed", "need authentication", "need authorization"},
};

const char *get_icmp_type_str(int type) {
    if (type > ICMP_TYPE_MAX_INDEX) return "other";

    return ICMP_TYPE_STR[type];
}

const char *get_icmp_type_code_str(int type, int code) {
    if (type > ICMP_TYPE_MAX_INDEX) return "unknown";
    if (code > ICMP_TYPE_CODE_MAX_INDEX[type]) return "unknown";

    return ICMP_TYPE_CODE_STR[type][code];
}

void print_icmp_type_code_str() {
    lock_file(stderr);
    fprintf(stderr, "------------------------------------------------------\n");
    for (int i = 0; i <= ICMP_TYPE_MAX_INDEX; i++) {
        fprintf(stderr, "%-25s %s\n", "icmp-type-str(code)",
                "icmp-code-str(code)");
        fprintf(stderr,
                "------------------------------------------------------\n");
        fprintf(stderr, "%s(%d)\n", ICMP_TYPE_STR[i], i);
        for (int j = 0; j <= ICMP_TYPE_CODE_MAX_INDEX[i]; j++)
            fprintf(stderr, "%-25s %s(%d)\n", "", ICMP_TYPE_CODE_STR[i][j], j);
        fprintf(stderr,
                "------------------------------------------------------\n");
    }
    unlock_file(stderr);
}
