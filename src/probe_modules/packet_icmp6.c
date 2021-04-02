/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "packet_icmp6.h"

#include "../../lib/lockfd.h"

#define ICMP6_TYPE_MAX_INDEX 4
#define ICMP6_CODE_MAX_INDEX 10

static const char *ICMP6_TYPE_STR[] = {
    "other", "unreach", "packetobig", "timexceed", "paramprob", // 1 - 4
};

static int ICMP6_TYPE_CODE_MAX_INDEX[] = {
    0, 8, 0, 1, 10, // 1 - 4
};

static const char
    *ICMP6_TYPE_CODE_STR[ICMP6_TYPE_MAX_INDEX + 1][ICMP6_CODE_MAX_INDEX + 1] = {
        {
            // other: 0
            "unknown",
        },
        {// unreach: 1
         "no route to dst", "communication admin prohibited",
         "beyond src addr scope", "addr unreach", "port unreach",
         "src addr policy failed", "route rejected", "src routing header error",
         "too long headers"},
        {
            // packetobig: 2
            "no code",
        },
        {
            // timexceed: 3
            "transit time exceeded",
            "fragment reassembly time exceeded",
        },
        {
            // paramprob: 4
            "header field error",
            "unknown next header",
            "unknown ipv6 option",
            "incomplete ipv6 header chain in 1st fragement",
            "sr upper-layer header error",
            "unknown next header at intermediate node",
            "header-ext too big",
            "header-ext chain too big",
            "header-ext too many",
            "header-ext option too many",
            "option goo big",
        },
};

const char *get_icmp6_type_str(int type) {
    if (type > ICMP6_TYPE_MAX_INDEX) return "other";

    return ICMP6_TYPE_STR[type];
}

const char *get_icmp6_type_code_str(int type, int code) {
    if (type > ICMP6_TYPE_MAX_INDEX) return "unknown";
    if (code > ICMP6_TYPE_CODE_MAX_INDEX[type]) return "unknown";

    return ICMP6_TYPE_CODE_STR[type][code];
}

void print_icmp6_type_code_str() {
    lock_file(stderr);
    fprintf(stderr, "------------------------------------------------------\n");
    for (int i = 0; i <= ICMP6_TYPE_MAX_INDEX; i++) {
        fprintf(stderr, "%-25s %s\n", "icmpv6-type-str(code)",
                "icmpv6-code-str(code)");
        fprintf(stderr,
                "------------------------------------------------------\n");
        fprintf(stderr, "%s(%d)\n", ICMP6_TYPE_STR[i], i);
        for (int j = 0; j <= ICMP6_TYPE_CODE_MAX_INDEX[i]; j++)
            fprintf(stderr, "%-25s %s(%d)\n", "", ICMP6_TYPE_CODE_STR[i][j], j);
        fprintf(stderr,
                "------------------------------------------------------\n");
    }
    unlock_file(stderr);
}
