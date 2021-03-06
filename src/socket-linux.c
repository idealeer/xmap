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

#include "socket.h"

#include <errno.h>
#include <string.h>

#include "state.h"

#include "../lib/includes.h"
#include "../lib/logger.h"

sock_t get_socket(UNUSED uint32_t id) {
    int sock;
    if (xconf.send_ip_pkts) {
        sock = socket(AF_PACKET, SOCK_DGRAM,
                      htons(ETH_P_ALL)); // link level for all ipv46-
    } else {
        sock = socket(AF_PACKET, SOCK_RAW,
                      htons(ETH_P_ALL)); // link level for all eth-ipv46-
    }
    if (sock <= 0) {
        log_fatal("send",
                  "couldn't create socket. "
                  "Are you root? Error: %s\n",
                  strerror(errno));
    }
    sock_t s;
    s.sock = sock;
    return s;
}
