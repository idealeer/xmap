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

#ifndef XMAP_SEND_BSD_H
#define XMAP_SEND_BSD_H

#include <stdlib.h>
#include <unistd.h>

#include "../lib/includes.h"

#ifdef XMAP_SEND_LINUX_H
#error "Don't include both send-bsd.h and send-linux.h"
#endif

// thread
int send_run_init(UNUSED sock_t sock) {
    // Don't need to do anything on BSD-like variants
    return EXIT_SUCCESS;
}

// thread
int send_packet(sock_t sock, void *buf, int len, UNUSED uint32_t idx) {
    return write(sock.sock, buf, len);
}

#endif // XMAP_SEND_BSD_H
