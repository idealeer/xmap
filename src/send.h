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

#ifndef XMAP_SEND_H
#define XMAP_SEND_H

#include "iterator.h"
#include "socket.h"

// global sender initialize (not thread specific)
iterator_t *send_init(void);

// one sender thread
int send_run(sock_t, shard_t *);

#endif // XMAP_SEND_H
