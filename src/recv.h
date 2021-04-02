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

#ifndef XMAP_RECV_H
#define XMAP_RECV_H

#include <pthread.h>

int recv_update_stats(void);

int recv_run(pthread_mutex_t *recv_ready_mutex);

#endif // XMAP_RECV_H
