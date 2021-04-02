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

#ifndef XMAP_MONITOR_H
#define XMAP_MONITOR_H

#include <pthread.h>

#include "iterator.h"

void monitor_run(iterator_t *it, pthread_mutex_t *lock);

void monitor_init(void);

#endif // XMAP_MONITOR_H
