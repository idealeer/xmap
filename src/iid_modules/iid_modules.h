/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_IID_MODULES_H
#define XMAP_IID_MODULES_H

#include "../state.h"

#define IP_MAX_BYTES 16

extern uint8_t IID[IP_MAX_BYTES]; // both for ipv4 & ipv6

// called at sender initialization
typedef int (*iid_global_init_cb)(struct state_conf *conf);

// called at sender thread initialization
typedef int (*iid_thread_init_cb)(void);

// called at sender thread getting IP suffix
typedef int (*iid_get_cb)(void *iid, int iid_num, void *args);

// called at the end of scan
typedef int (*iid_close_cb)(void);

typedef struct iid_module {
    const char *       name;
    iid_global_init_cb global_init;
    iid_thread_init_cb thread_init;
    iid_get_cb         get_current_iid;
    iid_close_cb       close;
    const char *       helptext;
} iid_module_t;

iid_module_t *get_iid_module_by_name(const char *name);

void print_iid_modules(void);

#endif // XMAP_IID_MODULES_H
