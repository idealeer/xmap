/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "iid_modules.h"

#include <string.h>

extern iid_module_t module_zero;
extern iid_module_t module_low;
extern iid_module_t module_full;
extern iid_module_t module_rand;
extern iid_module_t module_set;
extern iid_module_t module_low_fill;
// Add your module here

uint8_t IID[IP_MAX_BYTES];

iid_module_t *iid_modules[] = {
    &module_full, &module_low, &module_low_fill,
    &module_rand, &module_set, &module_zero,
    // Add your module here
};

iid_module_t *get_iid_module_by_name(const char *name) {
    int len = (int) (sizeof(iid_modules) / sizeof(iid_modules[0]));
    for (int i = 0; i < len; i++) {
        if (!strcmp(iid_modules[i]->name, name)) {
            return iid_modules[i];
        }
    }

    return NULL;
}

void print_iid_modules(void) {
    int len = (int) (sizeof(iid_modules) / sizeof(iid_modules[0]));
    for (int i = 0; i < len; i++) {
        printf("%s\n", iid_modules[i]->name);
    }
}
