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

#ifndef XMAP_VALIDATE_H
#define XMAP_VALIDATE_H

#include "../lib/types.h"
#include <stdint.h>

#define VALIDATE_BYTES 16

void validate_init();

void validate_gen(const uint8_t *src_ip, const uint8_t *dst_ip,
                  port_h_t dst_port, uint8_t output[VALIDATE_BYTES]);

#endif // XMAP_VALIDATE_H
