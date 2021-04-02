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

#ifndef XMAP_GET_GATEWAY_H
#define XMAP_GET_GATEWAY_H

#include "../lib/includes.h"
#include <stdint.h>

char *get_default_iface(void);

int get_iface_ip(const char *iface, uint8_t *ip, int ipv46_flag);

int get_iface_hw_addr(const char *iface, unsigned char *hw_mac);

int get_default_gw_ip(uint8_t *gw_ip, const char *iface);

int get_hw_addr(const uint8_t *gw_ip_, const char *iface,
                unsigned char *hw_mac);

#endif // XMAP_GET_GATEWAY_H
