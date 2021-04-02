/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_MODULE_ICMP6_H
#define XMAP_MODULE_ICMP6_H

#include <assert.h>
#include <string.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/types.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "../validate.h"
#include "packet.h"
#include "packet_icmp6.h"
#include "probe_modules.h"

#define ICMP6_MINLEN 8
#define ICMP6_MAX_PAYLOAD_LEN 1500 - 40 - 8 // 1500 - IPv6_h - ICMPv6_h

#endif // XMAP_MODULE_ICMP6_H
