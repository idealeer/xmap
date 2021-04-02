/*
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_PACKET_ICMP_H
#define XMAP_PACKET_ICMP_H

const char *get_icmp_type_str(int type);

const char *get_icmp_type_code_str(int type, int code);

void print_icmp_type_code_str();

#endif // XMAP_PACKET_ICMP_H
