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

#ifndef XMAP_UTILITY_H
#define XMAP_UTILITY_H

void parse_source_ip_addresses(char given_string[]);

void parse_target_ports(char given_string[]);

void init_target_port();

#endif // XMAP_UTILITY_H
