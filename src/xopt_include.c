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

#if __GNUC__ < 4
#error "gcc version >= 4 is required"
#elif __GNUC__ == 4 && __GNUC_MINOR__ >= 6
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#elif __GNUC_MINOR__ >= 4
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif

#include "xopt.c"
