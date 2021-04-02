/*
 * Logger Copyright 2013 Regents of the University of Michigan
 *
 * XMap Copyright 2021 Xiang Li from Network and Information Security Lab
 * Tsinghua University
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef XMAP_LOGGER_H
#define XMAP_LOGGER_H

#include <stdarg.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// do not collide with constants defined in syslog.h
enum LogLevel {
    XLOG_FATAL,
    XLOG_ERROR,
    XLOG_WARN,
    XLOG_INFO,
    XLOG_DEBUG,
    XLOG_TRACE,
    XNUM_LOGLEVELS
};

int log_fatal(const char *loggerName, const char *logMessage, ...)
    __attribute__((noreturn));

int log_error(const char *loggerName, const char *logMessage, ...);

int log_warn(const char *loggerName, const char *logMessage, ...);

int log_info(const char *loggerName, const char *logMessage, ...);

int log_debug(const char *loggerName, const char *logMessage, ...);

#ifdef DEBUG
int log_trace(const char *loggerName, const char *logMessage, ...);
#else
#define log_trace(...) ;
#endif

int log_init(FILE *stream, enum LogLevel level, int syslog_enabled,
             const char *syslog_app);

void check_and_log_file_error(FILE *file, const char *name);

size_t dstrftime(char *, size_t, const char *, double);

double now();

#ifdef __cplusplus
};
#endif

#endif // XMAP_LOGGER_H
